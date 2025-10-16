package network

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/wire"
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/multiformats/go-multiaddr"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxProtocolVersion 含义：当前节点支持的最高协议版本，
	//值对应wire包中定义的AddrV2Version（通常是 P2P 协议中支持 “版本 2 地址格式” 的版本号）。
	//作用：节点在与其他节点建立连接时，会通过 “版本协商” 交换双方支持的最高协议版本，
	//最终使用双方都支持的最低版本进行通信。此参数定义了当前节点能兼容的最高版本，确保与新节点的兼容性。
	MaxProtocolVersion = wire.AddrV2Version

	// DefaultTrickleInterval 含义：向对等节点发送inv消息（用于通知对方 “有新的区块 / 交易”）的最小时间间隔（默认 10 秒）。
	//背景：inv消息（inventory 消息）用于广播新发现的区块或交易，但如果频繁发送会导致网络拥堵。“Trickle（涓流）模式” 通过控制发送间隔，将批量的inv消息分散发送，避免网络峰值压力。
	//作用：平衡消息及时性和网络负载，例如节点发现 100 笔新交易时，不会一次性发送，而是每 10 秒发送一部分。
	DefaultTrickleInterval = 10 * time.Second

	// MinAcceptableProtocolVersion 含义：当前节点可接受的最低协议版本，值对应wire包中支持 “多地址格式” 的版本号。
	//作用：拒绝与协议版本低于此值的节点连接。例如，某些老节点可能只支持旧的地址格式，无法处理新功能（如多地址广播），通过此参数过滤不兼容的节点，保证通信正常。
	MinAcceptableProtocolVersion = wire.MultipleAddressVersion

	// outputBufferSize 含义：节点输出消息通道（channel）的缓冲区大小（可存放 50 个消息）。
	//背景：P2P 节点通常用 “通道” 异步发送消息（如sendQueue <- msg），缓冲区避免了发送方因接收方处理缓慢而阻塞。
	//作用：控制消息队列的容量，当缓冲区满时，新消息会等待（或丢弃，取决于实现），防止内存溢出。
	outputBufferSize = 50

	// 含义：涓流模式下，单次inv消息最多包含的inventory 条目数量（1000 条）。
	//作用：限制单条inv消息的大小（每条 inventory 是一个哈希，1000 条约占 32KB，避免消息过大导致传输超时或被对等节点拒绝）。
	MaxInvTrickleSize = 1000

	// maxKnownInventory 含义：节点内存中缓存的 “已知 inventory（区块 / 交易哈希）” 的最大数量（1000 个）。
	//作用：记录已向对等节点发送过的inv消息哈希，避免重复发送（例如，节点 A 向节点 B 发送过交易哈希 H，后续不会再发 H 给 B），减少网络冗余。
	MaxKnownInventory = 1000

	// negotiateTimeout 含义：节点连接建立后，版本协商阶段的超时时间（30 秒）。
	//背景：节点连接后，首先会交换version消息（包含协议版本、节点信息等），完成 “版本协商” 后才开始正常通信。
	//作用：如果 30 秒内未完成协商（如对方未回复version），则断开连接，避免无效连接占用资源。
	negotiateTimeout = 30 * time.Second

	// idleTimeout 含义：连接的空闲超时时间（5 分钟）。
	//作用：如果对等节点 5 分钟内没有任何消息交互（无block、tx、ping等任何消息），则断开连接，清理长期不活跃的节点，释放资源。
	idleTimeout = 5 * time.Minute

	// stallTickInterval 含义：检查对等节点是否 “停滞（stalled）” 的时间间隔（每 15 秒一次）。
	//背景：“停滞” 指节点虽然连接存活，但对消息无响应（如发送getdata请求后一直没收到block）。
	//作用：定期检测节点是否正常响应，避免长期等待无响应的节点。
	stallTickInterval = 15 * time.Second

	// stallResponseTimeout 含义：等待消息响应的最大超时时间（30 秒）。
	//作用：如果发送需要响应的消息（如getblock请求）后，30 秒内未收到回复，结合stallTickInterval的检查，判定节点 “停滞” 并断开连接，确保节点不会被无响应的对等节点拖累。
	stallResponseTimeout = 30 * time.Second
)

type HashFunc func() (hash *chainhash.Hash, height int32, err error)

type PeerConfig struct {
	NewestBlock         HashFunc
	Proxy               string
	UserAgentName       string
	UserAgentVersion    string
	UserAgentComments   []string
	ChainParams         *core.Params
	Services            wire.ServiceFlag
	ProtocolVersion     uint32
	DisableRelayTx      bool
	Listeners           MessageListeners
	TrickleInterval     time.Duration
	AllowSelfConns      bool
	DisableStallHandler bool
}

var (
	// nodeCount is the total number of peer connections made since startup
	// and is used to assign an id to a peer.
	nodeCount int32

	// zeroHash is the zero value hash (all zeros).  It is defined as a
	// convenience.
	zeroHash chainhash.Hash

	// sentNonces houses the unique nonces that are generated when pushing
	// version messages that are used to detect self connections.
	sentNonces = lru.NewCache(50)
)

// 先修正 Peer 结构体（补充缺失字段+修正类型）
type Peer struct {
	peerInfo *PeerInfo

	// 2. 业务基础状态
	inbound        bool      // 是否为入站连接（被动接收的连接）
	connectedAt    time.Time // 连接建立时间
	disconnectedAt time.Time // 连接断开时间
	isConnected    bool      // 当前是否连接

	// 3. 协议协商状态（补充 services 字段）
	protocolVersion      uint32           // 协商后的协议版本（取双方最小值）
	sendHeadersPreferred bool             //
	userAgent            string           // 对方节点的 UserAgent（如 "MyBlockchain/1.0.0"）
	services             wire.ServiceFlag // 节点支持的服务类型（如 SFNodeWitness 表示支持隔离见证）
	witnessEnabled       bool             // 是否支持隔离见证（区块链特性）
	sendHeadersPref      bool             // 是否偏好接收 Headers 而非 Inv（同步优化）

	// 4. 库存管理（修正 knownInventory 为指针类型）
	knownInventory lru.Cache       // 已向该节点发送过的 Inv 哈希（key: inv哈希字符串）
	trickleTimer   *time.Timer     // Trickle 模式定时器（批量发送 Inv）
	invQueue       []*wire.InvVect // 待发送的 Inv 队列（Trickle 攒批用）

	// 5. 同步控制状态
	lastRecvTime    time.Time            // 最后一次收到消息的时间（Idle 检测用）
	lastSendTime    time.Time            // 最后一次发送消息的时间
	pendingRequests map[string]time.Time // 待响应的请求（key: 消息类型，value: 发送时间，Stall 检测用）

	// 6. 业务统计
	lastRecv           int64
	lastSend           int64
	bytesSent          uint64          // 累计发送字节数
	bytesReceived      uint64          // 累计接收字节数
	lastBlockHeight    int32           // 对方节点的最新区块高度
	lastAnnouncedBlock *chainhash.Hash // 对方最近宣布的区块哈希
	startingHeight     int32           // 对方初始区块高度（连接时协商的）
	timeConnected      time.Time       // 连接建立时间（与 connectedAt 一致，可统一）
	timeOffset         int64           // 对方时间与本地时间的偏移（秒）

	// 7. 消息回调（关联上层业务逻辑）
	listeners *MessageListeners

	// 状态锁（保护不同类型的字段）
	statsMtx sync.RWMutex // 保护统计类字段（如 bytesSent、lastBlockHeight）
	flagsMtx sync.Mutex   // 保护标识类字段（如 libp2pPeerID、addrs、services）
}
type StatsSnap struct {
	libp2pPeerID   string                // LibP2P 节点唯一ID
	addrs          []multiaddr.Multiaddr // 节点地址列表
	Services       wire.ServiceFlag
	LastSend       time.Time
	LastRecv       time.Time
	BytesSent      uint64
	BytesRecv      uint64
	ConnTime       time.Time
	TimeOffset     int64
	Version        uint32
	UserAgent      string
	Inbound        bool
	StartingHeight int32
	LastBlock      int32
}

type MessageListeners struct {
}

// NewPeer 创建 Peer 实例
func NewPeer(peerInfo *PeerInfo, inbound bool, listeners *MessageListeners) *Peer {
	return &Peer{
		peerInfo:             peerInfo,
		inbound:              inbound,
		connectedAt:          time.Now(),
		timeConnected:        time.Now(), // 统一连接时间字段
		isConnected:          true,
		protocolVersion:      MaxProtocolVersion,
		services:             0,  // 初始值，后续协议协商时更新（如对方支持隔离见证则设为 wire.SFNodeWitness）
		userAgent:            "", // 初始值，协议协商时从对方 Version 消息中获取
		witnessEnabled:       false,
		sendHeadersPref:      false,
		sendHeadersPreferred: false,
		lastRecv:             0,
		lastSend:             0,
		// 修正 knownInventory 为指针类型，用 lru.New 初始化
		knownInventory:  lru.NewCache(MaxKnownInventory),
		invQueue:        make([]*wire.InvVect, 0, MaxInvTrickleSize),
		trickleTimer:    time.NewTimer(DefaultTrickleInterval),
		pendingRequests: make(map[string]time.Time),
		lastRecvTime:    time.Now(),
		listeners:       listeners,
	}
}

func (p *Peer) String() string {
	return fmt.Sprintf("%s (%s)", p.peerInfo, directionString(p.inbound))
}

// 更新节点的最新高度
func (p *Peer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	if newHeight <= p.lastBlockHeight {
		p.statsMtx.Unlock()
		return
	}
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.peerInfo.ID, p.lastBlockHeight, newHeight)
	p.lastBlockHeight = newHeight
	p.statsMtx.Unlock()
}

// 这个 UpdateLastAnnouncedBlock 方法的核心作用是 记录并更新 “某个对等节点（Peer）最近向本地节点宣布（广播）的区块哈希”，
// 是区块链节点在区块同步过程中用于追踪对等节点状态的关键工具。
func (p *Peer) UpdateLastAnnouncedBlock(blkHash *chainhash.Hash) {
	log.Tracef("Updating last blk for peer %v, %v", p.peerInfo.ID, blkHash)
	p.statsMtx.Lock()
	p.lastAnnouncedBlock = blkHash
	p.statsMtx.Unlock()
}

// AddKnownInventory  记录已向该节点发送的 Inv（避免重复）
func (p *Peer) AddKnownInventory(invVect *wire.InvVect) {
	p.knownInventory.Add(invVect)
}

// StatsSnapshot 实现：安全获取 Peer 瞬时状态快照
func (p *Peer) StatsSnapshot() *StatsSnap {
	// 锁顺序：先加读锁（statsMtx.RLock），再加写锁（flagsMtx.Lock），避免死锁
	// defer 按逆序释放锁：先释放 flagsMtx（写锁），再释放 statsMtx（读锁）
	p.statsMtx.RLock()
	defer p.statsMtx.RUnlock()

	p.flagsMtx.Lock()
	defer p.flagsMtx.Unlock()

	// 1. 处理引用类型：addrs 是切片（引用类型），需深拷贝避免外部修改影响快照
	addrsCopy := make([]multiaddr.Multiaddr, len(p.peerInfo.Addrs))
	copy(addrsCopy, p.peerInfo.Addrs) // 深拷贝地址列表

	// 2. 读取 flagsMtx 保护的“标识类字段”（节点唯一标识、协议基础信息）
	baseInfo := struct {
		libp2pPeerID    string
		addrs           []multiaddr.Multiaddr
		services        wire.ServiceFlag
		protocolVersion uint32
		userAgent       string
		inbound         bool
	}{
		libp2pPeerID:    p.peerInfo.ID,
		addrs:           addrsCopy,
		services:        p.services,
		protocolVersion: p.protocolVersion,
		userAgent:       p.userAgent,
		inbound:         p.inbound,
	}

	// 3. 读取 statsMtx 保护的“统计类字段”（连接状态、数据统计、区块信息）
	statsInfo := struct {
		lastSend       time.Time
		lastRecv       time.Time
		bytesSent      uint64
		bytesRecv      uint64
		connTime       time.Time
		timeOffset     int64
		startingHeight int32
		lastBlock      int32
	}{
		lastSend:       p.lastSendTime,
		lastRecv:       p.lastRecvTime,
		bytesSent:      p.bytesSent,
		bytesRecv:      p.bytesReceived,
		connTime:       p.timeConnected,
		timeOffset:     p.timeOffset,
		startingHeight: p.startingHeight,
		lastBlock:      p.lastBlockHeight,
	}

	// 4. 构造并返回快照（所有字段均为瞬时值，后续 Peer 修改不影响）
	return &StatsSnap{
		libp2pPeerID:   baseInfo.libp2pPeerID,
		addrs:          baseInfo.addrs,
		Services:       baseInfo.services,
		LastSend:       statsInfo.lastSend,
		LastRecv:       statsInfo.lastRecv,
		BytesSent:      statsInfo.bytesSent,
		BytesRecv:      statsInfo.bytesRecv,
		ConnTime:       statsInfo.connTime,
		TimeOffset:     statsInfo.timeOffset,
		Version:        baseInfo.protocolVersion,
		UserAgent:      baseInfo.userAgent,
		Inbound:        baseInfo.inbound,
		StartingHeight: statsInfo.startingHeight,
		LastBlock:      statsInfo.lastBlock,
	}
}

func (p *Peer) ID() string {
	return p.peerInfo.ID
}

func (p *Peer) NA() *[]multiaddr.Multiaddr {
	p.flagsMtx.Lock()
	na := p.peerInfo.Addrs
	p.flagsMtx.Unlock()
	return &na
}

func (p *Peer) Addr() []multiaddr.Multiaddr {
	return p.peerInfo.Addrs
}

func (p *Peer) Inbound() bool {
	return p.inbound
}

func (p *Peer) Services() wire.ServiceFlag {
	p.flagsMtx.Lock()
	services := p.services
	p.flagsMtx.Unlock()
	return services
}

func (p *Peer) UserAgent() string {
	p.flagsMtx.Lock()
	userAgent := p.userAgent
	p.flagsMtx.Unlock()
	return userAgent
}

func (p *Peer) LastAnnouncedBlock() *chainhash.Hash {
	p.statsMtx.RLock()
	lastAnnouncedBlock := p.lastAnnouncedBlock
	p.statsMtx.RUnlock()
	return lastAnnouncedBlock
}

func (p *Peer) IsWitnessEnabled() bool {
	p.flagsMtx.Lock()
	witnessEnabled := p.witnessEnabled
	p.flagsMtx.Unlock()

	return witnessEnabled
}

func (p *Peer) WantsHeaders() bool {
	p.flagsMtx.Lock()
	sendHeadersPreferred := p.sendHeadersPreferred
	p.flagsMtx.Unlock()

	return sendHeadersPreferred
}

func (p *Peer) StartingHeight() int32 {
	p.statsMtx.RLock()
	startingHeight := p.startingHeight
	p.statsMtx.RUnlock()
	return startingHeight
}

func (p *Peer) TimeOffset() int64 {
	p.statsMtx.RLock()
	timeOffset := p.timeOffset
	p.statsMtx.RUnlock()
	return timeOffset
}

func (p *Peer) TimeConnected() time.Time {
	p.statsMtx.RLock()
	timeConnected := p.timeConnected
	p.statsMtx.RUnlock()
	return timeConnected
}

func (p *Peer) BytesSent() uint64 {
	return atomic.LoadUint64(&p.bytesSent)
}

func (p *Peer) BytesReceived() uint64 {
	return atomic.LoadUint64(&p.bytesReceived)
}

func (p *Peer) LastSend() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastSend), 0)
}

func (p *Peer) LastRecv() time.Time {
	return time.Unix(atomic.LoadInt64(&p.lastRecv), 0)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

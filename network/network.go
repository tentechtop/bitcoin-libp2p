package network

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/db"
	"bitcoin/event"
	"bitcoin/wire"
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/decred/dcrd/lru"
	"google.golang.org/protobuf/proto"
	"sort"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/libp2p/go-libp2p/p2p/host/autonat"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	quic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// ProtocolHandler 定义协议处理函数类型
type ProtocolHandler func(peerID string, data []byte) ([]byte, error)

// NetworkLayer 网络层接口
type NetworkLayer interface {
	SavePeers() error
	Start() error
	Stop() error
	SelfID() string
	SelfAddrs() []multiaddr.Multiaddr
	Connect(peerInfo PeerInfo) error
	Disconnect(peerID string) error
	ConnectedPeers() []PeerInfo
	Send(peerID string, proto protocol.ID, data []byte) ([]byte, error)
	Broadcast(proto protocol.ID, data []byte) map[string]error
	RegisterProtocol(proto protocol.ID, handler ProtocolHandler)
	DiscoverPeers() (<-chan PeerInfo, error)
	GetConnectedPeerById(peerID string) (PeerInfo, error)
	QueryPersistentPeer(peerID string) (PersistentPeer, error)
	SaveOrUpdatePersistentPeer(peer PersistentPeer) error
	//获取所有节点
	GetAllPersistentPeer() ([]PersistentPeer, error)
	MarkPeerHandshaked(peerID string)
	IsPeerHandshaked(peerID string) bool
	IsOnline(peerID string) bool
	GetChain() *blockchain.BlockChain
	//Ban掉一个节点 参数节点ID String
	Ban(peerID string) error
	//解封一个节点  参数节点ID String
	Unban(peerID string) error
	//对一个节点进行扣分或者加分  参数是节点ID 和 分数
	AdjustPeerScore(peerID string, score int) error
	//根据服务能力查询已经连接且握手的节点
	GetPeerByCondition(peer PersistentPeer) ([]PersistentPeer, error)
	//获取所有持久化节点即使未在线
	GetAllPeer() ([]PersistentPeer, error)
}

// 新增一个用于控制握手并发的map
var handshakeInProgress sync.Map // map[string]struct{}

// PersistentPeer 节点持久化信息结构体
// 与ProtoPersistentPeer完全对齐，增加了转换方法
type PersistentPeer struct {
	ID       string   `json:"id"`        // peer.ID 的字符串形式
	Addrs    []string `json:"addrs"`     // multiaddr 字符串形式
	LastSeen int64    `json:"last_seen"` // 最后活跃时间（时间戳）

	// 1. 连接元数据
	Direction   wire.ConnectionDirection `json:"direction"`    // 连接方向
	ConnTime    int64                    `json:"conn_time"`    // 连接建立时间戳
	DisconnTime int64                    `json:"disconn_time"` // 最后断开时间戳（-1 表示当前连接）
	UserAgent   string                   `json:"user_agent"`   // 用户代理

	// 2. 协议与能力
	ProtocolVersion uint32             `json:"protocol_version"` // 协商后的 P2P 协议版本
	Services        []wire.ServiceFlag `json:"services"`         // 支持的服务能力
	SupportedMsgs   []string           `json:"supported_msgs"`   // 支持的消息类型列表

	// 3. 连接质量
	RTT         uint32            `json:"rtt"`          // 往返延迟（毫秒）
	MsgCount    map[string]uint64 `json:"msg_count"`    // 消息类型统计
	BytesSent   uint64            `json:"bytes_sent"`   // 累计发送字节数
	BytesRecv   uint64            `json:"bytes_recv"`   // 累计接收字节数
	UptimeRatio float32           `json:"uptime_ratio"` // 历史 uptime 占比（0.0~1.0）

	// 4. 安全与行为
	BanScore        uint32               `json:"ban_score"`        // 违规积分
	BanUntil        int64                `json:"ban_until"`        // 封禁截止时间戳（-1 表示未封禁）
	LastErr         string               `json:"last_err"`         // 最后一次错误信息
	HandshakeStatus wire.HandshakeStatus `json:"handshake_status"` // 握手状态

	// 5. 重连策略
	RetryCount    uint32 `json:"retry_count"`    // 历史重连次数
	RetryInterval uint32 `json:"retry_interval"` // 下次重连间隔（秒）
	IsTrusted     bool   `json:"is_trusted"`     // 是否为可信节点
	IsOnline      bool   `json:"is_online"`      // 是否在线
	FeeFilter     int64  `json:"fee_filter"`     // 手续费过滤

	TimeOffset         int64           `json:"time_offset"`          // 对方时间与本地时间的偏移（秒）
	LastAnnouncedBlock *chainhash.Hash `json:"last_announced_block"` // 对方最近宣布的区块哈希
	LastBlockHeight    int32           `json:"last_block_height"`    // 对方节点的最新区块高度
	StartingHeight     int32           `json:"starting_height"`      // 对方初始区块高度（连接时协商的）
	statsMtx           sync.RWMutex    // 保护统计类字段
	flagsMtx           sync.Mutex      // 保护统计类字段

	TimeConnected time.Time `json:"time_connected"` // 连接建立时间

	KnownInventory *lru.Cache      // 已向该节点发送过的 Inv 哈希（key: inv哈希字符串）
	TrickleTimer   *time.Timer     // Trickle 模式定时器（批量发送 Inv）
	InvQueue       []*wire.InvVect // 待发送的 Inv 队列（Trickle 攒批用）

	LastRecvTime    time.Time            // 最后一次收到消息的时间（Idle 检测用）
	LastSendTime    time.Time            // 最后一次发送消息的时间
	PendingRequests map[string]time.Time // 待响应的请求（key: 消息类型，value: 发送时间，Stall 检测用）

	WitnessEnabled  bool `json:"witness_enabled"`   // 是否支持隔离见证（区块链特性）
	SendHeadersPref bool `json:"send_headers_pref"` // 是否偏好接收 Headers 而非 Inv（同步优化）
}

// PeerInfo 节点信息
type PeerInfo struct {
	ID      string
	Addrs   []multiaddr.Multiaddr
	Latency int64 // 延迟（毫秒），可选
}

// Config 网络层配置
type Config struct {
	Handshake      *wire.ProtoHandshake
	Services       []wire.ServiceFlag
	Chain          *blockchain.BlockChain
	DB             db.KeyValueStore
	Bus            *event.Bus
	ListenPort     int
	DataDir        string
	BootstrapPeers []string
	ProtocolPrefix string // 必须以 / 开头，如 "/myblockchain"
	EnableQUIC     bool
	EnableMDNS     bool
	Logger         Logger
	ProxyType      string // 代理类型，如 "socks5"（目前主流支持）
	ProxyAddr      string // 代理地址，如 "127.0.0.1:1080"
	ProxyUser      string // 代理用户名（可选）
	ProxyPasswd    string // 代理密码（可选）
}

const (
	discoveryLimit     = 32 // 每轮发现最多拿 32 个节点
	discoveryTimeout   = 10 * time.Second
	chanBufSize        = 128 // peerCh 缓冲，防止阻塞
	workerNum          = 4   // 并发 worker 数
	MaxPersistentPeers = 100
)

const (
	maxMsgSize    = 1 << 20          // 1 MiB
	perPeerRate   = 10 * 1024 * 1024 // 10 MiB/s
	perPeerBurst  = 2 * 1024 * 1024  // 2 MiB burst
	readDeadline  = 10 * time.Second
	writeDeadline = 10 * time.Second
)

// peerLimiter 每个 peer 一个限速器
var peerLimiter sync.Map // map[string]*rate.Limiter
func getLimiter(pid peer.ID) *rate.Limiter {
	l, _ := peerLimiter.LoadOrStore(string(pid), rate.NewLimiter(rate.Limit(perPeerRate), perPeerBurst))
	return l.(*rate.Limiter)
}

// 新增过期机制，内存永久占用
var probeCache sync.Map

type probeCacheEntry struct {
	Reachable bool      // 节点是否可达
	Timestamp time.Time // 缓存存入时间
}

const probeCacheExpiry = 1 * time.Hour

// Logger 日志接口
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
	Fatalf(format string, v ...interface{})
}

// defaultLogger 默认日志实现
type defaultLogger struct{}

func (d *defaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
}
func (d *defaultLogger) Println(v ...interface{}) {
	fmt.Println(v...)
}
func (d *defaultLogger) Fatalf(format string, v ...interface{}) {
	fmt.Printf(format, v...)
	os.Exit(1)
}

// networkLayer 网络层实现
type networkLayer struct {
	db          db.KeyValueStore
	chain       *blockchain.BlockChain
	bus         *event.Bus
	ctx         context.Context // 主上下文
	cancel      context.CancelFunc
	wg          sync.WaitGroup // 用于等待 goroutine 退出
	config      Config
	host        host.Host
	dht         *dht.IpfsDHT
	routingDisc *routing.RoutingDiscovery
	handlers    map[protocol.ID]ProtocolHandler

	running           bool
	saveDebounceTimer *time.Timer   // 防抖定时器
	saveDebounceDelay time.Duration // 防抖延迟时间，例如5秒
	saveMutex         sync.Mutex    // 保护定时器的互斥锁
	handlerMu         sync.RWMutex
	retryMutex        sync.Mutex
	retryInterval     time.Duration // 初始退避时间
	maxRetries        int           // 最大重试次数
	nat               autonat.AutoNAT
	mdnsService       mdns.Service // 新增：保存 mDNS 实例

	handshakedPeers sync.Map

	peerCache        map[string]PersistentPeer // 节点ID到节点信息的映射
	peerCacheMutex   sync.RWMutex              // 保护peerCache的读写锁
	cacheExpiry      time.Duration             // 缓存过期时间
	cacheLastUpdated time.Time                 // 缓存最后更新时间

}

// NewNetworkLayer 创建新的网络层实例
func NewNetworkLayer(ctx context.Context, config Config) (NetworkLayer, error) {
	// 校验协议前缀格式
	if len(config.ProtocolPrefix) == 0 || config.ProtocolPrefix[0] != '/' {
		return nil, fmt.Errorf("ProtocolPrefix 必须以 / 开头（如 \"/myblockchain\"）")
	}

	// 设置默认日志
	if config.Logger == nil {
		config.Logger = &defaultLogger{}
	}

	// 创建带取消功能的上下文
	ctx, cancel := context.WithCancel(ctx)

	// 创建代理拨号器
	/*	proxyDialer, err := newProxyDialer(chaincfg)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("初始化代理失败：%w", err)
		}*/

	// 生成或加载节点密钥
	privKey, err := LoadOrGenerateKey(config.DB)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("加载密钥失败: %w", err)
	}

	// 配置监听地址
	listenAddrs := make([]multiaddr.Multiaddr, 0)
	tcpAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", config.ListenPort))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("创建TCP地址失败: %w", err)
	}
	listenAddrs = append(listenAddrs, tcpAddr)

	// 如果启用QUIC，添加QUIC监听地址
	if config.EnableQUIC {
		quicAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", config.ListenPort))
		if err != nil {
			config.Logger.Printf("创建QUIC地址失败，将仅使用TCP: %v", err)
		} else {
			listenAddrs = append(listenAddrs, quicAddr)
		}
	}

	// 配置LibP2P选项
	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(listenAddrs...),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.EnableNATService(),
		libp2p.EnableHolePunching(),
		libp2p.NATPortMap(),
		libp2p.DefaultMuxers,                 //默认启用了 Yamux 和 Mplex 两个流复用器。 Yamux 性能更好，Mplex 已逐步弃用
		libp2p.Security(noise.ID, noise.New), //默认会尝试使用 Noise 和 TLS 两个加密协议。 明确指定 Noise，更安全、更轻量、更可控。 libp2p.Security(tls.ID, tls.New),
	}

	// 如果启用QUIC，添加QUIC传输
	if config.EnableQUIC {
		opts = append(opts, libp2p.Transport(quic.NewTransport))
	}

	// 创建主机
	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("创建LibP2P主机失败: %w", err)
	}

	// 创建DHT
	kad, err := dht.New(ctx, h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix(protocol.ID(config.ProtocolPrefix+"/dht")),
	)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("创建DHT失败: %w", err)
	}

	// 初始化网络层实例
	nl := &networkLayer{
		db:                config.DB,
		chain:             config.Chain,
		bus:               config.Bus,
		ctx:               ctx,
		cancel:            cancel,
		config:            config,
		host:              h,
		dht:               kad,
		handlers:          make(map[protocol.ID]ProtocolHandler),
		running:           false,
		saveDebounceDelay: 3 * time.Second, // 设置1秒防抖延迟
		saveDebounceTimer: nil,

		peerCache:        make(map[string]PersistentPeer),
		cacheExpiry:      5 * time.Minute, // 缓存5分钟过期
		cacheLastUpdated: time.Time{},     // 初始化为零值，表示缓存未初始化
	}

	// 初始化 AutoNAT
	nat, err := autonat.New(h)
	if err != nil {
		config.Logger.Printf("AutoNAT 初始化失败: %v", err)
	} else {
		nl.nat = nat
	}

	nl.host.SetStreamHandler(protocol.ID(config.ProtocolPrefix), nl.handleStream)

	return nl, nil
}

// newProxyDialer 根据配置创建代理拨号器
func newProxyDialer(cfg Config) (proxy.ContextDialer, error) {
	if cfg.ProxyType == "" || cfg.ProxyAddr == "" {
		return nil, nil // 无代理配置，返回nil（使用默认拨号）
	}
	// 仅支持 SOCKS5（libP2P 对 SOCKS5 支持最成熟）
	if cfg.ProxyType != "socks5" {
		return nil, fmt.Errorf("仅支持 socks5 代理，当前类型：%s", cfg.ProxyType)
	}
	// 配置 SOCKS5 认证（若有）
	var auth *proxy.Auth
	if cfg.ProxyUser != "" && cfg.ProxyPasswd != "" {
		auth = &proxy.Auth{
			User:     cfg.ProxyUser,
			Password: cfg.ProxyPasswd,
		}
	}
	// 创建 SOCKS5 代理拨号器（使用 golang.org/x/net/proxy）
	dialer, err := proxy.SOCKS5("tcp", cfg.ProxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 代理失败：%w", err)
	}
	// 断言为 ContextDialer（确保支持上下文）
	ctxDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("代理拨号器不支持 ContextDialer 接口")
	}
	return ctxDialer, nil
}

// Start 启动网络层
func (n *networkLayer) Start() error {

	if n.running {
		return nil
	}

	// 启动DHT
	if err := n.dht.Bootstrap(n.ctx); err != nil {
		return fmt.Errorf("DHT启动失败: %w", err)
	}

	// 初始化路由发现
	n.routingDisc = routing.NewRoutingDiscovery(n.dht)

	// 如果启用mDNS，启动mDNS服务（修复：确保nl引用正确）
	if n.config.EnableMDNS {
		//serviceName := "/myblockchain/mdns" // 两个节点必须使用相同的名称
		go func() {
			// 创建mDNS服务
			mdnsService := mdns.NewMdnsService(n.host, n.config.ProtocolPrefix, &mdnsNotifee{nl: n})
			// 保存服务实例
			mdnsService.Start()
			n.mdnsService = mdnsService
			log.Infof("mDNS服务启动成功")
			// 等待退出信号
			<-n.ctx.Done()
			// 收到退出信号，关闭mDNS服务
			if err := mdnsService.Close(); err != nil {
				log.Infof("mDNS服务关闭错误: %v", err)
			} else {
				log.Infof("mDNS服务已关闭")
			}
			n.mdnsService = nil
		}()
	}

	// 连接到启动节点
	if err := n.connectBootstrapPeers(); err != nil {
		log.Infof("连接启动节点时出错: %v", err)
	}

	// 注册网络事件监听器（监听连接建立/断开）
	n.host.Network().Notify(&network.NotifyBundle{
		ConnectedF:    n.onPeerConnected,    // 新节点连接时
		DisconnectedF: n.onPeerDisconnected, // 节点断开时
	})

	log.Infof("DHT启动成功，初始路由表大小: %d", n.dht.RoutingTable().Size())

	n.running = true

	// 打印对外地址
	log.Infof("[NAT] 对外地址: %v", n.host.Addrs())

	log.Infof("当前节点ID: %s\n", n.SelfID())

	//启动节点发现
	_, err := n.DiscoverPeers()
	if err != nil {
		log.Infof("启动节点发现失败: %v", err)
	}

	cleanupTicker := time.NewTicker(probeCacheExpiry / 2) // 每30分钟清理一次
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-n.ctx.Done(): // 网络层停止时退出清理协程
				return
			case <-cleanupTicker.C:
				n.cleanupExpiredProbeCache() // 执行清理逻辑
			}
		}
	}()

	// 路由表变化 纳入WaitGroup管理
	go n.logRoutingTableDelta()
	// 加载并连接持久化节点
	go n.connectPersistentPeers()
	return nil
}

// 2. 仅当路由表长度变化时打印日志
func (n *networkLayer) logRoutingTableDelta() {
	n.wg.Add(1) // 新增
	go func() {
		defer n.wg.Done() // 新增
		lastSize := 0
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		// 并发控制信号量：避免同时握手过多节点（限制10个并发）
		sem := make(chan struct{}, 10)
		defer close(sem)

		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				current := n.dht.RoutingTable().Size()
				if current != lastSize {
					log.Infof("路由表变化: %d -> %d", lastSize, current)
					lastSize = current
					//与路由表中未握手的的节点握手
					routingPeers := n.dht.RoutingTable().ListPeers()
					log.Infof("路由表包含 %d 个节点，开始检查握手状态", len(routingPeers))
					//遍历节点，筛选未握手节点
					for _, pid := range routingPeers {
						peerID := pid.String()
						// 跳过自身节点
						if peerID == n.SelfID() {
							continue
						}
						// 3. 检查节点地址（无地址无法连接）
						addrs := n.host.Peerstore().Addrs(pid)
						if len(addrs) == 0 {
							log.Infof("未握手节点[%s]无地址信息，跳过", peerID)
							//continue
						}
						//并发控制：获取信号量
						sem <- struct{}{}
						go func(targetPID peer.ID, targetID string, targetAddrs []multiaddr.Multiaddr) {
							defer func() { <-sem }() // 释放信号量

							// 再次检查上下文（避免已关闭时继续执行）
							select {
							case <-n.ctx.Done():
								return
							default:
							}

							// 5. 检查连接状态：未连接则先连接
							connStatus := n.host.Network().Connectedness(targetPID)
							if connStatus != network.Connected {
								log.Infof("未握手节点[%s]未连接，发起连接", targetID)
								if err := n.Connect(PeerInfo{
									ID:    targetID,
									Addrs: targetAddrs,
								}); err != nil {
									log.Infof("连接未握手节点[%s]失败: %v", targetID, err)
									return
								}
							}
							go n.triggerHandshake(targetID)
						}(pid, peerID, addrs)
					}
				}
			}
		}
	}()
}

// 3. 加载并连接持久化节点
func (n *networkLayer) connectPersistentPeers() {
	log.Infof("连接到持久化节点")
	go func() {
		peers, err := n.loadPersistentPeers()
		if err != nil {
			log.Infof("加载持久化节点失败: %v", err)
			return
		}

		// 过滤引导节点
		bootstrapSet := make(map[string]struct{})
		for _, addr := range n.config.BootstrapPeers {
			if info, err := peer.AddrInfoFromP2pAddr(multiaddr.StringCast(addr)); err == nil {
				bootstrapSet[info.ID.String()] = struct{}{}
			}
		}
		var filtered []PersistentPeer
		for _, p := range peers {
			if _, ok := bootstrapSet[p.ID]; !ok {
				filtered = append(filtered, p)
			}
		}
		for _, p := range filtered {
			peerInfo, err := n.toPeerInfo(p)
			if err != nil {
				continue
			}
			if n.host.Network().Connectedness(peer.ID(peerInfo.ID)) == network.Connected {
				continue
			}
			if err := n.Connect(peerInfo); err != nil {
				log.Infof("连接持久化节点 %s 失败: %v", peerInfo.ID, err)
			} else {
				log.Infof("成功连接持久化节点: %s", peerInfo.ID)
			}
			go n.triggerHandshake(peerInfo.ID)
		}
	}()
}

// Stop 停止网络层
func (n *networkLayer) Stop() error {
	if !n.running {
		return nil
	}
	n.running = false
	// 2. 关闭所有连接
	for _, pid := range n.host.Network().Peers() {
		n.host.Network().ClosePeer(pid)
	}
	// 3. 取消上下文，通知所有 goroutine 退出
	n.cancel()
	// 4. 等待所有 goroutine 退出
	n.wg.Wait()
	// 5. 停止防抖定时器
	n.saveMutex.Lock()
	if n.saveDebounceTimer != nil {
		n.saveDebounceTimer.Stop()
	}
	n.saveMutex.Unlock()
	// 7. 关闭 DHT
	if n.dht != nil {
		if err := n.dht.Close(); err != nil {
			log.Infof("关闭 DHT 时出错: %v", err)
		}
	}
	log.Infof("成功关闭DHT")
	// 8. 最后关闭 LibP2P 主机（确保底层资源最后释放）
	if err := n.host.Close(); err != nil {
		log.Infof("关闭 LibP2P 主机时出错: %v", err)
		return err
	}
	log.Infof("LibP2P 主机已关闭")
	log.Infof("网络层已成功关闭")
	return nil
}

// SelfID 返回自身节点ID
func (n *networkLayer) SelfID() string {
	return n.host.ID().String()
}

// SelfAddrs 返回自身节点地址
func (n *networkLayer) SelfAddrs() []multiaddr.Multiaddr {
	return n.host.Addrs()
}

// Connect 连接到指定节点
func (n *networkLayer) Connect(peerInfo PeerInfo) error {
	log.Infof("Connect: %s 开始连接", peerInfo.ID)
	if !n.running {
		return fmt.Errorf("网络层未启动")
	}
	return n.attemptConnect(peerInfo)
}

// 尝试连接到指定节点
func (n *networkLayer) attemptConnect(peerInfo PeerInfo) error {
	n.retryMutex.Lock()
	defer n.retryMutex.Unlock()
	p, err := n.QueryPersistentPeer(peerInfo.ID)
	if err == nil && p.BanUntil > time.Now().Unix() {
		return fmt.Errorf("节点 %s 处于封禁状态", peerInfo.ID)
	}

	log.Infof("尝试连接")

	if n.host.Network().Connectedness(peer.ID(peerInfo.ID)) == network.Connected {
		return nil
	}

	pid, err := peer.Decode(peerInfo.ID)
	if err != nil {
		return fmt.Errorf("无效节点ID: %w", err)
	}

	addrInfo := peer.AddrInfo{ID: pid, Addrs: peerInfo.Addrs}

	ctx, cancel := context.WithTimeout(n.ctx, 5*time.Second)
	defer cancel()

	// 1. TCP/QUIC 建连
	if err := n.host.Connect(ctx, addrInfo); err != nil {
		return err
	}
	go n.triggerHandshake(peerInfo.ID)
	return nil
}

// Disconnect 断开与指定节点的连接
func (n *networkLayer) Disconnect(peerID string) error {
	if !n.running {
		return fmt.Errorf("网络层未启动")
	}

	pid, err := peer.Decode(peerID)
	if err != nil {
		return fmt.Errorf("无效的节点ID: %w", err)
	}

	n.host.Network().ClosePeer(pid)
	return nil
}

// ConnectedPeers 获取已连接的节点列表
func (n *networkLayer) ConnectedPeers() []PeerInfo {
	peers := make([]PeerInfo, 0)
	for _, pid := range n.host.Network().Peers() {
		peers = append(peers, PeerInfo{
			ID:    pid.String(),
			Addrs: n.host.Peerstore().Addrs(pid),
		})
	}
	return peers
}

// Send 向指定节点发送数据
func (n *networkLayer) SendBack(peerID string, proto protocol.ID, data []byte) ([]byte, error) {
	if !n.running {
		return nil, fmt.Errorf("网络层未启动")
	}

	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, fmt.Errorf("无效的节点ID: %w", err)
	}

	// 创建流
	stream, err := n.host.NewStream(n.ctx, pid, proto)
	if err != nil {
		return nil, fmt.Errorf("创建流失败: %w", err)
	}
	defer stream.Close()

	// 发送数据
	if _, err := stream.Write(data); err != nil {
		return nil, fmt.Errorf("发送数据失败: %w", err)
	}

	// 读取响应
	buf := make([]byte, 4096)
	readLen, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	return buf[:readLen], nil
}

func (n *networkLayer) Send(peerID string, proto protocol.ID, data []byte) ([]byte, error) {
	if !n.running {
		return nil, fmt.Errorf("网络层未启动")
	}

	pid, err := peer.Decode(peerID)
	if err != nil {
		log.Infof("无效的节点ID: %w", err)
		return nil, err
	}
	stream, err := n.host.NewStream(n.ctx, pid, proto)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	_ = stream.SetReadDeadline(time.Now().Add(readDeadline))
	_ = stream.SetWriteDeadline(time.Now().Add(writeDeadline))

	if err := safeWriteMsg(stream, pid, data); err != nil {
		return nil, err
	}
	return safeReadMsg(stream, pid)
}

// Broadcast 广播数据到所有已连接节点握手的节点
func (n *networkLayer) Broadcast(proto protocol.ID, data []byte) map[string]error {
	errors := make(map[string]error)
	peers := n.ConnectedPeers()
	for _, peer := range peers {
		_, err := n.Send(peer.ID, proto, data)
		if err != nil {
			errors[peer.ID] = err
		}
	}
	return errors
}

func (n *networkLayer) BroadcastACK(proto protocol.ID, data []byte, timeout time.Duration, retries int) map[string]error {
	errors := make(map[string]error)
	peers := n.ConnectedPeers()

	// 用于同步等待所有广播操作完成
	var wg sync.WaitGroup

	// 用于控制重传
	retryCh := make(chan string, len(peers))

	// 启动广播操作
	for _, peer := range peers {
		wg.Add(1)
		go func(peer PeerInfo) {
			defer wg.Done()
			// 尝试发送消息
			for attempt := 0; attempt <= retries; attempt++ {
				_, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				resp, err := n.Send(peer.ID, proto, data)
				if err != nil {
					log.Infof("向 %s 发送广播失败（尝试 %d/%d）: %v", peer.ID, attempt+1, retries+1, err)
					retryCh <- peer.ID
					continue
				}

				// 检查是否收到 ACK
				if string(resp) == "ACK" {
					errors[peer.ID] = nil
					return
				} else {
					log.Infof("从 %s 收到非 ACK 响应: %s", peer.ID, string(resp))
					retryCh <- peer.ID
				}
			}
			// 如果所有尝试都失败
			errors[peer.ID] = fmt.Errorf("所有尝试均失败")
		}(peer)
	}

	// 等待所有广播操作完成
	wg.Wait()

	return errors
}

// RegisterProtocol 注册协议处理器
func (n *networkLayer) RegisterProtocol(proto protocol.ID, handler ProtocolHandler) {
	n.handlerMu.Lock()
	defer n.handlerMu.Unlock()
	n.handlers[proto] = handler

	// 为该协议注册流处理器
	n.host.SetStreamHandler(proto, n.handleStream)
}

// DiscoverPeers 启动节点发现
func (n *networkLayer) DiscoverPeers() (<-chan PeerInfo, error) {
	if !n.running || n.routingDisc == nil {
		return nil, errors.New("网络层未启动或路由发现未初始化")
	}
	peerCh := make(chan PeerInfo, chanBufSize)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer close(peerCh)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-n.ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(n.ctx, discoveryTimeout)
				peerStream, err := n.routingDisc.FindPeers(
					ctx,
					n.config.ProtocolPrefix,
					discovery.Limit(discoveryLimit),
				)
				if err != nil {
					log.Infof("FindPeers 失败: %v", err)
					cancel()
					continue
				}

				// 1. 把 peerStream 转到无缓冲 raw channel，完成后关闭
				raw := make(chan peer.AddrInfo, discoveryLimit)
				go func() {
					defer close(raw)
					for p := range peerStream {
						select {
						case raw <- p:
						case <-ctx.Done():
							return
						}
					}
				}()

				// 2. 启动固定数量 worker
				var wg sync.WaitGroup
				wg.Add(workerNum)
				for i := 0; i < workerNum; i++ {
					go func() {
						defer wg.Done()
						for p := range raw {
							if p.ID.String() == n.SelfID() {
								continue
							}
							select {
							case peerCh <- PeerInfo{
								ID:    p.ID.String(),
								Addrs: p.Addrs,
							}:
							case <-n.ctx.Done():
								return
							}
						}
					}()
				}
				wg.Wait()
				cancel()
			}
		}
	}()
	return peerCh, nil
}

// handleStream 处理流数据 高并发
func (n *networkLayer) handleStream(stream network.Stream) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(readDeadline))
	_ = stream.SetWriteDeadline(time.Now().Add(writeDeadline))

	peerID := stream.Conn().RemotePeer() // 从流中获取协议ID
	msgProto := stream.Protocol()

	// 关键修改：检查节点是否已完成握手，未完成则拒绝处理
	// 关键修改：握手协议消息绕过握手状态检查
	// 只有非握手协议才需要验证是否已完成握手
	if msgProto != HandshakeProtocol {
		// 检查节点是否已完成握手，未完成则拒绝处理非握手协议消息
		if !n.IsPeerHandshaked(peerID.String()) {
			log.Infof("拒绝处理未完成握手的节点 %s 的数据（协议: %s）", peerID, msgProto)
			// 发送握手要求响应
			resp := &wire.CommonResp{
				Code:    403,
				Message: "未完成握手，请先进行握手",
			}
			respData, _ := proto.Marshal(resp)
			_ = safeWriteMsg(stream, peerID, respData)
			// 主动关闭连接
			go func() {
				_ = n.Disconnect(peerID.String())
			}()
			return
		}
	}
	log.Infof("收到来自 %s 的协议 %s 数据", peerID, msgProto)

	data, err := safeReadMsg(stream, peerID)
	if err != nil {
		log.Infof("read: %v", err)
		return
	}
	handler, exists := n.handlers[stream.Protocol()]
	var resp []byte
	if !exists {
		log.Infof("未找到协议 %s 的处理器", msgProto)
		resp = []byte("unsupported wire")
	} else {
		var err error
		resp, err = handler(peerID.String(), data)
		if err != nil {
			log.Infof("处理 %s 协议数据失败: %v", msgProto, err)
			resp = []byte(err.Error())
		}
	}
	if resp != nil {
		if err := safeWriteMsg(stream, peerID, resp); err != nil {
			log.Infof("向 %s 发送响应失败: %v", peerID, err)
		}
	}
}

func (n *networkLayer) handleStreamBack(stream network.Stream) {
	defer stream.Close()

	peerID := stream.Conn().RemotePeer().String()
	proto := stream.Protocol() // 从流中获取协议ID
	log.Infof("收到来自 %s 的协议 %s 数据", peerID, proto)

	// 读取数据
	buf := make([]byte, 4096)
	readLen, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Infof("从 %s 读取数据失败: %v", peerID, err)
		return
	}
	data := buf[:readLen]
	handler, exists := n.handlers[proto]
	var response []byte
	if !exists {
		log.Infof("未找到协议 %s 的处理器", proto)
		response = []byte("未支持的协议")
	} else {
		// 调用处理器
		var err error
		response, err = handler(peerID, data)
		if err != nil {
			log.Infof("处理 %s 协议数据失败: %v", proto, err)
			response = []byte("处理数据时出错")
		}
	}

	// 发送响应
	if _, err := stream.Write(response); err != nil {
		log.Infof("向 %s 发送响应失败: %v", peerID, err)
	}
}

// 连接到启动节点
func (n *networkLayer) connectBootstrapPeers() error {
	var lastErr error
	for _, addrStr := range n.config.BootstrapPeers {
		ma, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			log.Infof("解析启动节点地址 %s 失败: %v", addrStr, err)
			lastErr = err
			continue
		}

		info, err := peer.AddrInfoFromP2pAddr(ma)
		if err != nil {
			log.Infof("解析启动节点信息 %s 失败: %v", addrStr, err)
			lastErr = err
			continue
		}

		if err := n.host.Connect(n.ctx, *info); err != nil {
			log.Infof("连接启动节点 %s 失败: %v", info.ID, err)
			lastErr = err
		} else {
			log.Infof("成功连接启动节点: %s", info.ID)
			go n.triggerHandshake(info.ID.String())
		}
	}
	return lastErr
}

// mdnsNotifee 处理mDNS发现的节点
type mdnsNotifee struct {
	nl *networkLayer
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	peerID := pi.ID.String()
	if peerID == m.nl.SelfID() {
		return
	}

	// 检查是否已连接
	if m.nl.host.Network().Connectedness(pi.ID) == network.Connected {
		return
	}

	m.nl.config.Logger.Printf("mDNS发现节点: %s", peerID)
	_ = m.nl.Connect(PeerInfo{
		ID:    peerID,
		Addrs: pi.Addrs,
	})
}

// LoadOrGenerateKey 从数据库加载或生成节点密钥
// 使用 PeerKeyBucket 存储，以 PeerPrivateKeyKey 为键
func LoadOrGenerateKey(store db.KeyValueStore) (crypto.PrivKey, error) {
	// 1. 构造完整的数据库键：PeerKeyBucket + PeerPrivateKeyKey
	// 按照db包的设计，使用Bucket的Key方法生成带桶前缀的键
	key := db.MainStatus.Key([]byte(db.PeerPrivateKeyKey))

	var privKey crypto.PrivKey
	// 2. 尝试从数据库读取已存在的密钥
	err := store.Get(key, func(value []byte) error {
		if value == nil {
			return db.ErrKeyNotFound // 密钥不存在，需要生成新的
		}

		// 反序列化私钥
		decodedKey, err := crypto.UnmarshalPrivateKey(value)
		if err != nil {
			return fmt.Errorf("反序列化私钥失败: %w", err)
		}
		privKey = decodedKey
		return nil
	})

	// 处理数据库操作错误（忽略"键不存在"的错误）
	if err != nil && err != db.ErrKeyNotFound {
		return nil, fmt.Errorf("从数据库读取密钥失败: %w", err)
	}

	// 3. 如果密钥不存在，则生成新的Ed25519密钥
	if privKey == nil {
		newPriv, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("生成新密钥失败: %w", err)
		}

		// 序列化密钥
		keyBytes, err := crypto.MarshalPrivateKey(newPriv)
		if err != nil {
			return nil, fmt.Errorf("序列化新密钥失败: %w", err)
		}

		// 将新密钥保存到数据库（使用事务确保原子性）
		if err := store.Update(func(batch db.IndexedBatch) error {
			return batch.Put(key, keyBytes)
		}); err != nil {
			return nil, fmt.Errorf("保存新密钥到数据库失败: %w", err)
		}
		privKey = newPriv
	}
	return privKey, nil
}

// 将当前连接的节点转换为PersistentPeer列表
func (n *networkLayer) getPersistentPeers() []PersistentPeer {
	connected := n.ConnectedPeers()
	peers := make([]PersistentPeer, 0, len(connected))
	for _, p := range connected {
		// 转换multiaddr为字符串
		addrStrs := make([]string, 0, len(p.Addrs))
		for _, addr := range p.Addrs {
			addrStrs = append(addrStrs, addr.String())
		}
		peers = append(peers, PersistentPeer{
			ID:       p.ID,
			Addrs:    addrStrs,
			LastSeen: time.Now().Unix(), // 更新最后seen时间为当前时间
		})
	}
	return peers
}

// 保存节点信息到数据库（Protobuf 序列化）- 增加数量控制
func (n *networkLayer) savePersistentPeers() error {
	// 1. 获取当前连接的节点并转换为 PersistentPeer 列表
	peers := n.getPersistentPeers()
	if len(peers) == 0 {
		log.Infof("没有需要保存的节点信息")
		return nil
	}
	if len(peers) == 0 {
		log.Infof("没有需要保存的有效节点")
		return nil
	}
	//  数量控制
	filteredPeers := filterTopNPeers(peers, MaxPersistentPeers)

	// 批量保存到数据库
	err := n.db.Update(func(batch db.IndexedBatch) error {
		if err := n.clearAllPersistentPeers(batch); err != nil {
			return fmt.Errorf("清空旧节点失败: %w", err)
		}

		for _, p := range filteredPeers {
			protoPeer := p.ToProto()
			data, err := proto.Marshal(protoPeer)
			if err != nil {
				return fmt.Errorf("序列化节点 %s 失败: %w", p.ID, err)
			}
			key := db.PersistentPeerBucket.Key([]byte(p.ID))
			if err := batch.Put(key, data); err != nil {
				return fmt.Errorf("保存节点 %s 失败: %w", p.ID, err)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 关键修改：批量更新缓存
	n.replaceCache(filteredPeers)

	log.Infof("成功保存 %d 个节点信息到数据库", len(filteredPeers))
	return nil
}

// 新增：清空数据库中所有持久化节点（用于批量更新前的清理）
func (n *networkLayer) clearAllPersistentPeers(batch db.IndexedBatch) error {
	// 构造节点存储桶前缀
	bucketPrefix := db.PersistentPeerBucket.Key()

	// 迭代删除桶内所有键值对
	iter, err := n.db.NewIterator(bucketPrefix, true)
	if err != nil {
		return fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close()

	for iter.Valid() {
		// 删除当前键
		if err := batch.Delete(iter.Key()); err != nil {
			return fmt.Errorf("删除旧节点（键: %x）失败: %w", iter.Key(), err)
		}
		iter.Next()
	}
	return nil
}

// 从数据库加载节点信息（Protobuf 反序列化）- 增加数量控制
func (n *networkLayer) loadPersistentPeers() ([]PersistentPeer, error) {
	// 1. 先检查缓存是否有效（如果最近更新过，直接使用缓存）
	n.peerCacheMutex.RLock()
	cacheValid := !n.cacheLastUpdated.IsZero()
	n.peerCacheMutex.RUnlock()

	if cacheValid {
		n.peerCacheMutex.RLock()
		peers := make([]PersistentPeer, 0, len(n.peerCache))
		for _, p := range n.peerCache {
			peers = append(peers, p)
		}
		n.peerCacheMutex.RUnlock()
		log.Infof("从缓存加载节点：共 %d 个", len(peers))
		return peers, nil
	}

	// 2. 缓存无效，从数据库加载
	var peers []PersistentPeer
	bucketPrefix := db.PersistentPeerBucket.Key()
	iter, err := n.db.NewIterator(bucketPrefix, true)
	if err != nil {
		return nil, fmt.Errorf("创建节点迭代器失败: %w", err)
	}
	defer iter.Close()

	if !iter.First() {
		log.Infof("数据库中无持久化节点数据")
		return peers, nil
	}

	for iter.Valid() {
		value, err := iter.Value()
		if err != nil {
			return nil, fmt.Errorf("读取节点数据失败（键: %x）: %w", iter.Key(), err)
		}

		var protoPeer wire.ProtoPersistentPeer
		if err := proto.Unmarshal(value, &protoPeer); err != nil {
			log.Infof("反序列化节点数据失败，跳过该节点（键: %x）: %v", iter.Key(), err)
			iter.Next()
			continue
		}

		var p PersistentPeer
		p.FromProto(&protoPeer)

		nodeID := string(iter.Key()[len(bucketPrefix):])
		if p.ID != nodeID {
			log.Infof("节点ID与存储键不一致，跳过（键: %s, 节点ID: %s）", nodeID, p.ID)
			iter.Next()
			continue
		}

		peers = append(peers, p)
		iter.Next()
	}

	// --------------------------
	// 新增：加载后筛选，确保不超过100个
	// --------------------------
	filteredPeers := filterTopNPeers(peers, MaxPersistentPeers)
	n.replaceCache(filteredPeers)
	log.Infof("加载节点筛选后：原始=%d，保留=%d", len(peers), len(filteredPeers))
	return filteredPeers, nil
}

// ---------- 新增：从 peers.json 中删除指定节点 ----------
// 从数据库中删除指定节点的持久化记录
func (n *networkLayer) removePersistentPeer(targetID string) {
	// 1. 构造目标节点的存储键
	key := db.PersistentPeerBucket.Key([]byte(targetID))

	// 2. 执行删除操作（事务保证原子性）
	err := n.db.Update(func(batch db.IndexedBatch) error {
		return batch.Delete(key)
	})

	// 3. 日志反馈结果
	if err != nil {
		log.Infof("删除节点[%s]失败: %v", targetID, err)
	} else {
		log.Infof("已删除节点[%s]的持久化记录", targetID)
		n.removeFromCache(targetID)
	}
}

// 轻量级探测：TCP/QUIC 都能覆盖
func (n *networkLayer) addrReachable(addr multiaddr.Multiaddr) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// 提取 network+host
	netw, host, err := manet.DialArgs(addr)
	if err != nil {
		return false
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, netw, host)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// 将PersistentPeer转换为PeerInfo（包含有效的multiaddr）
func (n *networkLayer) toPeerInfo(p PersistentPeer) (PeerInfo, error) {
	addrs := make([]multiaddr.Multiaddr, 0, len(p.Addrs))
	for _, addrStr := range p.Addrs {
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			log.Infof("忽略无效地址 %s（节点 %s）: %v", addrStr, p.ID, err)
			continue // 跳过无效地址
		}
		addrs = append(addrs, addr)
	}

	if len(addrs) == 0 {
		return PeerInfo{}, fmt.Errorf("节点 %s 没有有效地址", p.ID)
	}

	return PeerInfo{
		ID:    p.ID,
		Addrs: addrs,
	}, nil
}

// 在networkLayer结构体中实现
func (n *networkLayer) SavePeers() error {
	return n.savePersistentPeers()
}

// 修改1: 在onPeerConnected的握手goroutine中使用上下文控制
func (n *networkLayer) onPeerConnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer().String()
	dir := conn.Stat().Direction
	log.Infof("节点 %s 已经连接 dir=%v", peerID, dir)
}

// 节点断开连接时触发
func (n *networkLayer) onPeerDisconnected(net network.Network, conn network.Conn) {
	peerID := conn.RemotePeer().String()
	dir := conn.Stat().Direction
	log.Infof("节点 %s 断开连接 dir=%v", peerID, dir)
	//更新节点为已经下线
	// 新增：从握手状态Map中删除断开连接的节点ID
	/*	n.handshakedPeers.Delete(peerID)*/
}

func writeMsg(w io.Writer, p []byte) error {
	var header [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(header[:], uint64(len(p)))
	if _, err := w.Write(header[:n]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// 读取：先读 varint，再读 body
func readMsg(r io.Reader) ([]byte, error) {
	l, err := binary.ReadUvarint(r.(io.ByteReader))
	if err != nil {
		return nil, err
	}
	if l > 1<<20 {
		return nil, errors.New("message too large")
	}
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	return buf, err
}

func safeReadMsg(r io.Reader, pid peer.ID) ([]byte, error) {
	// 包装成带缓冲的 ByteReader
	br := bufio.NewReader(r)

	if err := getLimiter(pid).WaitN(context.Background(), 4); err != nil {
		return nil, err
	}
	l, err := binary.ReadUvarint(br) // ← 用 br 而不是 r
	if err != nil {
		return nil, err
	}
	if l > maxMsgSize {
		return nil, errors.New("message too large")
	}
	if err := getLimiter(pid).WaitN(context.Background(), int(l)); err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(br, buf); err != nil { // ← 继续用 br
		return nil, err
	}
	return buf, nil
}

func safeWriteMsg(w io.Writer, pid peer.ID, p []byte) error {
	if len(p) > maxMsgSize {
		return errors.New("message too large")
	}
	if err := getLimiter(pid).WaitN(context.Background(), 4+len(p)); err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	var header [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(header[:], uint64(len(p)))
	if _, err := bw.Write(header[:n]); err != nil {
		return err
	}
	if _, err := bw.Write(p); err != nil {
		return err
	}
	return bw.Flush()
}

func (n *networkLayer) BroadcastAsync(ctx context.Context, proto protocol.ID, data []byte) error {
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, 16) // 并发上限
	for _, p := range n.ConnectedPeers() {
		p := p
		g.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()
			_, err := n.Send(p.ID, proto, data)
			return err
		})
	}
	return g.Wait()
}

// ToProto 将PersistentPeer转换为ProtoPersistentPeer
func (p *PersistentPeer) ToProto() *wire.ProtoPersistentPeer {
	// 转换服务能力列表
	protoServices := make([]wire.ServiceFlag, len(p.Services))
	for i, s := range p.Services {
		protoServices[i] = wire.ServiceFlag(s)
	}

	return &wire.ProtoPersistentPeer{
		ID:                 p.ID,
		Addrs:              p.Addrs,
		LastSeen:           p.LastSeen,
		Direction:          wire.ConnectionDirection(p.Direction),
		ConnTime:           p.ConnTime,
		DisconnTime:        p.DisconnTime,
		UserAgent:          p.UserAgent,
		ProtocolVersion:    p.ProtocolVersion,
		Services:           protoServices,
		SupportedMsgs:      p.SupportedMsgs,
		Rtt:                p.RTT,
		MsgCount:           p.MsgCount,
		BytesSent:          p.BytesSent,
		BytesRecv:          p.BytesRecv,
		UptimeRatio:        p.UptimeRatio,
		BanScore:           p.BanScore,
		BanUntil:           p.BanUntil,
		LastErr:            p.LastErr,
		HandshakeStatus:    p.HandshakeStatus,
		RetryCount:         p.RetryCount,
		RetryInterval:      p.RetryInterval,
		IsTrusted:          p.IsTrusted,
		IsOnline:           p.IsOnline,
		LastBlockHeight:    p.LastBlockHeight,
		LastAnnouncedBlock: p.LastAnnouncedBlock[:],
	}
}

// FromProto 从ProtoPersistentPeer转换为PersistentPeer
func (p *PersistentPeer) FromProto(protoPeer *wire.ProtoPersistentPeer) {
	// 转换服务能力列表
	services := make([]wire.ServiceFlag, len(protoPeer.Services))
	for i, s := range protoPeer.Services {
		services[i] = s
	}

	hash, _ := chainhash.BytesToHash(protoPeer.LastAnnouncedBlock)

	p.ID = protoPeer.ID
	p.Addrs = protoPeer.Addrs
	p.LastSeen = protoPeer.LastSeen
	p.Direction = protoPeer.Direction
	p.ConnTime = protoPeer.ConnTime
	p.DisconnTime = protoPeer.DisconnTime
	p.UserAgent = protoPeer.UserAgent
	p.ProtocolVersion = protoPeer.ProtocolVersion
	p.Services = services
	p.SupportedMsgs = protoPeer.SupportedMsgs
	p.RTT = protoPeer.Rtt
	p.MsgCount = protoPeer.MsgCount
	p.BytesSent = protoPeer.BytesSent
	p.BytesRecv = protoPeer.BytesRecv
	p.UptimeRatio = protoPeer.UptimeRatio
	p.BanScore = protoPeer.BanScore
	p.BanUntil = protoPeer.BanUntil
	p.LastErr = protoPeer.LastErr
	p.HandshakeStatus = protoPeer.HandshakeStatus
	p.RetryCount = protoPeer.RetryCount
	p.RetryInterval = protoPeer.RetryInterval
	p.IsTrusted = protoPeer.IsTrusted
	p.IsOnline = protoPeer.IsOnline
	p.LastAnnouncedBlock = &hash
	p.LastBlockHeight = protoPeer.LastBlockHeight

}

//	根据节点ID获取已连接的节点信息
//
// 若节点ID无效、未连接或网络层未启动，返回空PeerInfo及对应错误
func (n *networkLayer) GetConnectedPeerById(peerID string) (PeerInfo, error) {
	// 1. 校验网络层状态：未启动则直接返回错误
	if !n.running {
		return PeerInfo{}, fmt.Errorf("网络层未启动，无法获取节点信息")
	}

	// 2. 校验并解码节点ID：字符串ID需转换为libp2p的peer.ID类型
	pid, err := peer.Decode(peerID)
	if err != nil {
		return PeerInfo{}, fmt.Errorf("无效的节点ID [%s]：%w", peerID, err)
	}

	// 3. 检查节点是否已连接
	if n.host.Network().Connectedness(pid) != network.Connected {
		return PeerInfo{}, fmt.Errorf("节点 [%s] 未处于连接状态", peerID)
	}

	// 4. 从Peerstore获取节点地址列表（已连接节点必然有地址缓存）
	addrs := n.host.Peerstore().Addrs(pid)
	if len(addrs) == 0 {
		// 理论上已连接节点不会无地址，此处做兼容处理
		log.Infof("警告：已连接节点 [%s] 无缓存地址", peerID)
		return PeerInfo{ID: peerID}, nil // 至少返回有效ID
	}

	// 5. 构造并返回完整的PeerInfo
	return PeerInfo{
		ID:    peerID,
		Addrs: addrs,
		// Latency字段可选：若需要实时延迟可额外实现（如通过RTT统计）
		Latency: 0,
	}, nil
}

// QueryPersistentPeer 根据节点ID查询持久化节点信息
// 若未查询到（或查询过程出错），返回空的PersistentPeer结构体
func (n *networkLayer) QueryPersistentPeer(peerID string) (PersistentPeer, error) {
	// 1. 构造数据库查询键：PersistentPeerBucket + 节点ID（与保存逻辑对齐）
	queryKey := db.PersistentPeerBucket.Key([]byte(peerID))

	// 初始化返回结果（默认为空结构体）
	var targetPeer PersistentPeer

	// 2. 从数据库读取对应节点数据
	err := n.db.Get(queryKey, func(value []byte) error {
		// 若值为空，说明键不存在（未查询到节点）
		if value == nil {
			return db.ErrKeyNotFound
		}

		// 3. Protobuf 反序列化：二进制数据 → ProtoPersistentPeer
		var protoPeer wire.ProtoPersistentPeer
		if err := proto.Unmarshal(value, &protoPeer); err != nil {
			return fmt.Errorf("反序列化节点数据失败: %w", err)
		}

		// 4. 转换为业务层的 PersistentPeer 结构体
		targetPeer.FromProto(&protoPeer)
		return nil
	})

	// 5. 处理查询错误（未找到时仅返回空，其他错误打日志后仍返回空）
	if err != nil {
		if err != db.ErrKeyNotFound {
			// 非"未找到"错误需记录日志（如反序列化失败、数据库异常）
			log.Infof("查询持久化节点 [%s] 异常: %v", peerID, err)
		}
		return PersistentPeer{}, fmt.Errorf("查询持久化节点 [%s] 异常: %v", peerID, err) // 未找到或出错，返回空结构体
	}

	// 6. 查询成功，返回完整的持久化节点信息
	return targetPeer, nil
}

// SaveOrUpdatePersistentPeer 保存或更新单个节点的持久化信息-增加数量控制
func (n *networkLayer) SaveOrUpdatePersistentPeer(peer PersistentPeer) error {
	// 1. 原有校验逻辑（不变）
	if peer.ID == "" {
		err := fmt.Errorf("节点ID不能为空")
		log.Infof("保存/更新节点失败: %v", err)
		return err
	}
	/*	if len(peer.Addrs) == 0 {
		err := fmt.Errorf("节点地址列表不能为空（节点ID: %s）", peer.ID)
		log.Infof("保存/更新节点失败: %v", err)
		return err
	}*/
	/*	hasValidAddr := false
		for _, addrStr := range peer.Addrs {
			if strings.TrimSpace(addrStr) != "" {
				hasValidAddr = true
				break
			}
		}*/
	/*	if !hasValidAddr {
			err := fmt.Errorf("节点地址列表无有效地址（节点ID: %s）", peer.ID)
			log.Infof("保存/更新节点失败: %v", err)
			return err
		}
	*/
	// 2. 更新最后活跃时间（不变）
	peer.LastSeen = time.Now().Unix()

	// 3. 原有序列化与保存逻辑（不变）
	protoPeer := peer.ToProto()
	data, err := proto.Marshal(protoPeer)
	if err != nil {
		err = fmt.Errorf("序列化节点 [%s] 失败: %w", peer.ID, err)
		log.Infof("保存/更新节点失败: %v", err)
		return err
	}
	key := db.PersistentPeerBucket.Key([]byte(peer.ID))
	if err := n.db.Update(func(batch db.IndexedBatch) error {
		return batch.Put(key, data)
	}); err != nil {
		err = fmt.Errorf("数据库事务执行失败: %w", err)
		log.Infof("保存/更新节点失败: %v", err)
		return err
	}

	// 关键修改：主动更新缓存
	n.updateCache(peer)

	// --------------------------
	// 新增：检查总节点数，超过100则清理
	// --------------------------
	if err := n.pruneExcessPeers(); err != nil {
		log.Infof("清理超额节点失败: %v", err)
		// 清理失败不阻断当前保存，但需打日志
	}

	// 4. 原有日志（不变）
	log.Infof("成功保存或更新节点持久化信息（节点ID: %s，地址数: %d）", peer.ID, len(peer.Addrs))
	return nil
}

// 新增：清理超额节点（保留前100个最有价值的节点）
func (n *networkLayer) pruneExcessPeers() error {
	// 1. 加载所有节点
	allPeers, err := n.loadPersistentPeers() // 这里会优先读缓存
	if err != nil {
		return fmt.Errorf("加载所有节点失败: %w", err)
	}

	// 2. 若未超过限制，直接返回
	if len(allPeers) <= MaxPersistentPeers {
		return nil
	}

	// 3. 筛选需要保留的节点
	filteredPeers := filterTopNPeers(allPeers, MaxPersistentPeers)

	// 4. 批量更新数据库
	err = n.db.Update(func(batch db.IndexedBatch) error {
		if err := n.clearAllPersistentPeers(batch); err != nil {
			return fmt.Errorf("清空旧节点失败: %w", err)
		}

		for _, p := range filteredPeers {
			protoPeer := p.ToProto()
			data, err := proto.Marshal(protoPeer)
			if err != nil {
				return fmt.Errorf("序列化节点 %s 失败: %w", p.ID, err)
			}
			key := db.PersistentPeerBucket.Key([]byte(p.ID))
			if err := batch.Put(key, data); err != nil {
				return fmt.Errorf("保存节点 %s 失败: %w", p.ID, err)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 关键修改：批量更新缓存
	n.replaceCache(filteredPeers)

	log.Infof("清理超额节点：原始=%d，保留=%d", len(allPeers), len(filteredPeers))
	return nil
}

// --------------------------
// 工具函数：节点筛选与排序
// --------------------------

// deduplicatePeers 按节点ID去重（保留最后出现的节点，即LastSeen更新的）
func deduplicatePeers(peers []PersistentPeer) []PersistentPeer {
	peerMap := make(map[string]PersistentPeer, len(peers))
	for _, p := range peers {
		// 若已存在该节点，保留LastSeen更新的版本
		if existing, ok := peerMap[p.ID]; ok {
			if p.LastSeen > existing.LastSeen {
				peerMap[p.ID] = p
			}
		} else {
			peerMap[p.ID] = p
		}
	}
	// 转换回切片
	deduped := make([]PersistentPeer, 0, len(peerMap))
	for _, p := range peerMap {
		deduped = append(deduped, p)
	}
	return deduped
}

// sortPeersByValue 按节点价值排序（优先保留最近活跃的节点）
func sortPeersByValue(peers []PersistentPeer) []PersistentPeer {
	// 按 LastSeen 降序排序（最新活跃的在前）
	sort.Slice(peers, func(i, j int) bool {
		// 扩展点：可叠加其他维度（如 IsTrusted 优先、RTT 越小越优先）
		if peers[i].IsTrusted != peers[j].IsTrusted {
			return peers[i].IsTrusted // 可信节点优先
		}
		return peers[i].LastSeen > peers[j].LastSeen // 最近活跃优先
	})
	return peers
}

// filterTopNPeers 筛选前 N 个最有价值的节点（去重→排序→截取）
func filterTopNPeers(peers []PersistentPeer, n int) []PersistentPeer {
	if len(peers) <= 0 {
		return nil
	}
	// 1. 去重（避免同一节点因地址变化重复保存）
	deduped := deduplicatePeers(peers)
	if len(deduped) <= n {
		return deduped
	}
	// 2. 按价值排序
	sorted := sortPeersByValue(deduped)
	// 3. 截取前 N 个
	return sorted[:n]
}

// GetAllPersistentPeer 实现 NetworkLayer 接口，获取所有持久化节点（最多保留 MaxPersistentPeers 个）
// 返回经过去重、排序（按价值）后的有效节点列表，若加载失败返回错误
func (n *networkLayer) GetAllPersistentPeer() ([]PersistentPeer, error) {
	// 直接复用 loadPersistentPeers 方法：该方法已实现
	// 1. 从数据库读取所有持久化节点（Protobuf 反序列化）
	// 2. 节点去重（按 ID 去重，保留最新活跃版本）
	// 3. 按价值排序（可信节点优先、最近活跃优先）
	// 4. 数量控制（最多保留 MaxPersistentPeers 个）
	peers, err := n.loadPersistentPeers()
	if err != nil {
		// 记录加载失败日志，便于问题排查
		log.Infof("获取所有持久化节点失败: %v", err)
		return nil, fmt.Errorf("加载持久化节点数据异常: %w", err)
	}
	// 日志输出加载结果，便于监控节点数量
	log.Infof("成功获取持久化节点 %d 个（最多保留 %d 个）", len(peers), MaxPersistentPeers)
	return peers, nil
}

// 1. 标记节点为已成功握手（内部使用，握手响应验证通过后调用）
func (n *networkLayer) MarkPeerHandshaked(peerID string) {
	n.handshakedPeers.Store(peerID, struct{}{})
}

// 2. 判断节点是否已成功握手（公开方法，实现内部检查与外部查询）
func (n *networkLayer) IsPeerHandshaked(peerID string) bool {
	_, exists := n.handshakedPeers.Load(peerID)
	return exists
}

// IsOnline 判断指定节点是否在线（处于连接状态）
func (n *networkLayer) IsOnline(peerID string) bool {
	// 1. 检查网络层是否处于运行状态
	if !n.running {
		return false
	}

	// 2. 解析节点ID（字符串形式转换为libp2p的peer.ID类型）
	pid, err := peer.Decode(peerID)
	if err != nil {
		// 节点ID无效，视为不在线
		return false
	}

	// 3. 检查节点连接状态
	// libp2p的Connectedness返回当前连接状态，network.Connected表示已建立连接
	return n.host.Network().Connectedness(pid) == network.Connected
}

// 新增：清理过期的 probeCache 条目
func (n *networkLayer) cleanupExpiredProbeCache() {
	var cleanedCount int
	// 遍历 sync.Map：Range 方法会迭代所有键值对
	probeCache.Range(func(key, value interface{}) bool {
		entry := value.(probeCacheEntry)
		// 判断是否过期
		if time.Since(entry.Timestamp) >= probeCacheExpiry {
			probeCache.Delete(key) // 删除过期条目
			cleanedCount++
		}
		return true // 返回 true 继续迭代
	})

	// 可选：输出清理日志，便于监控
	if cleanedCount > 0 {
		log.Infof("[probeCache] 清理过期条目 %d 个", cleanedCount)
	}
}

func (n *networkLayer) GetChain() *blockchain.BlockChain {
	return n.chain
}

func (n *networkLayer) GetPeerByCondition(target PersistentPeer) ([]PersistentPeer, error) {
	var result []PersistentPeer
	// 1. 获取所有已连接且已握手的节点ID
	peers, err := n.loadPersistentPeers()
	if err != nil {
		log.Infof("获取所有持久化节点失败: %v", err)
		return nil, fmt.Errorf("加载持久化节点数据异常: %w", err)
	}

	//connectedPeers := n.ConnectedPeers()
	for _, peerInfo := range peers {
		// 2. 查询节点的持久化信息
		peer, err := n.QueryPersistentPeer(peerInfo.ID)
		if err != nil {
			log.Infof("查询节点 %s 信息失败: %v", peerInfo.ID, err)
			continue
		}
		// 3. 检查所有非空条件
		match := true
		// 检查节点ID
		if target.ID != "" && peer.ID != target.ID {
			match = false
		}
		// 检查地址列表（只要有一个地址匹配即可）
		if len(target.Addrs) > 0 && match {
			hasMatchingAddr := false
			peerAddrSet := make(map[string]struct{})
			for _, addr := range peer.Addrs {
				peerAddrSet[addr] = struct{}{}
			}
			for _, targetAddr := range target.Addrs {
				if _, exists := peerAddrSet[targetAddr]; exists {
					hasMatchingAddr = true
					break
				}
			}
			if !hasMatchingAddr {
				match = false
			}
		}
		// 检查最后活跃时间（大于等于目标时间）
		if target.LastSeen > 0 && match && peer.LastSeen < target.LastSeen {
			match = false
		}
		// 检查连接方向
		if target.Direction != -1 && target.Direction != 0 && match && peer.Direction != target.Direction {
			match = false
		}
		// 检查连接建立时间（大于等于目标时间）
		if target.ConnTime > 0 && match && peer.ConnTime < target.ConnTime {
			match = false
		}
		// 检查协议版本
		if target.ProtocolVersion > 0 && match && peer.ProtocolVersion != target.ProtocolVersion {
			match = false
		}
		// 检查服务能力（包含目标节点的所有服务能力）
		if len(target.Services) > 0 && match {
			hasAllServices := true
			for _, targetService := range target.Services {
				found := false
				for _, peerService := range peer.Services {
					if targetService == peerService {
						found = true
						break
					}
				}
				if !found {
					hasAllServices = false
					break
				}
			}
			if !hasAllServices {
				match = false
			}
		}
		// 检查支持的消息类型（包含目标节点的所有消息类型）
		if len(target.SupportedMsgs) > 0 && match {
			hasAllMsgs := true
			peerMsgSet := make(map[string]struct{})
			for _, msg := range peer.SupportedMsgs {
				peerMsgSet[msg] = struct{}{}
			}

			for _, targetMsg := range target.SupportedMsgs {
				if _, exists := peerMsgSet[targetMsg]; !exists {
					hasAllMsgs = false
					break
				}
			}
			if !hasAllMsgs {
				match = false
			}
		}
		// 检查往返延迟（小于等于目标延迟）
		if target.RTT > 0 && match && peer.RTT > target.RTT {
			match = false
		}
		// 检查封禁状态（如果目标指定未封禁）
		if target.BanUntil == -1 && match && peer.BanUntil > time.Now().Unix() {
			match = false
		}
		// 检查是否为可信节点
		if target.IsTrusted && match && !peer.IsTrusted {
			match = false
		}
		if n.IsPeerHandshaked(peerInfo.ID) {
			peer.HandshakeStatus = wire.HandshakeStatus_HANDSHAKE_COMPLETED
		}
		if target.HandshakeStatus != -1 && target.HandshakeStatus != 0 && match && peer.HandshakeStatus != target.HandshakeStatus {
			match = false
		}
		if n.IsOnline(peerInfo.ID) {
			peer.IsOnline = true
		}

		if target.IsOnline && match && !peer.IsOnline {
			match = false
		}

		// 如果所有条件都匹配，则加入结果列表
		if match {
			result = append(result, peer)
		}
	}
	return result, nil
}

// Ban 封禁一个节点，默认封禁24小时
func (n *networkLayer) Ban(peerID string) error {
	if peerID == n.SelfID() {
		return errors.New("不能封禁自身节点")
	}

	// 1. 获取节点信息
	peer, err := n.QueryPersistentPeer(peerID)
	if err != nil {
		return fmt.Errorf("节点 %s 不存在: %w", peerID, err)
	}

	// 2. 设置封禁信息（24小时后解封）
	now := time.Now().Unix()
	peer.BanUntil = now + 24*3600 // 24小时
	peer.BanScore = 100           // 封禁分数设为最高
	peer.LastErr = "节点被手动封禁"

	// 3. 断开连接
	if err := n.Disconnect(peerID); err != nil {
		log.Infof("断开被封禁节点 %s 连接失败: %v", peerID, err)
	}

	// 4. 保存更新
	return n.SaveOrUpdatePersistentPeer(peer)
}

// Unban 解封一个节点
func (n *networkLayer) Unban(peerID string) error {
	// 1. 获取节点信息
	peer, err := n.QueryPersistentPeer(peerID)
	if err != nil {
		return fmt.Errorf("节点 %s 不存在: %w", peerID, err)
	}

	// 2. 清除封禁状态
	peer.BanUntil = -1 // -1表示未封禁
	peer.BanScore = 0  // 重置分数
	peer.LastErr = ""  // 清除错误信息

	// 3. 保存更新
	return n.SaveOrUpdatePersistentPeer(peer)
}

// AdjustPeerScore 调整节点分数，正数加分，负数扣分
// 当分数超过100时会自动封禁节点
func (n *networkLayer) AdjustPeerScore(peerID string, score int) error {
	if score == 0 {
		return errors.New("调整分数不能为0")
	}

	// 1. 获取节点信息
	peer, err := n.QueryPersistentPeer(peerID)
	if err != nil {
		return fmt.Errorf("节点 %s 不存在: %w", peerID, err)
	}

	// 2. 调整分数（确保不小于0）
	newScore := int(peer.BanScore) + score
	if newScore < 0 {
		newScore = 0
	}
	peer.BanScore = uint32(newScore)

	// 3. 如果分数超过阈值，自动封禁
	if newScore >= 100 && peer.BanUntil <= time.Now().Unix() {
		peer.BanUntil = time.Now().Unix() + 24*3600 // 封禁24小时
		peer.LastErr = fmt.Sprintf("分数超过阈值自动封禁，当前分数: %d", newScore)

		// 断开连接
		if err := n.Disconnect(peerID); err != nil {
			log.Infof("自动封禁时断开节点 %s 连接失败: %v", peerID, err)
		}
	}

	// 4. 保存更新
	return n.SaveOrUpdatePersistentPeer(peer)
}

// GetAllPeer 获取所有持久化节点（无论是否在线、是否握手，只要已持久化存储）
func (n *networkLayer) GetAllPeer() ([]PersistentPeer, error) {
	// 直接复用loadPersistentPeers方法，该方法从数据库加载所有持久化节点
	// 包括反序列化、去重和数量控制（最多保留MaxPersistentPeers个）
	peers, err := n.loadPersistentPeers()
	if err != nil {
		log.Infof("获取所有持久化节点失败: %v", err)
		return nil, fmt.Errorf("加载持久化节点数据异常: %w", err)
	}

	// 日志输出获取结果，便于监控
	log.Infof("成功获取所有持久化节点 %d 个（包含未在线和未握手节点）", len(peers))
	return peers, nil
}

// 新增：与指定节点进行握手
func (n *networkLayer) handshakeWithPeer(peerID string) error {
	// 检查是否正在握手，如果是则等待
	if _, exists := handshakeInProgress.LoadOrStore(peerID, struct{}{}); exists {
		// 等待已有的握手完成
		ctxWait, cancelWait := context.WithTimeout(n.ctx, 5*time.Second)
		defer cancelWait()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if !n.IsHandshaking(peerID) {
				break
			}
			select {
			case <-ticker.C:
				// 继续等待
			case <-ctxWait.Done():
				return fmt.Errorf("等待节点[%s]握手超时: %w", peerID, ctxWait.Err())
			case <-n.ctx.Done():
				return n.ctx.Err()
			}
		}

		// 检查是否已经握手成功
		if n.IsPeerHandshaked(peerID) {
			return nil
		}
	}
	defer handshakeInProgress.Delete(peerID) // 确保最终清理

	// 1. 检查节点是否已连接
	if !n.IsOnline(peerID) {
		return fmt.Errorf("节点 %s 未连接，无法进行握手", peerID)
	}

	// 2. 检查是否已完成握手，避免重复握手
	if n.IsPeerHandshaked(peerID) {
		log.Infof("节点 %s 已完成握手，无需重复操作", peerID)
		return nil
	}

	height, _ := n.chain.GetMainLatestHeight()
	latestHash, _ := n.chain.GetMainLatestHash()
	n.config.Handshake.LastBlockHeight = height
	n.config.Handshake.LatestHash = latestHash[:]

	// 4. 序列化握手请求
	reqData, err := proto.Marshal(n.config.Handshake)
	if err != nil {
		return fmt.Errorf("序列化握手请求失败: %w", err)
	}

	//发送开始时间
	// 记录发送开始时间
	startTime := time.Now()
	// 5. 发送握手请求（使用握手专用协议）
	respData, err := n.Send(peerID, HandshakeProtocol, reqData)
	if err != nil {
		//请握手失败的连接
		// 关键修改：握手请求发送失败，彻底清理连接
		return n.handleHandshakeFailure(peerID, fmt.Errorf("发送握手请求失败: %w", err))
	}
	//发送结束时间
	// 计算RTT（从发送到接收响应的时间）
	rtt := time.Since(startTime)
	rttMs := rtt.Milliseconds()
	log.Infof("节点 %s 握手请求往返时间: %d 毫秒", peerID, rttMs)

	// 6. 处理握手响应（验证对方是否接受握手）
	var handshakeResp wire.CommonResp
	if err := proto.Unmarshal(respData, &handshakeResp); err != nil {
		return fmt.Errorf("握手响应失败: %w", err)
	}
	if handshakeResp.Code != 200 {
		return fmt.Errorf("握手失败: %w", err)
	}
	var handshakeAck wire.ProtoHandshake
	if err := proto.Unmarshal(handshakeResp.Data, &handshakeAck); err != nil {
		return fmt.Errorf("握手响应ACK解析失败: %w", err)
	}
	hash, _ := chainhash.BytesToHash(handshakeAck.LatestHash)
	go func() {
		//根据ACK更新或者新增节点信息
		// 3.1 获取当前连接的节点详细信息（含地址、服务类型等）
		connectedPeer, err := n.GetConnectedPeerById(peerID)
		if err != nil {
			log.Errorf("获取节点 [%s] 连接信息失败: %v", peerID, err)
			return
		}

		// 3.2 转换节点地址（multiaddr → 字符串切片，适配持久化结构）
		addrStrs := make([]string, 0, len(connectedPeer.Addrs))
		for _, addr := range connectedPeer.Addrs {
			addrStr := addr.String()
			if addrStr != "" { // 过滤空地址
				addrStrs = append(addrStrs, addrStr)
			}
		}
		/*		if len(addrStrs) == 0 {
				log.Warnf("节点 [%s] 无有效地址，跳过持久化", peerID)
				return
			}*/

		// 3.3 检查节点是否已存在于持久化存储中
		existingPeer, err := n.QueryPersistentPeer(peerID)
		if err != nil {
			// 3.4 节点不存在 → 新增持久化节点
			newCache := lru.NewCache(MaxKnownInventory)

			newPersistentPeer := &PersistentPeer{
				ID:              connectedPeer.ID,
				Addrs:           addrStrs,
				LastSeen:        time.Now().Unix(), // 记录当前活跃时间
				Services:        handshakeAck.Services,
				Direction:       wire.ConnectionDirection_DIR_INBOUND,
				ConnTime:        time.Now().Unix(),
				DisconnTime:     -1,                     // -1 表示未断开
				UserAgent:       handshakeAck.UserAgent, // 若握手Ack无UA，可暂用unknown（建议从Handshake阶段同步）
				ProtocolVersion: 0,                      // 若需版本，可从Handshake阶段存储的临时数据中获取
				BanScore:        0,
				BanUntil:        -1, // 未封禁
				IsTrusted:       false,
				HandshakeStatus: wire.HandshakeStatus_HANDSHAKE_COMPLETED,
				RTT:             uint32(rttMs),

				KnownInventory:     &newCache,
				InvQueue:           make([]*wire.InvVect, 0, MaxInvTrickleSize),
				TrickleTimer:       time.NewTimer(DefaultTrickleInterval),
				PendingRequests:    make(map[string]time.Time),
				LastRecvTime:       time.Now(),
				WitnessEnabled:     true,
				LastAnnouncedBlock: &hash,
				LastBlockHeight:    handshakeAck.LastBlockHeight,
			}

			// 保存新节点到存储
			if err := n.SaveOrUpdatePersistentPeer(*newPersistentPeer); err != nil {
				log.Errorf("新增持久化节点[%s]失败: %v", peerID, err)
			} else {
				log.Infof("握手确认后，成功新增节点[%s]（地址数: %d）", peerID, len(addrStrs))
			}
		} else {
			// 3.5 节点已存在 → 更新节点信息（仅更新动态字段）
			existingPeer.LastSeen = time.Now().Unix() // 刷新最后活跃时间
			existingPeer.Addrs = addrStrs             // 同步最新地址列表
			existingPeer.ConnTime = time.Now().Unix() // 刷新连接时间
			existingPeer.DisconnTime = -1             // 标记为已连接
			existingPeer.Services = handshakeAck.Services
			existingPeer.UserAgent = handshakeAck.UserAgent
			existingPeer.HandshakeStatus = wire.HandshakeStatus_HANDSHAKE_COMPLETED
			existingPeer.RTT = uint32(rttMs)

			existingPeer.LastAnnouncedBlock = &hash
			existingPeer.LastBlockHeight = handshakeAck.LastBlockHeight

			if existingPeer.KnownInventory == nil {
				cache := lru.NewCache(MaxKnownInventory)
				existingPeer.KnownInventory = &cache
			}
			if existingPeer.InvQueue == nil {
				existingPeer.InvQueue = make([]*wire.InvVect, 0, MaxInvTrickleSize)
			}
			// 3. 初始化Trickle定时器（控制Inv批量发送频率）
			if existingPeer.TrickleTimer == nil {
				existingPeer.TrickleTimer = time.NewTimer(DefaultTrickleInterval)
			} else {
				// 若定时器已存在，重置为默认间隔（避免使用旧的超时时间）
				if !existingPeer.TrickleTimer.Stop() {
					<-existingPeer.TrickleTimer.C // 清空可能的未处理事件
				}
				existingPeer.TrickleTimer.Reset(DefaultTrickleInterval)
			}
			// 4. 初始化待响应请求映射（检测请求超时用）
			if existingPeer.PendingRequests == nil {
				existingPeer.PendingRequests = make(map[string]time.Time)
			}

			// 5. 初始化最后收发时间（用于空闲检测）
			if existingPeer.LastRecvTime.IsZero() {
				existingPeer.LastRecvTime = time.Now()
			}
			if existingPeer.LastSendTime.IsZero() {
				existingPeer.LastSendTime = time.Now()
			}

			// 6. 初始化区块链相关运行时字段
			if existingPeer.LastAnnouncedBlock == nil {
				existingPeer.LastAnnouncedBlock = &chainhash.Hash{} // 空哈希初始化
			}
			// 若有其他动态字段（如服务类型、协议版本），可在此补充更新
			// 更新节点到存储
			if err := n.SaveOrUpdatePersistentPeer(existingPeer); err != nil {
				log.Errorf("更新持久化节点[%s]失败: %v", peerID, err)
			} else {
				log.Infof("握手确认后，成功更新节点[%s]（最新地址数: %d）", peerID, len(addrStrs))
			}
		}
		if height < handshakeAck.LastBlockHeight {
			log.Infof("本地节点高度小于握手节点高度 需要同步 区块")
			//发送区块链路标
			localIndex, _ := n.chain.GetSyncIndex()
			localIndex.PeerId = n.SelfID()
			marshal, _ := proto.Marshal(localIndex)
			//将本地路标发送给目标节点就能收到
			go n.Send(peerID, SyncIndexProtocol, marshal)
		} else {
			log.Infof("无需同步.....................................................................")
		}
		// 7. 握手成功，更新节点状态
		n.MarkPeerHandshaked(peerID)
	}()
	return nil
}

// 新增：直接更新缓存中的单个节点
func (n *networkLayer) updateCache(peer PersistentPeer) {
	n.peerCacheMutex.Lock()
	defer n.peerCacheMutex.Unlock()

	// 更新缓存条目
	n.peerCache[peer.ID] = peer
	// 刷新缓存时间
	n.cacheLastUpdated = time.Now()
}

// 新增：从缓存中删除单个节点
func (n *networkLayer) removeFromCache(peerID string) {
	n.peerCacheMutex.Lock()
	defer n.peerCacheMutex.Unlock()

	delete(n.peerCache, peerID)
	n.cacheLastUpdated = time.Now()
}

// 新增：批量替换缓存（用于批量更新场景）
func (n *networkLayer) replaceCache(peers []PersistentPeer) {
	n.peerCacheMutex.Lock()
	defer n.peerCacheMutex.Unlock()

	// 清空旧缓存
	n.peerCache = make(map[string]PersistentPeer, len(peers))
	// 写入新数据
	for _, p := range peers {
		n.peerCache[p.ID] = p
	}
	n.cacheLastUpdated = time.Now()
}

func (n *networkLayer) IsHandshaking(peerID string) bool {
	_, exists := handshakeInProgress.Load(peerID)
	return exists
}

// 新增全局拦截函数
func (n *networkLayer) triggerHandshake(peerID string) {
	// 双重检查：是否已握手或正在握手
	if n.IsPeerHandshaked(peerID) {
		log.Infof("已经握手")
		return
	}
	log.Infof("未握手")
	if _, exists := handshakeInProgress.Load(peerID); exists {
		return
	}

	// 仅允许一个goroutine执行握手
	go func() {
		// 再次检查（防止竞态）
		if n.IsPeerHandshaked(peerID) {
			return
		}
		log.Infof("开始与节点 %s 进行握手", peerID)
		if err := n.handshakeWithPeer(peerID); err != nil {
			log.Infof("与节点 %s 握手失败: %v", peerID, err)
			// 握手失败清理
			if disconnectErr := n.Disconnect(peerID); disconnectErr != nil {
				log.Infof("断开握手失败节点 %s 连接失败: %v", peerID, disconnectErr)
			}
			n.removePersistentPeer(peerID)
		}
	}()
}

// 新增：统一处理握手失败逻辑
func (n *networkLayer) handleHandshakeFailure(peerID string, err error) error {
	log.Infof("与节点 %s 握手失败: %v", peerID, err)

	// 1. 标记握手状态为失败
	peerInfo, _ := n.QueryPersistentPeer(peerID)
	peerInfo.HandshakeStatus = wire.HandshakeStatus_HANDSHAKE_FAILED
	peerInfo.LastErr = err.Error()
	_ = n.SaveOrUpdatePersistentPeer(peerInfo)

	// 2. 彻底断开连接（包括所有流）
	// 关闭所有关联的流
	pid, decodeErr := peer.Decode(peerID)
	if decodeErr != nil {
		log.Infof("无效的节点ID %s，转换失败: %v", peerID, decodeErr)
		return fmt.Errorf("无效节点ID: %w", decodeErr)
	}

	for _, stream := range n.host.Network().ConnsToPeer(pid) {
		_ = stream.Close()
	}
	_ = n.Disconnect(peerID)

	// 3. 从路由表中移除
	if n.dht != nil {
		n.dht.RoutingTable().RemovePeer(pid)
	}

	return err
}

// 更新节点的最新高度
func (p *PersistentPeer) UpdateLastBlockHeight(newHeight int32) {
	p.statsMtx.Lock()
	if newHeight <= p.LastBlockHeight {
		p.statsMtx.Unlock()
		return
	}
	log.Tracef("Updating last block height of peer %v from %v to %v",
		p.ID, p.LastBlockHeight, newHeight)
	p.LastBlockHeight = newHeight
	p.statsMtx.Unlock()
}

// 这个 UpdateLastAnnouncedBlock 方法的核心作用是 记录并更新 “某个对等节点（Peer）最近向本地节点宣布（广播）的区块哈希”，
// 是区块链节点在区块同步过程中用于追踪对等节点状态的关键工具。
func (p *PersistentPeer) UpdateLastAnnouncedBlock(blkHash *chainhash.Hash) {
	log.Tracef("Updating last blk for peer %v, %v", p.ID, blkHash)
	p.statsMtx.Lock()
	p.LastAnnouncedBlock = blkHash
	p.statsMtx.Unlock()
}

// AddKnownInventory  记录已向该节点发送的 Inv（避免重复）
func (p *PersistentPeer) AddKnownInventory(invVect *wire.InvVect) {
	p.KnownInventory.Add(invVect)
}

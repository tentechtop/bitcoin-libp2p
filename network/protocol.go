package network

import "github.com/libp2p/go-libp2p/core/protocol"

// 协议常量定义（统一管理所有协议ID）
const (
	// 协议前缀（可从配置中读取，这里先定义为变量，后续结合配置初始化）
	ProtocolPrefix = "/blockchain"
	// 区块协议：完整格式为 "前缀/模块/版本"
	BlockProtocol = protocol.ID(ProtocolPrefix + "/block/1.0.0")

	// 交易协议
	TxProtocol = protocol.ID(ProtocolPrefix + "/tx/1.0.0")
	// 握手协议
	HandshakeProtocol = protocol.ID(ProtocolPrefix + "/handshake/1.0.0")
	//握手确认协议
	HandshakeAckProtocol = protocol.ID(ProtocolPrefix + "/handshakeack/1.0.0")
	//RTT
	RTTPProtocol = protocol.ID(ProtocolPrefix + "/rttp/1.0.0")
	//inv消息
	InventoryProtocol = protocol.ID(ProtocolPrefix + "/inventory/1.0.0")
	//携带了数据的inv消息
	RelayProtocol   = protocol.ID(ProtocolPrefix + "/relay/1.0.0")
	GetDataProtocol = protocol.ID(ProtocolPrefix + "/getdata/1.0.0")
	DataReqProtocol = protocol.ID(ProtocolPrefix + "/datareq/1.0.0")

	SyncIndexProtocol           = protocol.ID(ProtocolPrefix + "/syncindex/1.0.0")
	PeerSyncIndexProtocol       = protocol.ID(ProtocolPrefix + "/getpeersyncindex/1.0.0")
	GetPeerLatestHeightProtocol = protocol.ID(ProtocolPrefix + "/getpeerlatestheight/1.0.0")
	GetHeadersProtocol          = protocol.ID(ProtocolPrefix + "/getheaders/1.0.0")
	GetBodyProtocol             = protocol.ID(ProtocolPrefix + "/getbodys/1.0.0")
)

// ServiceFlag identifies services supported by a bitcoin peer.
type ServiceFlag uint64

const (
	//表示该节点是一个「全节点」（full node）。全节点会存储完整的区块链副本，验证所有交易和区块的合法性，是区块链网络的核心基础设施。
	SFNodeNetwork ServiceFlag = 1 << iota

	//表示节点支持 getutxos 和 utxos 命令，对应 BIP0064 协议。这些命令用于查询未花费交易输出（UTXO）集合，帮助其他节点快速获取特定地址的可用资金信息。
	SFNodeGetUTXO

	//表示节点支持「布隆过滤」（bloom filtering）功能。布隆过滤器是轻量级节点（如 SPV 节点）常用的技术，可高效筛选出与自身相关的交易，减少不必要的数据传输（例如只同步涉及自己地址的交易）。
	SFNodeBloom

	//表示节点支持包含「见证数据」（witness data）的区块和交易，对应 BIP0144 协议（隔离见证，Segregated Witness）。隔离见证将交易的签名数据（见证）与交易核心数据分离，提升了交易容量和安全性，该标志说明节点可处理这类新型交易和区块。
	SFNodeWitness

	//表示节点支持「xthin blocks」（精简区块）。这是一种区块传播优化技术，类似于「紧凑区块」（compact blocks），通过只传输区块中必要的差异数据（而非完整区块），减少网络带宽消耗，加快区块同步速度。
	SFNodeXthin

	//占位标志，用于表示第 5 位定义的服务。具体功能未在注释中说明，可能是预留位或特定实现中自定义的扩展功能。
	SFNodeBit5

	//表示节点支持「承诺过滤器」（committed filters，CFs），对应 BIP157 和 BIP158 协议。承诺过滤器是一种带密码学承诺的区块过滤机制，帮助轻节点快速定位包含目标交易的区块，同时保证过滤结果的真实性
	SFNodeCF

	//表示节点运行「Segwit2X」软件。Segwit2X 是 2017 年的一个比特币协议提案，计划结合隔离见证（Segwit）和区块大小扩容至 2MB，该标志用于识别支持该提案的节点（注：该提案最终未被广泛采用）。
	SFNode2X

	//表示节点支持仅提供「最近 288 个区块」的数据（约 1 天的区块量，按 10 分钟一个区块计算）。这是一种轻量版全节点，不存储完整区块链历史，仅保留近期数据，适合资源有限的设备。
	SFNodeNetworkLimited = 1 << 10

	//表示节点支持 BIP324 定义的「P2P 协议 v2」。该版本协议引入了加密通信、更高效的握手机制等改进，提升了节点间通信的安全性和兼容性。
	SFNodeP2PV2 = 1 << 11
)

package wire

//协议层面（持久、跨实现、跨语言）
//必须保持 12 字节 ASCII 字符串（"tx"），否则无法与现有节点互通。
//→ 所以 Command() string 仍然返回 "tx"。
//传输优化层面（BIP-324 v2）
//一旦完成握手，v2 transport 会把 "tx" 映射成 1 字节 ID 0x15，节省 11 字节。
//→ 这是 框架内部自动完成 的，应用层无感知。

const MessageHeaderSize = 24

const CommandSize = 12

const MaxMessagePayload = (1024 * 1024 * 32) // 32MB

const (
	CmdVersion      = "version"
	CmdVerAck       = "verack"
	CmdGetAddr      = "getaddr"
	CmdAddr         = "addr"
	CmdAddrV2       = "addrv2"
	CmdGetBlocks    = "getblocks"
	CmdInv          = "inv"
	CmdGetData      = "getdata"
	CmdNotFound     = "notfound"
	CmdBlock        = "block"
	CmdTx           = "tx"
	CmdGetHeaders   = "getheaders"
	CmdHeaders      = "headers"
	CmdPing         = "ping"
	CmdPong         = "pong"
	CmdMemPool      = "mempool"
	CmdFilterAdd    = "filteradd"
	CmdFilterClear  = "filterclear"
	CmdFilterLoad   = "filterload"
	CmdMerkleBlock  = "merkleblock"
	CmdReject       = "reject"
	CmdSendHeaders  = "sendheaders"
	CmdFeeFilter    = "feefilter"
	CmdGetCFilters  = "getcfilters"
	CmdGetCFHeaders = "getcfheaders"
	CmdGetCFCheckpt = "getcfcheckpt"
	CmdCFilter      = "cfilter"
	CmdCFHeaders    = "cfheaders"
	CmdCFCheckpt    = "cfcheckpt"
	CmdSendAddrV2   = "sendaddrv2"
	CmdWTxIdRelay   = "wtxidrelay"
)

var (
	v2MessageIDs = map[uint8]string{
		1:  CmdAddr,
		2:  CmdBlock,
		5:  CmdFeeFilter,
		6:  CmdFilterAdd,
		7:  CmdFilterClear,
		8:  CmdFilterLoad,
		9:  CmdGetBlocks,
		11: CmdGetData,
		12: CmdGetHeaders,
		13: CmdHeaders,
		14: CmdInv,
		15: CmdMemPool,
		16: CmdMerkleBlock,
		17: CmdNotFound,
		18: CmdPing,
		19: CmdPong,
		21: CmdTx,
		22: CmdGetCFilters,
		23: CmdCFilter,
		24: CmdGetCFHeaders,
		25: CmdCFHeaders,
		26: CmdGetCFCheckpt,
		27: CmdCFCheckpt,
		28: CmdAddrV2,
	}

	v2Messages = map[string]uint8{
		CmdAddr:         1,
		CmdBlock:        2,
		CmdFeeFilter:    5,
		CmdFilterAdd:    6,
		CmdFilterClear:  7,
		CmdFilterLoad:   8,
		CmdGetBlocks:    9,
		CmdGetData:      11,
		CmdGetHeaders:   12,
		CmdHeaders:      13,
		CmdInv:          14,
		CmdMemPool:      15,
		CmdMerkleBlock:  16,
		CmdNotFound:     17,
		CmdPing:         18,
		CmdPong:         19,
		CmdTx:           21,
		CmdGetCFilters:  22,
		CmdCFilter:      23,
		CmdGetCFHeaders: 24,
		CmdCFHeaders:    25,
		CmdGetCFCheckpt: 26,
		CmdCFCheckpt:    27,
		CmdAddrV2:       28,
	}
)

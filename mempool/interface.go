package mempool

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"time"
)

type TxMempool interface {
	// ProcessTransaction 将验证过的交易添加到交易池 tx：要处理的交易
	//allowOrphan：是否允许把它当孤儿先存起来
	//rateLimit：是否启用速率限制（防 DoS）
	//tag：给交易打标签（本地、RPC、P2P 等）
	//[]*TxDesc：本次真正加入主池的交易（含因该交易而被“转正”的孤儿）
	//error：如果交易被拒绝，返回具体原因（双花、费太低、共识错误…）
	ProcessTransaction(tx *core.Tx, allowOrphan, rateLimit bool, tag Tag) ([]*TxDesc, error)

	RemoveTransaction(tx *core.Tx, removeRedeemers bool)

	CheckMempoolAcceptance(tx *core.Tx) (*MempoolAcceptResult, error)

	CheckSpend(op core.OutPoint) *core.Tx

	//返回交易池最近一次变动（新增或删除交易）的本地时间戳。
	LastUpdated() time.Time

	//一次性把**主池（不含孤儿池）**里所有交易的“档案”全部拿出来。
	TxDescs() []*TxDesc

	//主池当前有多少笔交易（不含孤儿）。
	Count() int

	//按哈希在主池里精确查找一笔交易。
	FetchTransaction(txHash *chainhash.Hash) (*core.Tx, error)

	//判断某笔交易是否已经存在，无论它在主池还是孤儿池。
	HaveTransaction(hash *chainhash.Hash) bool
}

package mempool

import (
	"bitcoin/blockchain"
	"bitcoin/blockchain/indexers"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/mining"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wire"
	"container/list"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultBlockPrioritySize    = 50000
	orphanTTL                   = time.Minute * 15
	orphanExpireScanInterval    = time.Minute * 5
	MaxRBFSequence              = 0xfffffffd
	MaxReplacementEvictions     = 100
	MinStandardTxNonWitnessSize = 65
)

type Tag uint64

type Policy struct {
	// MaxTxVersion is the transaction version that the mempool should
	// accept.  All transactions above this version are rejected as
	// non-standard.
	MaxTxVersion int32

	// DisableRelayPriority defines whether to relay free or low-fee
	// transactions that do not have enough priority to be relayed.
	DisableRelayPriority bool

	// AcceptNonStd defines whether to accept non-standard transactions. If
	// true, non-standard transactions will be accepted into the mempool.
	// Otherwise, all non-standard transactions will be rejected.
	AcceptNonStd bool

	// FreeTxRelayLimit defines the given amount in thousands of bytes
	// per minute that transactions with no fee are rate limited to.
	FreeTxRelayLimit float64

	// MaxOrphanTxs is the maximum number of orphan transactions
	// that can be queued.
	MaxOrphanTxs int

	// MaxOrphanTxSize is the maximum size allowed for orphan transactions.
	// This helps prevent memory exhaustion attacks from sending a lot of
	// of big orphans.
	MaxOrphanTxSize int

	// MaxSigOpCostPerTx is the cumulative maximum cost of all the signature
	// operations in a single transaction we will relay or mine.  It is a
	// fraction of the max signature operations for a block.
	MaxSigOpCostPerTx int

	// MinRelayTxFee defines the minimum transaction fee in BTC/kB to be
	// considered a non-zero fee.
	MinRelayTxFee utils.Amount

	// RejectReplacement, if true, rejects accepting replacement
	// transactions using the Replace-By-Fee (RBF) signaling policy into
	// the mempool.
	RejectReplacement bool
}

type Config struct {
	Policy Policy

	ChainParams *core.Params

	FetchUtxoView func(*core.Tx) (*blockchain.UtxoViewpoint, error)

	BestHeight func() int32

	MedianTimePast func() time.Time

	CalcSequenceLock func(*core.Tx, *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error)

	IsDeploymentActive func(deploymentID uint32) (bool, error)

	SigCache *txscript.SigCache

	HashCache *txscript.HashCache

	FeeEstimator *FeeEstimator

	AddrIndex *indexers.AddrIndex
}

// TxDesc 是一个关于“交易源”中某笔交易的描述符，同时还附带了一些额外的元数据。

type orphanTx struct {
	tx         *core.Tx
	tag        Tag
	expiration time.Time
}

type TxPool struct {
	lastUpdated int64

	mtx           sync.RWMutex
	cfg           Config
	pool          map[chainhash.Hash]*TxDesc
	orphans       map[chainhash.Hash]*orphanTx
	orphansByPrev map[core.OutPoint]map[chainhash.Hash]*core.Tx
	outpoints     map[core.OutPoint]*core.Tx
	pennyTotal    float64
	lastPennyUnix int64

	nextExpireScan time.Time
}

type MempoolAcceptResult struct {
	TxFee  utils.Amount
	TxSize int64

	Conflicts map[chainhash.Hash]*core.Tx

	MissingParents []*chainhash.Hash

	utxoView *blockchain.UtxoViewpoint

	bestHeight int32
}

type TxDesc struct {
	mining.TxDesc
	StartingPriority float64
}

func New(cfg *Config) *TxPool {
	return &TxPool{
		cfg:            *cfg,
		pool:           make(map[chainhash.Hash]*TxDesc),
		orphans:        make(map[chainhash.Hash]*orphanTx),
		orphansByPrev:  make(map[core.OutPoint]map[chainhash.Hash]*core.Tx),
		nextExpireScan: time.Now().Add(orphanExpireScanInterval),
		outpoints:      make(map[core.OutPoint]*core.Tx),
	}
}

func (mp *TxPool) ProcessTransaction(tx *core.Tx, allowOrphan, rateLimit bool, tag Tag) ([]*TxDesc, error) {
	log.Tracef("Processing transaction %v", tx.Hash())

	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	log.Infof("正在处理交易")

	// Potentially accept the transaction to the memory pool.
	missingParents, txD, err := mp.maybeAcceptTransaction(tx, true, rateLimit, true)
	if err != nil {
		log.Infof("交易存在错误")
		return nil, err
	}
	log.Info("基本检查完成")

	if len(missingParents) == 0 {
		// Accept any orphan transactions that depend on this
		// transaction (they may no longer be orphans if all inputs
		// are now available) and repeat for those accepted
		// transactions until there are no more.
		newTxs := mp.processOrphans(tx)
		acceptedTxs := make([]*TxDesc, len(newTxs)+1)

		// Add the parent transaction first so remote nodes
		// do not add orphans.
		acceptedTxs[0] = txD
		copy(acceptedTxs[1:], newTxs)

		return acceptedTxs, nil
	}

	// The transaction is an orphan (has inputs missing).  Reject
	// it if the flag to allow orphans is not set.
	if !allowOrphan {
		// Only use the first missing parent transaction in
		// the error message.
		//
		// NOTE: RejectDuplicate is really not an accurate
		// reject code here, but it matches the reference
		// implementation and there isn't a better choice due
		// to the limited number of reject codes.  Missing
		// inputs is assumed to mean they are already spent
		// which is not really always the case.
		str := fmt.Sprintf("orphan transaction %v references "+
			"outputs of unknown or fully-spent "+
			"transaction %v", tx.Hash(), missingParents[0])
		return nil, txRuleError(wire.RejectDuplicate, str)
	}

	// Potentially add the orphan transaction to the orphan pool.
	err = mp.maybeAddOrphan(tx, tag)
	return nil, err
}

func (mp *TxPool) maybeAddOrphan(tx *core.Tx, tag Tag) error {
	serializedLen := tx.MsgTx().SerializeSize()
	if serializedLen > mp.cfg.Policy.MaxOrphanTxSize {
		str := fmt.Sprintf("orphan transaction size of %d bytes is "+
			"larger than max allowed size of %d bytes",
			serializedLen, mp.cfg.Policy.MaxOrphanTxSize)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// Add the orphan if the none of the above disqualified it.
	mp.addOrphan(tx, tag)
	return nil
}

// addOrphan adds an orphan transaction to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) addOrphan(tx *core.Tx, tag Tag) {
	// Nothing to do if no orphans are allowed.
	if mp.cfg.Policy.MaxOrphanTxs <= 0 {
		return
	}

	// Limit the number orphan transactions to prevent memory exhaustion.
	// This will periodically remove any expired orphans and evict a random
	// orphan if space is still needed.
	mp.limitNumOrphans()

	mp.orphans[*tx.Hash()] = &orphanTx{
		tx:         tx,
		tag:        tag,
		expiration: time.Now().Add(orphanTTL),
	}
	for _, txIn := range tx.MsgTx().TxIn {
		if _, exists := mp.orphansByPrev[txIn.PreviousOutPoint]; !exists {
			mp.orphansByPrev[txIn.PreviousOutPoint] =
				make(map[chainhash.Hash]*core.Tx)
		}
		mp.orphansByPrev[txIn.PreviousOutPoint][*tx.Hash()] = tx
	}

	log.Debugf("Stored orphan transaction %v (total: %d)", tx.Hash(),
		len(mp.orphans))
}

func (mp *TxPool) limitNumOrphans() error {
	// Scan through the orphan pool and remove any expired orphans when it's
	// time.  This is done for efficiency so the scan only happens
	// periodically instead of on every orphan added to the pool.
	if now := time.Now(); now.After(mp.nextExpireScan) {
		origNumOrphans := len(mp.orphans)
		for _, otx := range mp.orphans {
			if now.After(otx.expiration) {
				// Remove redeemers too because the missing
				// parents are very unlikely to ever materialize
				// since the orphan has already been around more
				// than long enough for them to be delivered.
				mp.removeOrphan(otx.tx, true)
			}
		}

		// Set next expiration scan to occur after the scan interval.
		mp.nextExpireScan = now.Add(orphanExpireScanInterval)

		numOrphans := len(mp.orphans)
		if numExpired := origNumOrphans - numOrphans; numExpired > 0 {
			log.Debugf("Expired %d %s (remaining: %d)", numExpired,
				pickNoun(numExpired, "orphan", "orphans"),
				numOrphans)
		}
	}

	// Nothing to do if adding another orphan will not cause the pool to
	// exceed the limit.
	if len(mp.orphans)+1 <= mp.cfg.Policy.MaxOrphanTxs {
		return nil
	}

	// Remove a random entry from the map.  For most compilers, Go's
	// range statement iterates starting at a random item although
	// that is not 100% guaranteed by the spec.  The iteration order
	// is not important here because an adversary would have to be
	// able to pull off preimage attacks on the hashing function in
	// order to target eviction of specific entries anyways.
	for _, otx := range mp.orphans {
		// Don't remove redeemers in the case of a random eviction since
		// it is quite possible it might be needed again shortly.
		mp.removeOrphan(otx.tx, false)
		break
	}

	return nil
}

func (mp *TxPool) removeOrphan(tx *core.Tx, removeRedeemers bool) {
	// Nothing to do if passed tx is not an orphan.
	txHash := tx.Hash()
	otx, exists := mp.orphans[*txHash]
	if !exists {
		return
	}

	// Remove the reference from the previous orphan index.
	for _, txIn := range otx.tx.MsgTx().TxIn {
		orphans, exists := mp.orphansByPrev[txIn.PreviousOutPoint]
		if exists {
			delete(orphans, *txHash)

			// Remove the map entry altogether if there are no
			// longer any orphans which depend on it.
			if len(orphans) == 0 {
				delete(mp.orphansByPrev, txIn.PreviousOutPoint)
			}
		}
	}

	// Remove any orphans that redeem outputs from this one if requested.
	if removeRedeemers {
		prevOut := core.OutPoint{Hash: *txHash}
		for txOutIdx := range tx.MsgTx().TxOut {
			prevOut.Index = uint32(txOutIdx)
			for _, orphan := range mp.orphansByPrev[prevOut] {
				mp.removeOrphan(orphan, true)
			}
		}
	}

	// Remove the transaction from the orphan pool.
	delete(mp.orphans, *txHash)
}

func (mp *TxPool) Count() int {
	mp.mtx.RLock()
	count := len(mp.pool)
	mp.mtx.RUnlock()
	return count
}

func (mp *TxPool) FetchTransaction(txHash *chainhash.Hash) (*core.Tx, error) {
	// Protect concurrent access.
	mp.mtx.RLock()
	txDesc, exists := mp.pool[*txHash]
	mp.mtx.RUnlock()
	if exists {
		return txDesc.Tx, nil
	}
	return nil, fmt.Errorf("transaction is not in the pool")
}

func (mp *TxPool) RemoveTransaction(tx *core.Tx, removeRedeemers bool) {
	// Protect concurrent access.
	mp.mtx.Lock()
	mp.removeTransaction(tx, removeRedeemers)
	mp.mtx.Unlock()
}

func (mp *TxPool) CheckMempoolAcceptance(tx *core.Tx) (
	*MempoolAcceptResult, error) {

	return nil, nil
}

func (mp *TxPool) CheckSpend(op core.OutPoint) *core.Tx {
	mp.mtx.RLock()
	txR := mp.outpoints[op]
	mp.mtx.RUnlock()
	return txR
}

func (mp *TxPool) HaveTransaction(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	haveTx := mp.haveTransaction(hash)
	mp.mtx.RUnlock()

	return haveTx
}

func (mp *TxPool) haveTransaction(hash *chainhash.Hash) bool {
	return mp.isTransactionInPool(hash) || mp.isOrphanInPool(hash)
}

func (mp *TxPool) isTransactionInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.pool[*hash]; exists {
		return true
	}

	return false
}

func (mp *TxPool) isOrphanInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.orphans[*hash]; exists {
		return true
	}

	return false
}

func (mp *TxPool) TxDescs() []*TxDesc {
	mp.mtx.RLock()
	descs := make([]*TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = desc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

func (mp *TxPool) LastUpdated() time.Time {
	return time.Unix(atomic.LoadInt64(&mp.lastUpdated), 0)
}

func (mp *TxPool) MiningDescs() []*mining.TxDesc {
	mp.mtx.RLock()
	descs := make([]*mining.TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = &desc.TxDesc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

func (mp *TxPool) removeTransaction(tx *core.Tx, removeRedeemers bool) {
	txHash := tx.Hash()
	if removeRedeemers {
		// Remove any transactions which rely on this one.
		for i := uint32(0); i < uint32(len(tx.MsgTx().TxOut)); i++ {
			prevOut := core.OutPoint{Hash: *txHash, Index: i}
			if txRedeemer, exists := mp.outpoints[prevOut]; exists {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}
	if txDesc, exists := mp.pool[*txHash]; exists {
		if mp.cfg.AddrIndex != nil {
			mp.cfg.AddrIndex.RemoveUnconfirmedTx(txHash)
		}
		for _, txIn := range txDesc.Tx.MsgTx().TxIn {
			delete(mp.outpoints, txIn.PreviousOutPoint)
		}
		delete(mp.pool, *txHash)
		atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
	}
}

func (mp *TxPool) maybeAcceptTransaction(tx *core.Tx, isNew, rateLimit, rejectDupOrphans bool) ([]*chainhash.Hash, *TxDesc, error) {
	txHash := tx.Hash()
	r, err := mp.checkMempoolAcceptance(
		tx, isNew, rateLimit, rejectDupOrphans,
	)
	if err != nil {
		return nil, nil, err
	}
	if len(r.MissingParents) > 0 {
		return r.MissingParents, nil, nil
	}
	for _, conflict := range r.Conflicts {
		log.Debugf("Replacing transaction %v (fee_rate=%v sat/kb) "+
			"with %v (fee_rate=%v sat/kb)\n", conflict.Hash(),
			mp.pool[*conflict.Hash()].FeePerKB, tx.Hash(),
			int64(r.TxFee)*1000/r.TxSize)

		// The conflict set should already include the descendants for
		// each one, so we don't need to remove the redeemers within
		// this call as they'll be removed eventually.
		mp.removeTransaction(conflict, false)
	}
	txD := mp.addTransaction(r.utxoView, tx, r.bestHeight, int64(r.TxFee))

	log.Debugf("Accepted transaction %v (pool size: %v)", txHash,
		len(mp.pool))

	return nil, txD, nil
}

func (mp *TxPool) checkMempoolAcceptance(tx *core.Tx, isNew, rateLimit, rejectDupOrphans bool) (*MempoolAcceptResult, error) {
	txHash := tx.Hash()
	if mp.isTransactionInPool(txHash) || (rejectDupOrphans && mp.isOrphanInPool(txHash)) {
		str := fmt.Sprintf("already have transaction in mempool %v", txHash)
		return nil, txRuleError(wire.RejectDuplicate, str)
	}
	if tx.MsgTx().SerializeSizeStripped() < MinStandardTxNonWitnessSize {
		str := fmt.Sprintf("tx %v is too small", txHash)
		return nil, txRuleError(wire.RejectNonstandard, str)
	}
	err := blockchain.CheckTransactionSanity(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}
	if blockchain.IsCoinBase(tx) {
		str := fmt.Sprintf("transaction is an individual coinbase %v",
			txHash)
		return nil, txRuleError(wire.RejectInvalid, str)
	}
	bestHeight := mp.cfg.BestHeight()
	nextBlockHeight := bestHeight + 1
	medianTimePast := mp.cfg.MedianTimePast()
	isReplacement, err := mp.checkPoolDoubleSpend(tx)
	if err != nil {
		return nil, err
	}
	utxoView, err := mp.fetchInputUtxos(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}

	//这段代码的作用是检查当前交易是否已存在于主链中且仍有未花费的输出，如果存在则拒绝该交易（防止重复处理已上链的交易）。
	//具体逻辑拆解：
	//构建输出引用（OutPoint）
	//定义 prevOut 为一个交易输出引用结构，其哈希（Hash）设为当前交易的哈希（txHash），用于定位当前交易在区块链中的输出。
	//遍历交易的所有输出
	//循环检查当前交易的每一个输出（TxOut），通过设置 prevOut.Index 为当前输出的索引，精准定位到该交易的每一个具体输出。
	//检查主链 UTXO 中是否存在未花费的对应输出
	//通过 utxoView.LookupEntry(prevOut) 从主链的 UTXO 视图中查询该输出：
	//如果查询到该输出（entry != nil）且该输出未被花费（!entry.IsSpent()），说明该交易已经存在于主链中（因为主链 UTXO 中仍保留其未花费的输出），此时返回 RejectDuplicate 错误，拒绝处理该交易（避免重复添加或处理已上链的交易）。
	//移除 UTXO 视图中的条目
	//无论是否查询到条目，都调用 utxoView.RemoveEntry(prevOut) 从当前 UTXO 视图中移除该输出引用，可能是为了清理临时状态或避免后续处理中的干扰。
	//核心目的：
	//防止重复处理已存在于主链上的交易。如果一个交易已经被打包进区块链（主链）且仍有未花费的输出，说明它是有效的链上交易，不应再被添加到交易池或重新处理，因此通过此检查拒绝该交易。
	prevOut := core.OutPoint{Hash: *txHash}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)
		entry := utxoView.LookupEntry(prevOut)
		if entry != nil && !entry.IsSpent() {
			return nil, txRuleError(wire.RejectDuplicate,
				"transaction already exists in blockchain")
		}
		utxoView.RemoveEntry(prevOut)
	}

	//这段代码的作用是判断当前交易是否为 “孤儿交易（orphan transaction）”，并收集其所有缺失的父交易哈希。
	var missingParents []*chainhash.Hash
	for outpoint, entry := range utxoView.Entries() {
		if entry == nil || entry.IsSpent() {
			hashCopy := outpoint.Hash
			missingParents = append(missingParents, &hashCopy)
		}
	}

	if len(missingParents) > 0 {
		log.Debugf("Tx %v is an orphan with missing parents: %v",
			txHash, missingParents)
		return &MempoolAcceptResult{
			MissingParents: missingParents,
		}, nil
	}

	txFee, err := blockchain.CheckTransactionInputs(
		tx, nextBlockHeight, utxoView, mp.cfg.ChainParams,
	)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}
	err = mp.validateStandardness(
		tx, nextBlockHeight, medianTimePast, utxoView,
	)
	if err != nil {
		return nil, err
	}

	//
	/*	sequenceLock, err := mp.cfg.CalcSequenceLock(tx, utxoView)
		if err != nil {
			if cerr, ok := err.(blockchain.RuleError); ok {
				return nil, chainRuleError(cerr)
			}

			return nil, err
		}
		if !blockchain.SequenceLockActive(sequenceLock, nextBlockHeight, medianTimePast) {
			return nil, txRuleError(wire.RejectNonstandard,
				"transaction's sequence locks on inputs not met")
		}*/

	if err := mp.validateSigCost(tx, utxoView); err != nil {
		return nil, err
	}

	txSize := GetTxVirtualSize(tx)
	err = mp.validateRelayFeeMet(
		tx, txFee, txSize, utxoView, nextBlockHeight, isNew, rateLimit,
	)
	if err != nil {
		return nil, err
	}
	var conflicts map[chainhash.Hash]*core.Tx
	if isReplacement {
		conflicts, err = mp.validateReplacement(tx, txFee)
		if err != nil {
			return nil, err
		}
	}

	// Verify crypto signatures for each input and reject the transaction
	// if any don't verify.
	err = blockchain.ValidateTransactionScripts(tx, utxoView,
		txscript.StandardVerifyFlags, mp.cfg.SigCache,
		mp.cfg.HashCache)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}

	result := &MempoolAcceptResult{
		TxFee:      utils.Amount(txFee),
		TxSize:     txSize,
		Conflicts:  conflicts,
		utxoView:   utxoView,
		bestHeight: bestHeight,
	}
	return result, nil
}

func (mp *TxPool) checkPoolDoubleSpend(tx *core.Tx) (bool, error) {
	var isReplacement bool
	for _, txIn := range tx.MsgTx().TxIn {
		conflict, ok := mp.outpoints[txIn.PreviousOutPoint]
		if !ok {
			continue
		}

		// Reject the transaction if we don't accept replacement
		// transactions or if it doesn't signal replacement.
		if mp.cfg.Policy.RejectReplacement ||
			!mp.signalsReplacement(conflict, nil) {
			str := fmt.Sprintf("output already spent in mempool: "+
				"output=%v, tx=%v", txIn.PreviousOutPoint,
				conflict.Hash())
			return false, txRuleError(wire.RejectDuplicate, str)
		}

		isReplacement = true
	}

	return isReplacement, nil
}

// 这个 signalsReplacement 方法的作用是判断一个交易是否符合 Replace-By-Fee (RBF) 替换策略，即该交易是否允许被其他交易替换。
//
// 具体来说，它通过两种方式判断交易是否 "发出替换信号"：
//
// 显式信号（Explicit signaling）：
// 检查交易的所有输入（TxIn）的序列号（Sequence）。如果任何一个输入的序列号小于等于 MaxRBFSequence（即 0xfffffffe），则该交易明确声明自己允许被替换，直接返回 true。
// 继承信号（Inherited signaling）：
// 如果交易没有显式信号，则检查它的所有未确认祖先交易（即该交易依赖的、且尚未被区块链确认的前置交易）。如果存在任何一个未确认的祖先交易符合 RBF 策略（无论是显式信号还是继承信号），则当前交易也继承了替换权限，返回 true。
//
// 此外，方法还通过一个可选的 cache 缓存（map[chainhash.Hash]struct{}）优化性能，避免重复检查已经确定不发送替换信号的交易，减少不必要的递归计算。
func (mp *TxPool) signalsReplacement(tx *core.Tx,
	cache map[chainhash.Hash]struct{}) bool {
	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]struct{})
	}
	for _, txIn := range tx.MsgTx().TxIn {
		if txIn.Sequence <= MaxRBFSequence {
			return true
		}
		hash := txIn.PreviousOutPoint.Hash
		unconfirmedAncestor, ok := mp.pool[hash]
		if !ok {
			continue
		}
		// If we've already determined the transaction doesn't signal
		// replacement, we can avoid visiting it again.
		if _, ok := cache[hash]; ok {
			continue
		}
		if mp.signalsReplacement(unconfirmedAncestor.Tx, cache) {
			return true
		}
		// Since the transaction doesn't signal replacement, we'll cache
		// its result to ensure we don't attempt to determine so again.
		cache[hash] = struct{}{}
	}
	return false
}

// 这个  方法的作用是获取某笔交易所有输入所引用的 UTXO（未花费交易输出）详情，具体过程结合了主链（已确认交易）和交易池（未确认交易）的信息，确保完整获取输入对应的 UTXO 数据。
// 具体逻辑拆解：
// 从主链获取基础 UTXO 信息
// 首先通过 mp.cfg.FetchUtxoView(tx) 从主链（已上链的确认交易）中加载当前交易输入所引用的 UTXO 视图（UtxoViewpoint）。这一步获取的是区块链上已确认的 UTXO 数据。
// 用交易池信息补充缺失的 UTXO
// 由于交易的输入可能引用未确认的交易（这些交易还未上链，只存在于交易池中），主链的 UTXO 视图可能不包含这些信息。因此需要：
// 遍历当前交易的所有输入（TxIn），检查每个输入引用的前置输出（PreviousOutPoint）在主链 UTXO 视图中是否存在且未被花费。
// 若主链中没有该 UTXO（或已被花费），则检查交易池（mp.pool）中是否存在对应的未确认交易。如果存在，就将该未确认交易的输出添加到 UTXO 视图中，并用 mining.UnminedHeight 标记其未确认状态。
// 核心目的：
// 确保完整获取当前交易所有输入对应的 UTXO 详情，既包括主链上已确认的 UTXO，也包括交易池中未确认但被引用的 UTXO，为后续的交易验证（如检查输入是否有效、是否已被花费等）提供完整的数据基础。
func (mp *TxPool) fetchInputUtxos(tx *core.Tx) (*blockchain.UtxoViewpoint, error) {
	//最终错误在这里
	utxoView, err := mp.cfg.FetchUtxoView(tx)
	if err != nil {
		return nil, err
	}
	// Attempt to populate any missing inputs from the transaction pool.
	for _, txIn := range tx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		entry := utxoView.LookupEntry(*prevOut)
		if entry != nil && !entry.IsSpent() {
			continue
		}
		//用于添加一笔交易的输出到视图中
		if poolTxDesc, exists := mp.pool[prevOut.Hash]; exists {
			// AddTxOut ignores out of range index values, so it is
			// safe to call without bounds checking here.
			utxoView.AddTxOut(poolTxDesc.Tx, prevOut.Index, mining.UnminedHeight)
		}
	}
	return utxoView, nil
}

// 这段代码的核心作用是验证交易是否符合 “标准交易” 规则，包括交易本身的标准性和其输入的标准性。只有符合标准的交易才能被正常处理（除非系统配置为接受非标准交易）。
// 具体逻辑拆解：
// 非标准交易开关检查
// 首先判断系统配置（mp.cfg.Policy.AcceptNonStd）是否允许接受非标准交易。如果允许（AcceptNonStd为true），则直接返回nil（不进行标准性验证，跳过后续检查）。
// 注释特别提醒：如果修改此逻辑以接受非标准交易，需要额外检查交易的 ECDSA 签名验证次数是否合理（防止恶意交易通过大量签名消耗资源）。
// 验证交易整体标准性
// 调用CheckTransactionStandard函数，对交易本身进行标准性检查。检查依据包括：
// 下一个区块高度（nextBlockHeight）
// 过去的中位数时间（medianTimePast）
// 最小中继交易费（MinRelayTxFee）
// 最大交易版本（MaxTxVersion）等系统策略。
// 如果检查失败，会提取错误对应的 “拒绝码”（如无明确拒绝码则默认wire.RejectNonstandard），并返回包含交易哈希和错误信息的txRuleError（标记交易为非标准）。
// 验证交易输入标准性
// 调用checkInputsStandard函数，检查交易的所有输入是否符合标准。例如，输入引用的 UTXO 格式、签名脚本是否符合规范等。
// 若输入不符合标准，同样提取拒绝码（默认wire.RejectNonstandard），返回包含交易哈希和输入错误信息的txRuleError。
// 核心目的：
// 确保进入交易池的交易符合网络约定的 “标准格式和规则”，这有助于维护网络兼容性、减少异常交易带来的风险（如资源滥用、解析错误等）。只有通过标准性验证的交易，才会被进一步处理或转发；非标准交易则会被拒绝（除非系统明确允许）。
func (mp *TxPool) validateStandardness(tx *core.Tx, nextBlockHeight int32,
	medianTimePast time.Time, utxoView *blockchain.UtxoViewpoint) error {

	// Exit early if we accept non-standard transactions.
	//
	// NOTE: if you modify this code to accept non-standard transactions,
	// you should add code here to check that the transaction does a
	// reasonable number of ECDSA signature verifications.
	if mp.cfg.Policy.AcceptNonStd {
		return nil
	}

	// Check the transaction standard.
	err := CheckTransactionStandard(
		tx, nextBlockHeight, medianTimePast,
		mp.cfg.Policy.MinRelayTxFee, mp.cfg.Policy.MaxTxVersion,
	)
	if err != nil {
		// Attempt to extract a reject code from the error so it can be
		// retained. When not possible, fall back to a non standard
		// error.
		rejectCode, found := extractRejectCode(err)
		if !found {
			rejectCode = wire.RejectNonstandard
		}
		str := fmt.Sprintf("transaction %v is not standard: %v",
			tx.Hash(), err)

		return txRuleError(rejectCode, str)
	}

	// Check the inputs standard.
	err = checkInputsStandard(tx, utxoView)
	if err != nil {
		// Attempt to extract a reject code from the error so it can be
		// retained. When not possible, fall back to a non-standard
		// error.
		rejectCode, found := extractRejectCode(err)
		if !found {
			rejectCode = wire.RejectNonstandard
		}
		str := fmt.Sprintf("transaction %v has a non-standard "+
			"input: %v", tx.Hash(), err)

		return txRuleError(rejectCode, str)
	}

	return nil
}

// validateSigCost 用来判断一笔交易的“签名操作成本”是否超过内存池允许的上限，防止高成本交易被接纳。
// 比特币的签名验证（ECDSA / Schnorr）是 CPU 最耗时的操作之一。
// 为了防止：
// DoS 攻击：有人故意广播包含大量签名的交易拖慢节点。
// 资源滥用：把昂贵的验证工作推给全网节点。
// 协议把“签名操作”抽象为签名操作成本（sigop cost），并给每个交易设上限。
func (mp *TxPool) validateSigCost(tx *core.Tx,
	utxoView *blockchain.UtxoViewpoint) error {

	// Since the coinbase address itself can contain signature operations,
	// the maximum allowed signature operations per transaction is less
	// than the maximum allowed signature operations per block.
	//
	// TODO(roasbeef): last bool should be conditional on segwit activation
	sigOpCost, err := blockchain.GetSigOpCost(tx, false, utxoView)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return chainRuleError(cerr)
		}

		return err
	}

	// Exit early if the sig cost is under limit.
	if sigOpCost <= mp.cfg.Policy.MaxSigOpCostPerTx {
		return nil
	}
	str := fmt.Sprintf("transaction %v sigop cost is too high: %d > %d",
		tx.Hash(), sigOpCost, mp.cfg.Policy.MaxSigOpCostPerTx)
	return txRuleError(wire.RejectNonstandard, str)
}

func (mp *TxPool) validateReplacement(tx *core.Tx,
	txFee int64) (map[chainhash.Hash]*core.Tx, error) {

	// First, we'll make sure the set of conflicting transactions doesn't
	// exceed the maximum allowed.
	conflicts := mp.txConflicts(tx)
	if len(conflicts) > MaxReplacementEvictions {
		str := fmt.Sprintf("%v: replacement transaction evicts more "+
			"transactions than permitted: max is %v, evicts %v",
			tx.Hash(), MaxReplacementEvictions, len(conflicts))
		return nil, txRuleError(wire.RejectNonstandard, str)
	}

	// The set of conflicts (transactions we'll replace) and ancestors
	// should not overlap, otherwise the replacement would be spending an
	// output that no longer exists.
	for ancestorHash := range mp.txAncestors(tx, nil) {
		if _, ok := conflicts[ancestorHash]; !ok {
			continue
		}
		str := fmt.Sprintf("%v: replacement transaction spends parent "+
			"transaction %v", tx.Hash(), ancestorHash)
		return nil, txRuleError(wire.RejectInvalid, str)
	}

	// The replacement should have a higher fee rate than each of the
	// conflicting transactions and a higher absolute fee than the fee sum
	// of all the conflicting transactions.
	//
	// We usually don't want to accept replacements with lower fee rates
	// than what they replaced as that would lower the fee rate of the next
	// block. Requiring that the fee rate always be increased is also an
	// easy-to-reason about way to prevent DoS attacks via replacements.
	var (
		txSize           = GetTxVirtualSize(tx)
		txFeeRate        = txFee * 1000 / txSize
		conflictsFee     int64
		conflictsParents = make(map[chainhash.Hash]struct{})
	)
	for hash, conflict := range conflicts {
		if txFeeRate <= mp.pool[hash].FeePerKB {
			str := fmt.Sprintf("%v: replacement transaction has an "+
				"insufficient fee rate: needs more than %v, "+
				"has %v", tx.Hash(), mp.pool[hash].FeePerKB,
				txFeeRate)
			return nil, txRuleError(wire.RejectInsufficientFee, str)
		}

		conflictsFee += mp.pool[hash].Fee

		// We'll track each conflict's parents to ensure the replacement
		// isn't spending any new unconfirmed inputs.
		for _, txIn := range conflict.MsgTx().TxIn {
			conflictsParents[txIn.PreviousOutPoint.Hash] = struct{}{}
		}
	}

	// It should also have an absolute fee greater than all of the
	// transactions it intends to replace and pay for its own bandwidth,
	// which is determined by our minimum relay fee.
	minFee := calcMinRequiredTxRelayFee(txSize, mp.cfg.Policy.MinRelayTxFee)
	if txFee < conflictsFee+minFee {
		str := fmt.Sprintf("%v: replacement transaction has an "+
			"insufficient absolute fee: needs %v, has %v",
			tx.Hash(), conflictsFee+minFee, txFee)
		return nil, txRuleError(wire.RejectInsufficientFee, str)
	}

	// Finally, it should not spend any new unconfirmed outputs, other than
	// the ones already included in the parents of the conflicting
	// transactions it'll replace.
	for _, txIn := range tx.MsgTx().TxIn {
		if _, ok := conflictsParents[txIn.PreviousOutPoint.Hash]; ok {
			continue
		}
		// Confirmed outputs are valid to spend in the replacement.
		if _, ok := mp.pool[txIn.PreviousOutPoint.Hash]; !ok {
			continue
		}
		str := fmt.Sprintf("replacement transaction spends new "+
			"unconfirmed input %v not found in conflicting "+
			"transactions", txIn.PreviousOutPoint)
		return nil, txRuleError(wire.RejectInvalid, str)
	}

	return conflicts, nil
}

// txConflicts 方法的核心作用是 找出当给定交易被加入内存池时，所有与之存在 “UTXO 冲突”
// 的未确认交易及其后代交易，这些冲突交易将因新交易的加入而变得无效。
// 具体逻辑说明
// 在比特币网络中，每个未花费交易输出（UTXO）只能被花费一次。当一个新交易尝试加入内存池时，
// 如果它引用的某个 UTXO 已经被内存中现有的未确认交易引用（即两者尝试花费同一个 UTXO），就会产生 “冲突”。该方法的工作流程如下：
//
// 遍历新交易的所有输入：检查新交易（tx）的每个输入（TxIn）所引用的前序输出（PreviousOutPoint
// ，即它要花费的 UTXO）。
// 查找直接冲突交易：通过内存池的outpoints映射（记录 UTXO 与花费它的未确认交易的对应关系），
// 找到所有已经在内存池中、且同样尝试花费这些 UTXO 的未确认交易（即 “直接冲突交易”）。
// 递归查找冲突交易的后代：冲突交易的所有后代交易（依赖该冲突交易输出的交易）也会被视为冲突，
// 因为一旦父交易因冲突失效，
// 后代交易也会随之无效。方法通过txDescendants获取这些后代，并将它们一并加入冲突集合。
func (mp *TxPool) txConflicts(tx *core.Tx) map[chainhash.Hash]*core.Tx {
	conflicts := make(map[chainhash.Hash]*core.Tx)
	for _, txIn := range tx.MsgTx().TxIn {
		conflict, ok := mp.outpoints[txIn.PreviousOutPoint]
		if !ok {
			continue
		}
		conflicts[*conflict.Hash()] = conflict
		descendants := mp.txDescendants(conflict, nil)
		maps.Copy(conflicts, descendants)
	}
	return conflicts
}

// txDescendants 方法的核心作用是 查找并返回给定未确认交易的所有未确认后代交易
// （包括直接和间接依赖的后代），并通过缓存机制优化重复查询的效率。
// 具体逻辑说明
// 在比特币交易链中，“后代交易” 指的是直接或间接依赖于某笔交易输出的后续交易。例如：
// 若交易 B 花费交易 A 的输出，交易 C 花费交易 B 的输出，则 B 和 C 都是 A 的后代。该方法的工作流程如下：
//
// 初始化缓存：如果未提供缓存（cache），则创建一个新缓存，用于存储已计算过的交易后代，
// 避免重复递归计算，提升效率。
// 查找直接后代：遍历给定交易（tx）的所有输出（TxOut），为每个输出构建对应的OutPoint
// （包含交易哈希和输出索引）。通过内存池的outpoints映射（记录 UTXO 与花费它的未确认交易的对应关系），
// 找到所有直接花费这些输出的未确认交易 —— 这些是tx的直接后代。
// 递归查找间接后代：对于每个直接后代，检查缓存中是否已存在其后代信息。如果没有，
// 则递归调用txDescendants获取该后代的所有后代（即tx的间接后代），并将结果存入缓存。
// 聚合所有后代：将直接后代和递归找到的间接后代汇总，形成给定交易的完整后代集合并返回。
func (mp *TxPool) txDescendants(tx *core.Tx,
	cache map[chainhash.Hash]map[chainhash.Hash]*core.Tx) map[chainhash.Hash]*core.Tx {

	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]map[chainhash.Hash]*core.Tx)
	}

	// We'll go through all of the outputs of the transaction to determine
	// if they are spent by any other mempool transactions.
	descendants := make(map[chainhash.Hash]*core.Tx)
	op := core.OutPoint{Hash: *tx.Hash()}
	for i := range tx.MsgTx().TxOut {
		op.Index = uint32(i)
		descendant, ok := mp.outpoints[op]
		if !ok {
			continue
		}
		descendants[*descendant.Hash()] = descendant

		// Determine if the descendants of this descendant have already
		// been computed. If they haven't, we'll do so now and cache
		// them to use them later on if necessary.
		moreDescendants, ok := cache[*descendant.Hash()]
		if !ok {
			moreDescendants = mp.txDescendants(descendant, cache)
			cache[*descendant.Hash()] = moreDescendants
		}

		for _, moreDescendant := range moreDescendants {
			descendants[*moreDescendant.Hash()] = moreDescendant
		}
	}

	return descendants
}

// txAncestors 是比特币内存池（TxPool）中的核心方法，其核心作用是查找指定未确认交易的所有未确认祖先交易，
// 并通过缓存优化避免重复计算。以下从功能定义、工作原理、关键特性和示例场景展开详细说明：
// 若存在交易链 A → B → C（A 的输出被 B 花费，B 的输出被 C 花费），则 A 和 B 均为 C 的祖先；
// 该方法仅处理未确认交易（已确认交易已上链，不属于内存池范畴，不会被检索）。
func (mp *TxPool) txAncestors(tx *core.Tx,
	cache map[chainhash.Hash]map[chainhash.Hash]*core.Tx) map[chainhash.Hash]*core.Tx {

	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]map[chainhash.Hash]*core.Tx)
	}

	ancestors := make(map[chainhash.Hash]*core.Tx)
	for _, txIn := range tx.MsgTx().TxIn {
		parent, ok := mp.pool[txIn.PreviousOutPoint.Hash]
		if !ok {
			continue
		}
		ancestors[*parent.Tx.Hash()] = parent.Tx

		// Determine if the ancestors of this ancestor have already been
		// computed. If they haven't, we'll do so now and cache them to
		// use them later on if necessary.
		moreAncestors, ok := cache[*parent.Tx.Hash()]
		if !ok {
			moreAncestors = mp.txAncestors(parent.Tx, cache)
			cache[*parent.Tx.Hash()] = moreAncestors
		}
		maps.Copy(ancestors, moreAncestors)
	}
	return ancestors
}

func (mp *TxPool) RemoveDoubleSpends(tx *core.Tx) {
	// Protect concurrent access.
	mp.mtx.Lock()
	for _, txIn := range tx.MsgTx().TxIn {
		if txRedeemer, ok := mp.outpoints[txIn.PreviousOutPoint]; ok {
			if !txRedeemer.Hash().IsEqual(tx.Hash()) {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}
	mp.mtx.Unlock()
}

func (mp *TxPool) RemoveOrphan(tx *core.Tx) {
	mp.mtx.Lock()
	mp.removeOrphan(tx, false)
	mp.mtx.Unlock()
}

func (mp *TxPool) ProcessOrphans(acceptedTx *core.Tx) []*TxDesc {
	mp.mtx.Lock()
	acceptedTxns := mp.processOrphans(acceptedTx)
	mp.mtx.Unlock()

	return acceptedTxns
}

func (mp *TxPool) processOrphans(acceptedTx *core.Tx) []*TxDesc {
	var acceptedTxns []*TxDesc

	// Start with processing at least the passed transaction.
	processList := list.New()
	processList.PushBack(acceptedTx)
	for processList.Len() > 0 {
		// Pop the transaction to process from the front of the list.
		firstElement := processList.Remove(processList.Front())
		processItem := firstElement.(*core.Tx)

		prevOut := core.OutPoint{Hash: *processItem.Hash()}
		for txOutIdx := range processItem.MsgTx().TxOut {
			// Look up all orphans that redeem the output that is
			// now available.  This will typically only be one, but
			// it could be multiple if the orphan pool contains
			// double spends.  While it may seem odd that the orphan
			// pool would allow this since there can only possibly
			// ultimately be a single redeemer, it's important to
			// track it this way to prevent malicious actors from
			// being able to purposely constructing orphans that
			// would otherwise make outputs unspendable.
			//
			// Skip to the next available output if there are none.
			prevOut.Index = uint32(txOutIdx)
			orphans, exists := mp.orphansByPrev[prevOut]
			if !exists {
				continue
			}

			// Potentially accept an orphan into the tx pool.
			for _, tx := range orphans {
				missing, txD, err := mp.maybeAcceptTransaction(
					tx, true, true, false)
				if err != nil {
					// The orphan is now invalid, so there
					// is no way any other orphans which
					// redeem any of its outputs can be
					// accepted.  Remove them.
					mp.removeOrphan(tx, true)
					break
				}

				// Transaction is still an orphan.  Try the next
				// orphan which redeems this output.
				if len(missing) > 0 {
					continue
				}

				// Transaction was accepted into the main pool.
				//
				// Add it to the list of accepted transactions
				// that are no longer orphans, remove it from
				// the orphan pool, and add it to the list of
				// transactions to process so any orphans that
				// depend on it are handled too.
				acceptedTxns = append(acceptedTxns, txD)
				mp.removeOrphan(tx, false)
				processList.PushBack(tx)

				// Only one transaction for this outpoint can be
				// accepted, so the rest are now double spends
				// and are removed later.
				break
			}
		}
	}

	// Recursively remove any orphans that also redeem any outputs redeemed
	// by the accepted transactions since those are now definitive double
	// spends.
	mp.removeOrphanDoubleSpends(acceptedTx)
	for _, txD := range acceptedTxns {
		mp.removeOrphanDoubleSpends(txD.Tx)
	}

	return acceptedTxns
}

func (mp *TxPool) removeOrphanDoubleSpends(tx *core.Tx) {
	msgTx := tx.MsgTx()
	for _, txIn := range msgTx.TxIn {
		for _, orphan := range mp.orphansByPrev[txIn.PreviousOutPoint] {
			mp.removeOrphan(orphan, true)
		}
	}
}

func (mp *TxPool) MaybeAcceptTransaction(tx *core.Tx, isNew, rateLimit bool) ([]*chainhash.Hash, *TxDesc, error) {
	// Protect concurrent access.
	mp.mtx.Lock()
	hashes, txD, err := mp.maybeAcceptTransaction(tx, isNew, rateLimit, true)
	mp.mtx.Unlock()

	return hashes, txD, err
}

func (mp *TxPool) addTransaction(utxoView *blockchain.UtxoViewpoint, tx *core.Tx, height int32, fee int64) *TxDesc {
	// Add the transaction to the pool and mark the referenced outpoints
	// as spent by the pool.
	txD := &TxDesc{
		TxDesc: mining.TxDesc{
			Tx:       tx,
			Added:    time.Now(),
			Height:   height,
			Fee:      fee,
			FeePerKB: fee * 1000 / GetTxVirtualSize(tx),
		},
		StartingPriority: mining.CalcPriority(tx.MsgTx(), utxoView, height),
	}

	mp.pool[*tx.Hash()] = txD
	for _, txIn := range tx.MsgTx().TxIn {
		mp.outpoints[txIn.PreviousOutPoint] = tx
	}
	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())

	if mp.cfg.AddrIndex != nil {
		mp.cfg.AddrIndex.AddUnconfirmedTx(tx, utxoView)
	}

	// Record this tx for fee estimation if enabled.
	if mp.cfg.FeeEstimator != nil {
		mp.cfg.FeeEstimator.ObserveTransaction(txD)
	}
	return txD
}

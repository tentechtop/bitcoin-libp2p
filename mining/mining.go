package mining

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wire"
	"bytes"
	"container/heap"
	"fmt"

	"time"
)

const (

	// maxNonce is the maximum value a nonce can be in a block header.
	MaxNonce = ^uint32(0) // 2^32 - 1

	// maxExtraNonce is the maximum value an extra nonce used in a coinbase
	// transaction can be.
	MaxExtraNonce = ^uint64(0) // 2^64 - 1

	// hpsUpdateSecs is the number of seconds to wait in between each
	// update to the hashes per second monitor.
	HpsUpdateSecs = 10

	// hashUpdateSec is the number of seconds each worker waits in between
	// notifying the speed monitor with how many hashes have been completed
	// while they are actively searching for a solution.  This is done to
	// reduce the amount of syncs between the workers that must be done to
	// keep track of the hashes per second.
	HashUpdateSecs = 15
)

const (
	// MinHighPriority 是一条交易被视为“高优先级”的最小优先级值。
	// 计算公式：1 BTC × 144 / 250 ≈ 0.576 BTC
	// 144 ≈ 一天内产生的区块数（6×24），250 是比特币经典客户端当年用的经验系数。
	MinHighPriority = chaincfg.SatoshiPerBitcoin * 144.0 / 250

	// blockHeaderOverhead 是序列化一个完整区块头所需的最大字节数
	// 再加上“可变长度整数”最多占用的字节数。
	// 用于估算区块剩余可用空间时，先扣除头部开销。
	blockHeaderOverhead = chaincfg.MaxBlockHeaderPayload + chaincfg.MaxVarIntPayload

	// CoinbaseFlags 是一段固定附加在 coinbase 交易脚本里的标记字符串。
	// 目的：
	// 1) 便于全网识别该区块由 btcd 生成；
	// 2) 早期也用来监控 BIP16（P2SH）软分叉支持情况。
	CoinbaseFlags = "/P2SH/bitcoin/"
)

type TxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx *core.Tx

	// Added is the time when the entry was added to the source pool.
	Added time.Time

	// Height is the block height when the entry was added to the source
	// pool.
	Height int32

	// Fee is the total fee the transaction associated with the entry pays.
	Fee int64

	// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
	FeePerKB int64
}

type TxSource interface {
	// LastUpdated returns the last time a transaction was added to or
	// removed from the source pool.
	LastUpdated() time.Time

	// MiningDescs returns a slice of mining descriptors for all the
	// transactions in the source pool.
	MiningDescs() []*TxDesc

	// HaveTransaction returns whether or not the passed transaction hash
	// exists in the source pool.
	HaveTransaction(hash *chainhash.Hash) bool
}

type txPrioItem struct {
	tx       *core.Tx
	fee      int64
	priority float64
	feePerKB int64

	// dependsOn holds a map of transaction hashes which this one depends
	// on.  It will only be set when the transaction references other
	// transactions in the source pool and hence must come after them in
	// a block.
	dependsOn map[chainhash.Hash]struct{}
}

type txPriorityQueue struct {
	lessFunc txPriorityQueueLessFunc
	items    []*txPrioItem
}
type txPriorityQueueLessFunc func(*txPriorityQueue, int, int) bool

func (pq *txPriorityQueue) Len() int {
	return len(pq.items)
}

func (pq *txPriorityQueue) Less(i, j int) bool {
	return pq.lessFunc(pq, i, j)
}

func (pq *txPriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

func (pq *txPriorityQueue) Push(x interface{}) {
	pq.items = append(pq.items, x.(*txPrioItem))
}

func (pq *txPriorityQueue) Pop() interface{} {
	n := len(pq.items)
	item := pq.items[n-1]
	pq.items[n-1] = nil
	pq.items = pq.items[0 : n-1]
	return item
}

func (pq *txPriorityQueue) SetLessFunc(lessFunc txPriorityQueueLessFunc) {
	pq.lessFunc = lessFunc
	heap.Init(pq)
}

func txPQByPriority(pq *txPriorityQueue, i, j int) bool {
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}
	return pq.items[i].priority > pq.items[j].priority
}

func txPQByFee(pq *txPriorityQueue, i, j int) bool {
	if pq.items[i].feePerKB == pq.items[j].feePerKB {
		return pq.items[i].priority > pq.items[j].priority
	}
	return pq.items[i].feePerKB > pq.items[j].feePerKB
}

func newTxPriorityQueue(reserve int, sortByFee bool) *txPriorityQueue {
	pq := &txPriorityQueue{
		items: make([]*txPrioItem, 0, reserve),
	}
	if sortByFee {
		pq.SetLessFunc(txPQByFee)
	} else {
		pq.SetLessFunc(txPQByPriority)
	}
	return pq
}

// BlockTemplate 结构体用于描述一个“待挖矿”的区块模板。
// 除尚未满足工作量证明外，其余规则均已验证通过。
type BlockTemplate struct {
	// Block 即为该模板对应的完整区块，可直接交由矿工进行工作量计算。
	Block *core.MsgBlock

	// Fees 按交易顺序给出每笔交易支付的手续费（基础单位）。
	// 第 0 条交易为 Coinbase，因此 Fees[0] 为其余所有交易手续费总和的负值。
	Fees []int64

	// SigOpCosts 按交易顺序给出每笔交易消耗的签名操作数。
	SigOpCosts []int64

	// Height 表示该模板所连接的主链高度。
	Height int32

	// ValidPayAddress 指示 Coinbase 输出是否支付到指定地址。 验证矿工的地址
	// 若为 false，则 Coinbase 可被任何人领取，常用于无需支付地址的场景。
	ValidPayAddress bool

	// WitnessCommitment 对本区块内所有见证数据做一次性承诺（merkle root）。
	// 仅在隔离见证已激活且区块中存在含见证数据的交易时才会填充此字段。
	WitnessCommitment []byte
}

func mergeUtxoView(viewA *blockchain.UtxoViewpoint, viewB *blockchain.UtxoViewpoint) {
	viewAEntries := viewA.Entries()
	for outpoint, entryB := range viewB.Entries() {
		if entryA, exists := viewAEntries[outpoint]; !exists ||
			entryA == nil || entryA.IsSpent() {

			viewAEntries[outpoint] = entryB
		}
	}
}

func standardCoinbaseScript(nextBlockHeight int32, extraNonce uint64) ([]byte, error) {
	return txscript.NewScriptBuilder().AddInt64(int64(nextBlockHeight)).
		AddInt64(int64(extraNonce)).AddData([]byte(CoinbaseFlags)).
		Script()
}

func createCoinbaseTx(params *core.Params, coinbaseScript []byte, nextBlockHeight int32, addr utils.Address) (*core.Tx, error) {
	var pkScript []byte
	if addr != nil {
		var err error
		pkScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		scriptBuilder := txscript.NewScriptBuilder()
		pkScript, err = scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
	}
	tx := core.NewMsgTx(core.TxVersion)
	tx.AddTxIn(&core.TxIn{
		PreviousOutPoint: *core.NewOutPoint(&chainhash.Hash{}, core.MaxPrevOutIndex),
		SignatureScript:  coinbaseScript,
		Sequence:         core.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&core.TxOut{
		Value:    blockchain.CalcBlockSubsidy(nextBlockHeight, params),
		PkScript: pkScript,
	})
	return core.NewTx(tx), nil
}

func spendTransaction(utxoView *blockchain.UtxoViewpoint, tx *core.Tx, height int32) error {
	for _, txIn := range tx.MsgTx().TxIn {
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil {
			entry.Spend()
		}
	}

	utxoView.AddTxOuts(tx, height)
	return nil
}

func logSkippedDeps(tx *core.Tx, deps map[chainhash.Hash]*txPrioItem) {
	if deps == nil {
		return
	}

	for _, item := range deps {
		log.Tracef("Skipping tx %s since it depends on %s\n",
			item.tx.Hash(), tx.Hash())
	}
}

func MinimumMedianTime(chainState *blockchain.BestState) time.Time {
	return chainState.MedianTime.Add(time.Second)
}

func medianAdjustedTime(chainState *blockchain.BestState, timeSource blockchain.MedianTimeSource) time.Time {
	newTimestamp := timeSource.AdjustedTime()
	minTimestamp := MinimumMedianTime(chainState)
	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}
	return newTimestamp
}

type BlkTmplGenerator struct {
	policy      *Policy
	chainParams *core.Params
	txSource    TxSource
	chain       *blockchain.BlockChain
	timeSource  blockchain.MedianTimeSource
	sigCache    *txscript.SigCache
	hashCache   *txscript.HashCache
}

func NewBlkTmplGenerator(policy *Policy, params *core.Params, txSource TxSource, chain *blockchain.BlockChain, timeSource blockchain.MedianTimeSource, sigCache *txscript.SigCache, hashCache *txscript.HashCache) *BlkTmplGenerator {

	return &BlkTmplGenerator{
		policy:      policy,
		chainParams: params,
		txSource:    txSource,
		chain:       chain,
		timeSource:  timeSource,
		sigCache:    sigCache,
		hashCache:   hashCache,
	}
}

func (g *BlkTmplGenerator) NewBlockTemplateBack(payToAddress utils.Address, curHeight int32) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.chain.BestSnapshot()
	nextBlockHeight := best.Height + 1

	extraNonce := uint64(0)
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(g.chainParams, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}
	coinbaseSigOpCost := int64(blockchain.CountSigOps(coinbaseTx)) * blockchain.WitnessScaleFactor

	sourceTxns := g.txSource.MiningDescs() //提取交易
	log.Infof("提取交易%s", sourceTxns)

	sortedByFee := g.policy.BlockPrioritySize == 0
	priorityQueue := newTxPriorityQueue(len(sourceTxns), sortedByFee)

	blockTxns := make([]*core.Tx, 0, len(sourceTxns))
	//先加入Coinbase交易（区块必需，用于矿工奖励）
	blockTxns = append(blockTxns, coinbaseTx)

	blockUtxos := blockchain.NewUtxoViewpoint()
	log.Debugf("Block weight %d", blockUtxos)

	dependers := make(map[chainhash.Hash]map[chainhash.Hash]*txPrioItem)

	txFees := make([]int64, 0, len(sourceTxns))
	txSigOpCosts := make([]int64, 0, len(sourceTxns))
	txFees = append(txFees, -1) // Updated once known
	txSigOpCosts = append(txSigOpCosts, coinbaseSigOpCost)

	log.Debugf("Considering %d transactions for inclusion to new block",
		len(sourceTxns))

	log.Tracef("Priority queue len %d, dependers len %d",
		priorityQueue.Len(), len(dependers))

	blockWeight := uint32((blockHeaderOverhead * blockchain.WitnessScaleFactor) +
		blockchain.GetTransactionWeight(coinbaseTx))
	blockSigOpCost := coinbaseSigOpCost
	totalFees := int64(0)

	if err != nil {
		return nil, err
	}

	witnessIncluded := false

	// Now that the actual transactions have been selected, update the
	// block weight for the real transaction count and coinbase value with
	// the total fees accordingly.
	blockWeight -= wire.MaxVarIntPayload -
		(uint32(wire.VarIntSerializeSize(uint64(len(blockTxns)))) *
			blockchain.WitnessScaleFactor)
	coinbaseTx.MsgTx().TxOut[0].Value += totalFees
	txFees[0] = -totalFees

	var witnessCommitment []byte
	if witnessIncluded {
		witnessCommitment = AddWitnessCommitment(coinbaseTx, blockTxns)
	}
	ts := medianAdjustedTime(best, g.timeSource)

	//难度
	reqDifficulty, err := g.chain.CalcNextRequiredDifficulty(nextBlockHeight)
	if err != nil {
		return nil, err
	}

	//版本
	nextBlockVersion, err := g.chain.CalcNextBlockVersion(&best.Hash)
	if err != nil {
		return nil, err
	}

	var msgBlock core.MsgBlock
	msgBlock.Header = core.BlockHeader{
		Version:    nextBlockVersion,
		PrevBlock:  best.Hash,
		MerkleRoot: blockchain.CalcMerkleRoot(blockTxns, false),
		Timestamp:  ts.Unix(),
		Bits:       reqDifficulty,
	}
	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	block := core.NewBlock(&msgBlock)
	block.SetHeight(nextBlockHeight)
	if err := g.chain.CheckConnectBlockTemplate(block); err != nil {
		return nil, err
	}
	log.Debugf("Created new block template (%d transactions, %d in "+
		"fees, %d signature operations cost, %d weight, target difficulty "+
		"%064x)", len(msgBlock.Transactions), totalFees, blockSigOpCost,
		blockWeight, blockchain.CompactToBig(msgBlock.Header.Bits))

	return &BlockTemplate{
		Block:             &msgBlock,
		Fees:              txFees,
		SigOpCosts:        txSigOpCosts,
		Height:            nextBlockHeight,
		ValidPayAddress:   payToAddress != nil,
		WitnessCommitment: witnessCommitment,
	}, nil
}

func (g *BlkTmplGenerator) NewBlockTemplate(payToAddress utils.Address, curHeight int32) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.chain.BestSnapshot()
	nextBlockHeight := best.Height + 1

	// Create a standard coinbase transaction paying to the provided
	// address.  NOTE: The coinbase value will be updated to include the
	// fees from the selected transactions later after they have actually
	// been selected.  It is created here to detect any errors early
	// before potentially doing a lot of work below.  The extra nonce helps
	// ensure the transaction is not a duplicate transaction (paying the
	// same value to the same public key address would otherwise be an
	// identical transaction for block version 1).
	extraNonce := uint64(0)
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(g.chainParams, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}
	coinbaseSigOpCost := int64(blockchain.CountSigOps(coinbaseTx)) * blockchain.WitnessScaleFactor

	// Get the current source transactions and create a priority queue to
	// hold the transactions which are ready for inclusion into a block
	// along with some priority related and fee metadata.  Reserve the same
	// number of items that are available for the priority queue.  Also,
	// choose the initial sort order for the priority queue based on whether
	// or not there is an area allocated for high-priority transactions.
	sourceTxns := g.txSource.MiningDescs()
	sortedByFee := g.policy.BlockPrioritySize == 0
	priorityQueue := newTxPriorityQueue(len(sourceTxns), sortedByFee)

	// Create a slice to hold the transactions to be included in the
	// generated block with reserved space.  Also create a utxo view to
	// house all of the input transactions so multiple lookups can be
	// avoided.
	blockTxns := make([]*core.Tx, 0, len(sourceTxns))
	blockTxns = append(blockTxns, coinbaseTx)
	blockUtxos := blockchain.NewUtxoViewpoint()

	// dependers is used to track transactions which depend on another
	// transaction in the source pool.  This, in conjunction with the
	// dependsOn map kept with each dependent transaction helps quickly
	// determine which dependent transactions are now eligible for inclusion
	// in the block once each transaction has been included.
	dependers := make(map[chainhash.Hash]map[chainhash.Hash]*txPrioItem)

	// Create slices to hold the fees and number of signature operations
	// for each of the selected transactions and add an entry for the
	// coinbase.  This allows the code below to simply append details about
	// a transaction as it is selected for inclusion in the final block.
	// However, since the total fees aren't known yet, use a dummy value for
	// the coinbase fee which will be updated later.
	txFees := make([]int64, 0, len(sourceTxns))
	txSigOpCosts := make([]int64, 0, len(sourceTxns))
	txFees = append(txFees, -1) // Updated once known
	txSigOpCosts = append(txSigOpCosts, coinbaseSigOpCost)

	log.Debugf("Considering %d transactions for inclusion to new block",
		len(sourceTxns))

mempoolLoop:
	for _, txDesc := range sourceTxns {
		// A block can't have more than one coinbase or contain
		// non-finalized transactions.
		tx := txDesc.Tx
		if blockchain.IsCoinBase(tx) {
			log.Tracef("Skipping coinbase tx %s", tx.Hash())
			continue
		}
		if !blockchain.IsFinalizedTransaction(tx, nextBlockHeight,
			g.timeSource.AdjustedTime()) {

			log.Tracef("Skipping non-finalized tx %s", tx.Hash())
			continue
		}

		// Fetch all of the utxos referenced by this transaction.
		// NOTE: This intentionally does not fetch inputs from the
		// mempool since a transaction which depends on other
		// transactions in the mempool must come after those
		// dependencies in the final generated block.
		utxos, err := g.chain.FetchUtxoView(tx)
		if err != nil {
			log.Warnf("Unable to fetch utxo view for tx %s: %v",
				tx.Hash(), err)
			continue
		}

		// Setup dependencies for any transactions which reference
		// other transactions in the mempool so they can be properly
		// ordered below.
		prioItem := &txPrioItem{tx: tx}
		for _, txIn := range tx.MsgTx().TxIn {
			originHash := &txIn.PreviousOutPoint.Hash
			entry := utxos.LookupEntry(txIn.PreviousOutPoint)
			if entry == nil || entry.IsSpent() {
				if !g.txSource.HaveTransaction(originHash) {
					log.Tracef("Skipping tx %s because it "+
						"references unspent output %s "+
						"which is not available",
						tx.Hash(), txIn.PreviousOutPoint)
					continue mempoolLoop
				}

				// The transaction is referencing another
				// transaction in the source pool, so setup an
				// ordering dependency.
				deps, exists := dependers[*originHash]
				if !exists {
					deps = make(map[chainhash.Hash]*txPrioItem)
					dependers[*originHash] = deps
				}
				deps[*prioItem.tx.Hash()] = prioItem
				if prioItem.dependsOn == nil {
					prioItem.dependsOn = make(
						map[chainhash.Hash]struct{})
				}
				prioItem.dependsOn[*originHash] = struct{}{}

			}
		}

		// Calculate the final transaction priority using the input
		// value age sum as well as the adjusted transaction size.  The
		// formula is: sum(inputValue * inputAge) / adjustedTxSize
		prioItem.priority = CalcPriority(tx.MsgTx(), utxos,
			nextBlockHeight)

		// Calculate the fee in Satoshi/kB.
		prioItem.feePerKB = txDesc.FeePerKB
		prioItem.fee = txDesc.Fee

		// Add the transaction to the priority queue to mark it ready
		// for inclusion in the block unless it has dependencies.
		if prioItem.dependsOn == nil {
			heap.Push(priorityQueue, prioItem)
		}

		// Merge the referenced outputs from the input transactions to
		// this transaction into the block utxo view.  This allows the
		// code below to avoid a second lookup.
		mergeUtxoView(blockUtxos, utxos)
	}

	log.Tracef("Priority queue len %d, dependers len %d",
		priorityQueue.Len(), len(dependers))

	// The starting block size is the size of the block header plus the max
	// possible transaction count size, plus the size of the coinbase
	// transaction.
	blockWeight := uint32((blockHeaderOverhead * blockchain.WitnessScaleFactor) +
		blockchain.GetTransactionWeight(coinbaseTx))
	blockSigOpCost := coinbaseSigOpCost
	totalFees := int64(0)

	segwitActive := true
	witnessIncluded := false

	// Choose which transactions make it into the block.
	for priorityQueue.Len() > 0 {
		// Grab the highest priority (or highest fee per kilobyte
		// depending on the sort order) transaction.
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		tx := prioItem.tx

		switch {
		// If segregated witness has not been activated yet, then we
		// shouldn't include any witness transactions in the block.
		case !segwitActive && tx.HasWitness():
			continue

		// Otherwise, Keep track of if we've included a transaction
		// with witness data or not. If so, then we'll need to include
		// the witness commitment as the last output in the coinbase
		// transaction.
		case segwitActive && !witnessIncluded && tx.HasWitness():
			// If we're about to include a transaction bearing
			// witness data, then we'll also need to include a
			// witness commitment in the coinbase transaction.
			// Therefore, we account for the additional weight
			// within the block with a model coinbase tx with a
			// witness commitment.
			coinbaseCopy := core.NewTx(coinbaseTx.MsgTx().Copy())
			coinbaseCopy.MsgTx().TxIn[0].Witness = [][]byte{
				bytes.Repeat([]byte("a"),
					blockchain.CoinbaseWitnessDataLen),
			}
			coinbaseCopy.MsgTx().AddTxOut(&core.TxOut{
				PkScript: bytes.Repeat([]byte("a"),
					blockchain.CoinbaseWitnessPkScriptLength),
			})

			// In order to accurately account for the weight
			// addition due to this coinbase transaction, we'll add
			// the difference of the transaction before and after
			// the addition of the commitment to the block weight.
			weightDiff := blockchain.GetTransactionWeight(coinbaseCopy) -
				blockchain.GetTransactionWeight(coinbaseTx)

			blockWeight += uint32(weightDiff)

			witnessIncluded = true
		}

		// Grab any transactions which depend on this one.
		deps := dependers[*tx.Hash()]

		// Enforce maximum block size.  Also check for overflow.
		txWeight := uint32(blockchain.GetTransactionWeight(tx))
		blockPlusTxWeight := blockWeight + txWeight
		if blockPlusTxWeight < blockWeight ||
			blockPlusTxWeight >= g.policy.BlockMaxWeight {

			log.Tracef("Skipping tx %s because it would exceed "+
				"the max block weight", tx.Hash())
			logSkippedDeps(tx, deps)
			continue
		}

		// Enforce maximum signature operation cost per block.  Also
		// check for overflow.
		sigOpCost, err := blockchain.GetSigOpCost(tx, false, blockUtxos)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"GetSigOpCost: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}
		if blockSigOpCost+int64(sigOpCost) < blockSigOpCost ||
			blockSigOpCost+int64(sigOpCost) > blockchain.MaxBlockSigOpsCost {
			log.Tracef("Skipping tx %s because it would "+
				"exceed the maximum sigops per block", tx.Hash())
			logSkippedDeps(tx, deps)
			continue
		}

		// Skip free transactions once the block is larger than the
		// minimum block size.
		if sortedByFee &&
			prioItem.feePerKB < int64(g.policy.TxMinFreeFee) &&
			blockPlusTxWeight >= g.policy.BlockMinWeight {

			log.Tracef("Skipping tx %s with feePerKB %d "+
				"< TxMinFreeFee %d and block weight %d >= "+
				"minBlockWeight %d", tx.Hash(), prioItem.feePerKB,
				g.policy.TxMinFreeFee, blockPlusTxWeight,
				g.policy.BlockMinWeight)
			logSkippedDeps(tx, deps)
			continue
		}

		// Prioritize by fee per kilobyte once the block is larger than
		// the priority size or there are no more high-priority
		// transactions.
		if !sortedByFee && (blockPlusTxWeight >= g.policy.BlockPrioritySize ||
			prioItem.priority <= MinHighPriority) {

			log.Tracef("Switching to sort by fees per "+
				"kilobyte blockSize %d >= BlockPrioritySize "+
				"%d || priority %.2f <= minHighPriority %.2f",
				blockPlusTxWeight, g.policy.BlockPrioritySize,
				prioItem.priority, MinHighPriority)

			sortedByFee = true
			priorityQueue.SetLessFunc(txPQByFee)

			// Put the transaction back into the priority queue and
			// skip it so it is re-priortized by fees if it won't
			// fit into the high-priority section or the priority
			// is too low.  Otherwise this transaction will be the
			// final one in the high-priority section, so just fall
			// though to the code below so it is added now.
			if blockPlusTxWeight > g.policy.BlockPrioritySize ||
				prioItem.priority < MinHighPriority {

				heap.Push(priorityQueue, prioItem)
				continue
			}
		}

		// Ensure the transaction inputs pass all of the necessary
		// preconditions before allowing it to be added to the block.
		_, err = blockchain.CheckTransactionInputs(tx, nextBlockHeight,
			blockUtxos, g.chainParams)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionInputs: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}
		err = blockchain.ValidateTransactionScripts(tx, blockUtxos,
			txscript.StandardVerifyFlags, g.sigCache,
			g.hashCache)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"ValidateTransactionScripts: %v", tx.Hash(), err)
			logSkippedDeps(tx, deps)
			continue
		}

		// Spend the transaction inputs in the block utxo view and add
		// an entry for it to ensure any transactions which reference
		// this one have it available as an input and can ensure they
		// aren't double spending.
		spendTransaction(blockUtxos, tx, nextBlockHeight)

		// Add the transaction to the block, increment counters, and
		// save the fees and signature operation counts to the block
		// template.
		blockTxns = append(blockTxns, tx)
		blockWeight += txWeight
		blockSigOpCost += int64(sigOpCost)
		totalFees += prioItem.fee
		txFees = append(txFees, prioItem.fee)
		txSigOpCosts = append(txSigOpCosts, int64(sigOpCost))

		log.Tracef("Adding tx %s (priority %.2f, feePerKB %.2f)",
			prioItem.tx.Hash(), prioItem.priority, prioItem.feePerKB)

		// Add transactions which depend on this one (and also do not
		// have any other unsatisified dependencies) to the priority
		// queue.
		for _, item := range deps {
			// Add the transaction to the priority queue if there
			// are no more dependencies after this one.
			delete(item.dependsOn, *tx.Hash())
			if len(item.dependsOn) == 0 {
				heap.Push(priorityQueue, item)
			}
		}
	}

	// Now that the actual transactions have been selected, update the
	// block weight for the real transaction count and coinbase value with
	// the total fees accordingly.
	blockWeight -= wire.MaxVarIntPayload -
		(uint32(wire.VarIntSerializeSize(uint64(len(blockTxns)))) *
			blockchain.WitnessScaleFactor)
	coinbaseTx.MsgTx().TxOut[0].Value += totalFees
	txFees[0] = -totalFees

	// If segwit is active and we included transactions with witness data,
	// then we'll need to include a commitment to the witness data in an
	// OP_RETURN output within the coinbase transaction.
	var witnessCommitment []byte
	if witnessIncluded {
		witnessCommitment = AddWitnessCommitment(coinbaseTx, blockTxns)
	}

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the chain consensus rules.
	ts := medianAdjustedTime(best, g.timeSource)
	reqDifficulty, err := g.chain.CalcNextRequiredDifficulty(nextBlockHeight)
	if err != nil {
		return nil, err
	}

	// Calculate the next expected block version based on the state of the
	// rule change deployments.
	nextBlockVersion, err := g.chain.CalcNextBlockVersion(&best.Hash)
	if err != nil {
		return nil, err
	}

	// Create a new block ready to be solved.
	var msgBlock core.MsgBlock
	msgBlock.Header = core.BlockHeader{
		Version:    nextBlockVersion,
		PrevBlock:  best.Hash,
		MerkleRoot: blockchain.CalcMerkleRoot(blockTxns, false),
		Timestamp:  ts.Unix(),
		Bits:       reqDifficulty,
	}
	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	// Finally, perform a full check on the created block against the chain
	// consensus rules to ensure it properly connects to the current best
	// chain with no issues.
	block := core.NewBlock(&msgBlock)
	block.SetHeight(nextBlockHeight)
	if err := g.chain.CheckConnectBlockTemplate(block); err != nil {
		return nil, err
	}

	log.Debugf("Created new block template (%d transactions, %d in "+
		"fees, %d signature operations cost, %d weight, target difficulty "+
		"%064x)", len(msgBlock.Transactions), totalFees, blockSigOpCost,
		blockWeight, blockchain.CompactToBig(msgBlock.Header.Bits))

	return &BlockTemplate{
		Block:             &msgBlock,
		Fees:              txFees,
		SigOpCosts:        txSigOpCosts,
		Height:            nextBlockHeight,
		ValidPayAddress:   payToAddress != nil,
		WitnessCommitment: witnessCommitment,
	}, nil
}

// 给打包好的区块盖个「SEGWIT 防伪章」。
func AddWitnessCommitment(coinbaseTx *core.Tx, blockTxns []*core.Tx) []byte {
	var witnessNonce [blockchain.CoinbaseWitnessDataLen]byte
	coinbaseTx.MsgTx().TxIn[0].Witness = core.TxWitness{witnessNonce[:]}
	witnessMerkleRoot := blockchain.CalcMerkleRoot(blockTxns, true)
	var witnessPreimage [64]byte
	copy(witnessPreimage[:32], witnessMerkleRoot[:])
	copy(witnessPreimage[32:], witnessNonce[:])
	witnessCommitment := chainhash.DoubleHashB(witnessPreimage[:])
	witnessScript := append(blockchain.WitnessMagicBytes, witnessCommitment...)
	commitmentOutput := &core.TxOut{
		Value:    0,
		PkScript: witnessScript,
	}
	coinbaseTx.MsgTx().TxOut = append(coinbaseTx.MsgTx().TxOut,
		commitmentOutput)
	return witnessCommitment
}

func (g *BlkTmplGenerator) BestSnapshot() *blockchain.BestState {
	return g.chain.BestSnapshot()
}

func (g *BlkTmplGenerator) TxSource() TxSource {
	return g.txSource
}

func (g *BlkTmplGenerator) UpdateExtraNonce(msgBlock *core.MsgBlock, blockHeight int32, extraNonce uint64) error {
	coinbaseScript, err := standardCoinbaseScript(blockHeight, extraNonce)
	if err != nil {
		return err
	}
	if len(coinbaseScript) > blockchain.MaxCoinbaseScriptLen {
		return fmt.Errorf("coinbase transaction script length "+
			"of %d is out of range (min: %d, max: %d)",
			len(coinbaseScript), blockchain.MinCoinbaseScriptLen,
			blockchain.MaxCoinbaseScriptLen)
	}
	msgBlock.Transactions[0].TxIn[0].SignatureScript = coinbaseScript

	// TODO(davec): A btcutil.Block should use saved in the state to avoid
	// recalculating all of the other transaction hashes.
	// block.Transactions[0].InvalidateCache()

	// Recalculate the merkle root with the updated extra nonce.
	block := core.NewBlock(msgBlock)
	merkleRoot := blockchain.CalcMerkleRoot(block.Transactions(), false)
	msgBlock.Header.MerkleRoot = merkleRoot
	return nil
}

func (g *BlkTmplGenerator) UpdateBlockTime(msgBlock *core.MsgBlock, blockHeight int32) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the chain consensus
	// rules.
	newTime := medianAdjustedTime(g.chain.BestSnapshot(), g.timeSource)
	msgBlock.Header.Timestamp = newTime.Unix()

	// Recalculate the difficulty if running on a network that requires it.
	if g.chainParams.ReduceMinDifficulty {
		difficulty, err := g.chain.CalcNextRequiredDifficulty(blockHeight)
		if err != nil {
			return err
		}
		msgBlock.Header.Bits = difficulty
	}
	return nil
}

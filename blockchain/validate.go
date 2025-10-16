package blockchain

import (
	"bitcoin/chaincfg"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/txscript"
	"fmt"
	"math"
	"math/big"
	"runtime"
	"time"
)

const (
	// MaxTimeOffsetSeconds is the maximum number of seconds a block time
	// is allowed to be ahead of the current time.  This is currently 2
	// hours.
	MaxTimeOffsetSeconds = 2 * 60 * 60

	// MinCoinbaseScriptLen is the minimum length a coinbase script can be.
	MinCoinbaseScriptLen = 2

	// MaxCoinbaseScriptLen is the maximum length a coinbase script can be.
	MaxCoinbaseScriptLen = 100

	// medianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	medianTimeBlocks = 11

	// serializedHeightVersion is the block version which changed block
	// coinbases to start with the serialized block height.
	serializedHeightVersion = 2

	// baseSubsidy is the starting subsidy amount for mined blocks.  This
	// value is halved every SubsidyHalvingInterval blocks.
	baseSubsidy = 50 * chaincfg.SatoshiPerBitcoin

	// coinbaseHeightAllocSize is the amount of bytes that the
	// ScriptBuilder will allocate when validating the coinbase height.
	coinbaseHeightAllocSize = 5

	// maxTimeWarp is a maximum number of seconds that the timestamp of the first
	// block of a difficulty adjustment period is allowed to
	// be earlier than the last block of the previous period (BIP94).
	maxTimeWarp = 600 * time.Second
)

type txValidator struct {
	validateChan chan *txValidateItem
	quitChan     chan struct{}
	resultChan   chan error
	utxoView     *UtxoViewpoint
	flags        txscript.ScriptFlags
	sigCache     *txscript.SigCache
	hashCache    *txscript.HashCache
}

type txValidateItem struct {
	txInIndex int
	txIn      *core.TxIn
	tx        *core.Tx
	sigHashes *txscript.TxSigHashes
}

func newTxValidator(utxoView *UtxoViewpoint, flags txscript.ScriptFlags,
	sigCache *txscript.SigCache, hashCache *txscript.HashCache) *txValidator {
	return &txValidator{
		validateChan: make(chan *txValidateItem),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoView:     utxoView,
		sigCache:     sigCache,
		hashCache:    hashCache,
		flags:        flags,
	}
}

func (v *txValidator) Validate(items []*txValidateItem) error {
	if len(items) == 0 {
		return nil
	}

	// Limit the number of goroutines to do script validation based on the
	// number of processor cores.  This helps ensure the system stays
	// reasonably responsive under heavy load.
	maxGoRoutines := runtime.NumCPU() * 3
	if maxGoRoutines <= 0 {
		maxGoRoutines = 1
	}
	if maxGoRoutines > len(items) {
		maxGoRoutines = len(items)
	}

	// Start up validation handlers that are used to asynchronously
	// validate each transaction input.
	for i := 0; i < maxGoRoutines; i++ {
		go v.validateHandler()
	}

	// Validate each of the inputs.  The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// input had the validation error.
	numInputs := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numInputs {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *txValidateItem
		var item *txValidateItem
		if currentItem < numInputs {
			validateChan = v.validateChan
			item = items[currentItem]
		}

		select {
		case validateChan <- item:
			currentItem++

		case err := <-v.resultChan:
			processedItems++
			if err != nil {
				close(v.quitChan)
				return err
			}
		}
	}

	close(v.quitChan)
	return nil
}

func (v *txValidator) validateHandler() {
out:
	for {
		select {
		case txVI := <-v.validateChan:
			// Ensure the referenced input utxo is available.
			txIn := txVI.txIn
			utxo := v.utxoView.LookupEntry(txIn.PreviousOutPoint)
			if utxo == nil {
				str := fmt.Sprintf("unable to find unspent "+
					"output %v referenced from "+
					"transaction %s:%d",
					txIn.PreviousOutPoint, txVI.tx.Hash(),
					txVI.txInIndex)
				err := ruleError(ErrMissingTxOut, str)
				v.sendResult(err)
				break out
			}

			// Create a new script engine for the script pair.
			sigScript := txIn.SignatureScript
			witness := txIn.Witness
			pkScript := utxo.PkScript()
			inputAmount := utxo.Amount()
			vm, err := txscript.NewEngine(
				pkScript, txVI.tx.MsgTx(), txVI.txInIndex,
				v.flags, v.sigCache, txVI.sigHashes,
				inputAmount, v.utxoView,
			)
			if err != nil {
				str := fmt.Sprintf("failed to parse input "+
					"%s:%d which references output %v - "+
					"%v (input witness %x, input script "+
					"bytes %x, prev output script bytes %x)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPoint, err, witness,
					sigScript, pkScript)
				err := ruleError(ErrScriptMalformed, str)
				v.sendResult(err)
				break out
			}

			// Execute the script pair.
			if err := vm.Execute(); err != nil {
				str := fmt.Sprintf("failed to validate input "+
					"%s:%d which references output %v - "+
					"%v (input witness %x, input script "+
					"bytes %x, prev output script bytes %x)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPoint, err, witness,
					sigScript, pkScript)
				err := ruleError(ErrScriptValidation, str)
				v.sendResult(err)
				break out
			}

			// Validation succeeded.
			v.sendResult(nil)

		case <-v.quitChan:
			break out
		}
	}
}

func (v *txValidator) sendResult(result error) {
	select {
	case v.resultChan <- result:
	case <-v.quitChan:
	}
}

// SpentTxOut 就是“已经被花掉的交易输出”在数据库里留下的一张小抄（minimal snapshot）。
// 它存在的唯一目的是：回滚（reorg/undo）时能迅速把这笔输出复活成 UTXO，而不必再去磁盘里重扫整条交易。
// 1. 什么时候生成
// 当某笔交易真正把某个 UTXO 标记为“已花费”时，
// 节点会把这个 UTXO 的原始数据（金额、脚本、高度、是否 coinbase 等）
// 打包成一个 SpentTxOut，追加到 撤销数据库（undo database）。
type SpentTxOut struct {
	Amount     int64
	PkScript   []byte
	Height     int32
	IsCoinBase bool
}

// 接入主链
func (b *BlockChain) checkConnectBlock(block *core.Block, view *UtxoViewpoint, stxos *[]SpentTxOut) error {
	log.Infof("将视图连接到区块")
	//	防止有人尝试花掉创世块里的 50 BTC。
	if block.BlockHash.IsEqual(b.chainParams.GenesisHash) {
		str := "the coinbase for the genesis block is not spendable"
		return ruleError(ErrMissingTxOut, str)
	}
	//这一步是「链状态一致性断言」：
	//把待接入区块的 PrevBlock（父区块哈希） 取出来。
	//把它跟当前 UTXO 视图 view 的最佳哈希 view.BestHash() 做对比。
	//如果两者 不相等，说明两件事：
	//调用者给错了 view——它并不是“父区块对应的 UTXO 快照”。
	//后续所有验证（交易输入、奖励、脚本）都会基于错误的状态，结果不可信。
	//于是直接 panic 级别的 AssertError 抛出，强制终止程序，避免任何潜在的数据不一致。
	//一句话：确保本次验证的 UTXO 视图正好对准父区块，防止用“旧地图”去走“新路线”。
	parentHash := &block.MsgBlock().Header.PrevBlock
	if !view.BestHash().IsEqual(parentHash) {
		return AssertError(fmt.Sprintf("inconsistent view when "+
			"checking block connection: best hash is %v instead "+
			"of expected %v", view.BestHash(), parentHash))
	}
	err := view.fetchInputUtxos(b.utxoCache, block)
	if err != nil {
		return err
	}

	transactions := block.Transactions()
	//区块级签名操作计数器
	totalSigOpCost := 0
	for i, tx := range transactions {
		sigOpCost, err := GetSigOpCost(tx, i == 0, view)
		if err != nil {
			return err
		}
		lastSigOpCost := totalSigOpCost
		totalSigOpCost += sigOpCost
		if totalSigOpCost < lastSigOpCost || totalSigOpCost > MaxBlockSigOpsCost {
			str := fmt.Sprintf("block contains too many "+
				"signature operations - got %v, max %v",
				totalSigOpCost, MaxBlockSigOpsCost)
			return ruleError(ErrTooManySigOps, str)
		}
	}
	var totalFees int64
	for _, tx := range transactions {
		txFee, err := CheckTransactionInputs(tx, block.BlockHeight, view, b.chainParams)
		if err != nil {
			return err
		}

		// Sum the total fees and ensure we don't overflow the
		// accumulator.
		lastTotalFees := totalFees
		totalFees += txFee
		if totalFees < lastTotalFees {
			return ruleError(ErrBadFees, "total fees for block "+
				"overflows accumulator")
		}
		err = view.connectTransaction(tx, block.BlockHeight, stxos)
		if err != nil {
			return err
		}
	}
	var totalSatoshiOut int64
	for _, txOut := range transactions[0].MsgTx().TxOut {
		totalSatoshiOut += txOut.Value
	}
	expectedSatoshiOut := CalcBlockSubsidy(block.BlockHeight, b.chainParams) + totalFees
	if totalSatoshiOut > expectedSatoshiOut {
		str := fmt.Sprintf("coinbase transaction for block pays %v "+
			"which is more than expected value of %v",
			totalSatoshiOut, expectedSatoshiOut)
		return ruleError(ErrBadCoinbaseValue, str)
	}
	checkpoint := b.LatestCheckpoint()
	runScripts := true
	if checkpoint != nil && block.Height() <= checkpoint.Height {
		runScripts = false
	}
	log.Infof("是否运行脚本%s", runScripts)
	var scriptFlags txscript.ScriptFlags
	enforceBIP0016 := block.BlockHeader().Timestamp >= txscript.Bip16Activation.Unix()

	if enforceBIP0016 {
		scriptFlags |= txscript.ScriptBip16
	}

	//这段代码是一个**“跳过脚本验证”优化**：
	//checkpoint 是官方硬编码的“可信快照”（高度 + 哈希）。
	//如果当前区块高度 ≤ 最新 checkpoint 的高度，说明该区块 已被 checkpoint 覆盖。
	//此时 直接把 runScripts 设为 false，后续就不会执行昂贵的 ECDSA/Schnorr 脚本验证。
	//安全性仍由 checkpoint 保证——任何数据篡改都会在下一次 checkpoint 校验时被发现。
	//效果：
	//对早期区块省去大量 CPU 时间，节点同步速度显著提升。
	//检查区块里每笔交易的所有输入是否已满足相对时间锁（sequence lock），不满足就拒绝整区块。

	if runScripts {
		err := checkBlockScripts(block, view, scriptFlags, b.sigCache, b.hashCache)
		if err != nil {
			return err
		}
		log.Infof("检查交易脚本成功")
	}
	view.SetBestHash(block.Hash())
	return nil
}

func (b *BlockChain) CheckConnectBlockTemplate(block *core.Block) error {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	return nil
}

func checkBlockScripts(block *core.Block, utxoView *UtxoViewpoint,
	scriptFlags txscript.ScriptFlags, sigCache *txscript.SigCache,
	hashCache *txscript.HashCache) error {
	segwitActive := scriptFlags&txscript.ScriptVerifyWitness == txscript.ScriptVerifyWitness
	numInputs := 0
	for _, tx := range block.Transactions() {
		numInputs += len(tx.MsgTx().TxIn)
	}
	txValItems := make([]*txValidateItem, 0, numInputs)
	for _, tx := range block.Transactions() {
		hash := tx.Hash()
		if segwitActive && tx.HasWitness() && hashCache != nil &&
			!hashCache.ContainsHashes(hash) {

			hashCache.AddSigHashes(tx.MsgTx(), utxoView)
		}
		var cachedHashes *txscript.TxSigHashes
		if segwitActive && tx.HasWitness() {
			if hashCache != nil {
				cachedHashes, _ = hashCache.GetSigHashes(hash)
			} else {
				cachedHashes = txscript.NewTxSigHashes(
					tx.MsgTx(), utxoView,
				)
			}
		}
		for txInIdx, txIn := range tx.MsgTx().TxIn {
			if txIn.PreviousOutPoint.Index == math.MaxUint32 {
				continue
			}

			txVI := &txValidateItem{
				txInIndex: txInIdx,
				txIn:      txIn,
				tx:        tx,
				sigHashes: cachedHashes,
			}
			txValItems = append(txValItems, txVI)
		}
	}

	validator := newTxValidator(utxoView, scriptFlags, sigCache, hashCache)
	start := time.Now()
	if err := validator.Validate(txValItems); err != nil {
		return err
	}
	elapsed := time.Since(start)
	log.Tracef("block %v took %v to verify", block.Hash(), elapsed)
	if segwitActive && hashCache != nil {
		for _, tx := range block.Transactions() {
			if tx.MsgTx().HasWitness() {
				hashCache.PurgeSigHashes(tx.Hash())
			}
		}
	}
	return nil
}

func checkBlockSanity(block *core.Block, powLimit *big.Int, timeSource MedianTimeSource, flags BehaviorFlags) error {
	msgBlock := block.MsgBlock()
	header := &msgBlock.Header
	err := CheckBlockHeaderSanity(header, powLimit, timeSource, flags)
	if err != nil {
		return err
	}

	// A block must have at least one transaction.
	numTx := len(msgBlock.Transactions)
	if numTx == 0 {
		return ruleError(ErrNoTransactions, "block does not contain "+
			"any transactions")
	}

	// A block must not have more transactions than the max block payload or
	// else it is certainly over the weight limit.
	if numTx > MaxBlockBaseSize {
		str := fmt.Sprintf("block contains too many transactions - "+
			"got %d, max %d", numTx, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// A block must not exceed the maximum allowed block payload when
	// serialized.
	serializedSize := msgBlock.SerializeSizeStripped()
	if serializedSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", serializedSize, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// The first transaction in a block must be a coinbase.
	transactions := block.Transactions()
	if !IsCoinBase(transactions[0]) {
		return ruleError(ErrFirstTxNotCoinbase, "first transaction in "+
			"block is not a coinbase")
	}

	// A block must not have more than one coinbase.
	for i, tx := range transactions[1:] {
		if IsCoinBase(tx) {
			str := fmt.Sprintf("block contains second coinbase at "+
				"index %d", i+1)
			return ruleError(ErrMultipleCoinbases, str)
		}
	}

	// Do some preliminary checks on each transaction to ensure they are
	// sane before continuing.
	for _, tx := range transactions {
		err := CheckTransactionSanity(tx)
		if err != nil {
			return err
		}
	}

	// Build merkle tree and ensure the calculated merkle root matches the
	// entry in the block header.  This also has the effect of caching all
	// of the transaction hashes in the block to speed up future hash
	// checks.  Bitcoind builds the tree here and checks the merkle root
	// after the following checks, but there is no reason not to check the
	// merkle root matches here.
	calcMerkleRoot := CalcMerkleRoot(block.Transactions(), false)
	if !header.MerkleRoot.IsEqual(&calcMerkleRoot) {
		str := fmt.Sprintf("block merkle root is invalid - block "+
			"header indicates %v, but calculated value is %v",
			header.MerkleRoot, calcMerkleRoot)
		return ruleError(ErrBadMerkleRoot, str)
	}

	// Check for duplicate transactions.  This check will be fairly quick
	// since the transaction hashes are already cached due to building the
	// merkle tree above.
	existingTxHashes := make(map[chainhash.Hash]struct{})
	for _, tx := range transactions {
		hash := tx.Hash()
		if _, exists := existingTxHashes[*hash]; exists {
			str := fmt.Sprintf("block contains duplicate "+
				"transaction %v", hash)
			return ruleError(ErrDuplicateTx, str)
		}
		existingTxHashes[*hash] = struct{}{}
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.
	totalSigOps := 0
	for _, tx := range transactions {
		// We could potentially overflow the accumulator so check for
		// overflow.
		lastSigOps := totalSigOps
		totalSigOps += (CountSigOps(tx) * WitnessScaleFactor)
		if totalSigOps < lastSigOps || totalSigOps > MaxBlockSigOpsCost {
			str := fmt.Sprintf("block contains too many signature "+
				"operations - got %v, max %v", totalSigOps,
				MaxBlockSigOpsCost)
			return ruleError(ErrTooManySigOps, str)
		}
	}

	return nil
}

// 这段代码是区块链中处理区块接受逻辑的核心函数 maybeAcceptBlock，其主要作用是验证区块并将其纳入区块链体系（可能作为主链或侧链）。
// 1. 验证前序区块的有效性
// 2. 高度连续性
// 3. 验证区块的上下文合法性 用  验证区块在区块链中的 “上下文有效性”，主要包括：
// 区块时间戳不能早于前序区块（或符合特定时间规则，防止时间回溯攻击）。
// 区块难度目标符合当前网络的难度调整规则（确保工作量证明有效）。
// 其他与区块链位置相关的验证（如是否符合区块版本规则等）。
// 若验证失败，直接返回错误，拒绝接受区块。
// 4. 将区块存入数据库 即使区块最终可能无法接入主链，仍先将其存入数据库。原因是：
// 区块已通过工作量证明（PoW）和基础合法性校验，攻击者难以生成大量此类区块填充磁盘（成本极高）。
// 分离 “区块下载” 和 “链上连接” 逻辑，提升性能（下载轻量，连接复杂）。
// 保留无效 / 侧链区块供后续分析（如分叉链研究）。
// 6. 创建并索引区块节点
// 7.连接到最佳链（链选择） 核心步骤：根据 “工作量证明最大” 原则，将新节点连接到最佳链（可能是主链或侧链）。
func (b *BlockChain) maybeAcceptBlock(block *core.Block, flags BehaviorFlags) (bool, error) {
	err1 := b.checkBlockContext(block, flags)
	if err1 != nil {
		return false, err1
	}
	//保存区块
	err2 := b.SaveBlock(block)
	log.Infof("保存区块完成")
	if err2 != nil {
		return false, err2
	}
	go func() {
		b.sendNotification(NTBlockAccepted, block)
	}()

	// 3. 核心数据准备
	blockHash := block.Hash()                   // 当前区块哈希
	blockHeader := block.GetHeader()            // 当前区块头
	parentHash := blockHeader.ParentHash()      // 当前区块的父哈希
	blockHeight := block.Height()               // 当前区块高度（假设头中含高度字段，int32类型）
	currentBlockBody := block.GetBody()         // 假设获取到区块体
	currentWork := currentBlockBody.ChainWork() // ChainWork() 返回 *big.Int

	mainLatestHash, err := b.GetMainLatestHash() // 主链最新区块哈希
	if err != nil {
		return false, fmt.Errorf("获取主链最新哈希失败: %w", err)
	}
	mainChainWork, err := b.GetMainChainWork() // 主链当前累计工作量
	if err != nil {
		return false, fmt.Errorf("查询主链累计工作量出错: %w", err)
	}

	// 5. 判断是否为主链延续
	isMainChainExtension := parentHash.IsEqual(&mainLatestHash)

	// 6. 主链更新判断逻辑
	if isMainChainExtension {
		log.Infof("是主链的延续")
		if err := b.ApplyToMainChain(block); err != nil {
			return false, fmt.Errorf("应用到主链失败: %w", err)
		}
		// 6.1 是主链直接延续，直接更新主链
		if err := b.UpdateMainChain(blockHash, currentWork, blockHeight); err != nil {
			return false, fmt.Errorf("更新主链失败: %w", err)
		}
		if err := b.UpdateMainChainBestState(block, blockHeader, blockHash, currentWork, blockHeight); err != nil {
			return false, fmt.Errorf("更新主链最新快照: %w", err)
		}
		go func() {
			b.sendNotification(NTBlockConnected, block)
		}()
		return true, nil
	}

	log.Infof("不是主链的延续")

	workCmp := currentWork.Cmp(mainChainWork)
	switch workCmp {
	case 1:
		log.Infof("当前链的工作量更大")
		// 当前链工作量更大，执行链重组
		if err := b.reorganizeChain(block); err != nil {
			return false, fmt.Errorf("链重组失败: %w", err)
		}
		log.Infof("重组完成")
		if err := b.ApplyToMainChain(block); err != nil {
			return false, fmt.Errorf("应用到主链失败: %w", err)
		}
		if err := b.UpdateMainChain(blockHash, currentWork, blockHeight); err != nil {
			return false, fmt.Errorf("更新主链状态失败: %w", err)
		}
		if err := b.UpdateMainChainBestState(block, blockHeader, blockHash, currentWork, blockHeight); err != nil {
			return false, fmt.Errorf("更新主链最新快照: %w", err)
		}
		log.Infof("链重组完成，新主链高度: %d", blockHeight)
		return true, nil
	case 0:
		// 工作量相等，保持原主链
		log.Infof("发现工作量相同的链，保持当前主链")
		return false, nil
	case -1:
		// 工作量更小，作为侧链
		log.Infof("侧链区块已保存，高度: %d", blockHeight)
		return false, nil
	}
	return false, nil
}

func CheckBlockHeaderSanity(header *core.BlockHeader, powLimit *big.Int,
	timeSource MedianTimeSource, flags BehaviorFlags) error {

	// Ensure the proof of work bits in the block header is in min/max range
	// and the block hash is less than the target value described by the
	// bits.
	err := checkProofOfWork(header, powLimit, flags)
	if err != nil {
		return err
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := timeSource.AdjustedTime().Add(time.Second * MaxTimeOffsetSeconds)

	if header.Timestamp > (maxTimestamp.Unix()) {
		str := fmt.Sprintf("block timestamp of %v is too far in the "+
			"future", header.Timestamp)
		return ruleError(ErrTimeTooNew, str)
	}

	return nil
}

func checkProofOfWork(header *core.BlockHeader, powLimit *big.Int, flags BehaviorFlags) error {
	// The target difficulty must be larger than zero.
	target := CompactToBig(header.Bits)
	if target.Sign() <= 0 {
		str := fmt.Sprintf("block target difficulty of %064x is too low",
			target)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The target difficulty must be less than the maximum allowed.
	if target.Cmp(powLimit) > 0 {
		str := fmt.Sprintf("block target difficulty of %064x is "+
			"higher than max of %064x", target, powLimit)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The block hash must be less than the claimed target unless the flag
	// to avoid proof of work checks is set.
	if flags&BFNoPoWCheck != BFNoPoWCheck {
		// The block hash must be less than the claimed target.
		hash := header.BlockHash()
		hashNum := HashToBig(&hash)
		if hashNum.Cmp(target) > 0 {
			log.Infof("检查失败")
			str := fmt.Sprintf("block hash of %064x is higher than expected max of %064x", hashNum, target)
			return ruleError(ErrHighHash, str)
		}
	}
	return nil
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckTransactionSanity(tx *core.Tx) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	// A transaction must have at least one output.
	if len(msgTx.TxOut) == 0 {
		return ruleError(ErrNoTxOutputs, "transaction has no outputs")
	}

	// A transaction must not exceed the maximum allowed block payload when
	// serialized.
	serializedTxSize := tx.MsgTx().SerializeSizeStripped()
	if serializedTxSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized transaction is too big - got "+
			"%d, max %d", serializedTxSize, MaxBlockBaseSize)
		return ruleError(ErrTxTooBig, str)
	}

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a satoshi.  One bitcoin is a quantity of satoshi as defined by the
	// SatoshiPerBitcoin constant.
	var totalSatoshi int64
	for _, txOut := range msgTx.TxOut {
		satoshi := txOut.Value
		if satoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", satoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if satoshi > chaincfg.MaxSatoshi {
			str := fmt.Sprintf("transaction output value is "+
				"higher than max allowed value: %v > %v ",
				satoshi, chaincfg.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}

		// Two's complement int64 overflow guarantees that any overflow
		// is detected and reported.  This is impossible for Bitcoin, but
		// perhaps possible if an alt increases the total money supply.
		totalSatoshi += satoshi
		if totalSatoshi < 0 {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs exceeds max allowed value of %v",
				chaincfg.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if totalSatoshi > chaincfg.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs is %v which is higher than max "+
				"allowed value of %v", totalSatoshi,
				chaincfg.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[core.OutPoint]struct{})
	for _, txIn := range msgTx.TxIn {
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return ruleError(ErrDuplicateTxInputs, "transaction "+
				"contains duplicate inputs")
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Coinbase script length must be between min and max length.
	if IsCoinBase(tx) {
		slen := len(msgTx.TxIn[0].SignatureScript)
		if slen < MinCoinbaseScriptLen || slen > MaxCoinbaseScriptLen {
			str := fmt.Sprintf("coinbase transaction script length "+
				"of %d is out of range (min: %d, max: %d)",
				slen, MinCoinbaseScriptLen, MaxCoinbaseScriptLen)
			return ruleError(ErrBadCoinbaseScriptLen, str)
		}
	} else {
		// Previous transaction outputs referenced by the inputs to this
		// transaction must not be null.
		for _, txIn := range msgTx.TxIn {
			if isNullOutpoint(&txIn.PreviousOutPoint) {
				return ruleError(ErrBadTxInput, "transaction "+
					"input refers to previous output that "+
					"is null")
			}
		}
	}

	return nil
}

func isNullOutpoint(outpoint *core.OutPoint) bool {
	if outpoint.Index == math.MaxUint32 && outpoint.Hash == zeroHash {
		return true
	}
	return false
}

func SequenceLockActive(sequenceLock *SequenceLock, blockHeight int32,
	medianTimePast time.Time) bool {

	// If either the seconds, or height relative-lock time has not yet
	// reached, then the transaction is not yet mature according to its
	// sequence locks.
	if sequenceLock.Seconds >= medianTimePast.Unix() ||
		sequenceLock.BlockHeight >= blockHeight {
		return false
	}

	return true
}

func (b *BlockChain) ChainParams() *core.Params {
	return b.chainParams
}

// blocksPerRetarget 是区块链系统中用于定义难度调整周期的核心参数，其值为 int32 类型，含义是 “每隔多少个区块需要进行一次挖矿难度调整”。
func (b *BlockChain) BlocksPerRetarget() int32 {
	return b.blocksPerRetarget
}

func (b *BlockChain) MinRetargetTimespan() int64 {
	return b.minRetargetTimespan
}

func (b *BlockChain) MaxRetargetTimespan() int64 {
	return b.maxRetargetTimespan
}

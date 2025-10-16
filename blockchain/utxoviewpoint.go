// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bitcoin/txscript"
	"fmt"
)

// txoFlags is a bitmask defining additional information and state for a
// transaction output in a utxo view.

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *UtxoEntry) isModified() bool {
	return entry.packedFlags&tfModified == tfModified
}

// isFresh returns whether or not it's certain the output has never previously
// been stored in the database.
func (entry *UtxoEntry) isFresh() bool {
	return entry.packedFlags&tfFresh == tfFresh
}

// memoryUsage returns the memory usage in bytes of for the utxo entry.
// It returns 0 for a nil entry.
func (entry *UtxoEntry) memoryUsage() uint64 {
	if entry == nil {
		return 0
	}

	return baseEntrySize + uint64(cap(entry.pkScript))
}

// IsCoinBase returns whether or not the output was contained in a coinbase
// transaction.
func (entry *UtxoEntry) IsCoinBase() bool {
	return entry.packedFlags&tfCoinBase == tfCoinBase
}

// BlockHeight returns the height of the block containing the output.
func (entry *UtxoEntry) BlockHeight() int32 {
	return entry.blockHeight
}

func (entry *UtxoEntry) PackedFlags() uint8 {
	return uint8(txoFlags(entry.packedFlags))
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (entry *UtxoEntry) IsSpent() bool {
	return entry.packedFlags&tfSpent == tfSpent
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *UtxoEntry) Spend() {
	// Nothing to do if the output is already spent.
	if entry.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= tfSpent | tfModified
}

// Amount returns the amount of the output.
func (entry *UtxoEntry) Amount() int64 {
	return entry.amount
}

// PkScript returns the public key script for the output.
func (entry *UtxoEntry) PkScript() []byte {
	return entry.pkScript
}

// Clone returns a shallow copy of the utxo entry.
func (entry *UtxoEntry) Clone() *UtxoEntry {
	if entry == nil {
		return nil
	}

	return &UtxoEntry{
		amount:      entry.amount,
		pkScript:    entry.pkScript,
		blockHeight: entry.blockHeight,
		packedFlags: entry.packedFlags,
	}
}

// NewUtxoEntry returns a new UtxoEntry built from the arguments.
func NewUtxoEntry(
	txOut *core.TxOut, blockHeight int32, isCoinbase bool) *UtxoEntry {
	var cbFlag txoFlags
	if isCoinbase {
		cbFlag |= tfCoinBase
	}

	return &UtxoEntry{
		amount:      txOut.Value,
		pkScript:    txOut.PkScript,
		blockHeight: blockHeight,
		packedFlags: cbFlag,
	}
}

// UtxoViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.
type UtxoViewpoint struct {
	entries  map[core.OutPoint]*UtxoEntry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// represents.
func (view *UtxoViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// represents.
func (view *UtxoViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *UtxoViewpoint) LookupEntry(outpoint core.OutPoint) *UtxoEntry {
	return view.entries[outpoint]
}

// FetchPrevOutput fetches the previous output referenced by the passed
// outpoint. This is identical to the LookupEntry method, but it returns a
// wire.TxOut instead.
//
// NOTE: This is an implementation of the txscript.PrevOutputFetcher interface.
func (view *UtxoViewpoint) FetchPrevOutput(op core.OutPoint) *core.TxOut {
	prevOut := view.entries[op]
	if prevOut == nil {
		return nil
	}

	return &core.TxOut{
		Value:    prevOut.amount,
		PkScript: prevOut.PkScript(),
	}
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *UtxoViewpoint) addTxOut(outpoint core.OutPoint, txOut *core.TxOut, isCoinBase bool, blockHeight int32) {
	// Don't add provably unspendable outputs.
	if txscript.IsUnspendable(txOut.PkScript) {
		return
	}

	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	entry := view.LookupEntry(outpoint)
	if entry == nil {
		entry = new(UtxoEntry)
		view.entries[outpoint] = entry
	}

	entry.amount = txOut.Value
	entry.pkScript = txOut.PkScript
	entry.blockHeight = blockHeight
	entry.packedFlags = tfFresh | tfModified
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}
}

// AddTxOut adds the specified output of the passed transaction to the view if
// it exists and is not provably unspendable.  When the view already has an
// entry for the output, it will be marked unspent.  All fields will be updated
// for existing entries since it's possible it has changed during a reorg.
func (view *UtxoViewpoint) AddTxOut(tx *core.Tx, txOutIdx uint32, blockHeight int32) {
	// Can't add an output for an out of bounds index.
	if txOutIdx >= uint32(len(tx.MsgTx().TxOut)) {
		return
	}

	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	prevOut := core.OutPoint{Hash: *tx.Hash(), Index: txOutIdx}
	txOut := tx.MsgTx().TxOut[txOutIdx]
	view.addTxOut(prevOut, txOut, IsCoinBase(tx), blockHeight)
}

// AddTxOuts adds all outputs in the passed transaction which are not provably
// unspendable to the view.  When the view already has entries for any of the
// outputs, they are simply marked unspent.  All fields will be updated for
// existing entries since it's possible it has changed during a reorg.
func (view *UtxoViewpoint) AddTxOuts(tx *core.Tx, blockHeight int32) {
	// Loop all of the transaction outputs and add those which are not
	// provably unspendable.
	isCoinBase := IsCoinBase(tx)
	prevOut := core.OutPoint{Hash: *tx.Hash()}
	for txOutIdx, txOut := range tx.MsgTx().TxOut {
		// Update existing entries.  All fields are updated because it's
		// possible (although extremely unlikely) that the existing
		// entry is being replaced by a different transaction with the
		// same hash.  This is allowed so long as the previous
		// transaction is fully spent.
		prevOut.Index = uint32(txOutIdx)
		view.addTxOut(prevOut, txOut, isCoinBase, blockHeight)
	}
}

// ✅ “连接交易”
// 含义：
// 将区块中的所有交易“应用”到当前 UTXO 视图中，即：
// 标记所有交易输入所引用的 UTXO 为“已花费”（spent）。
// 添加所有交易输出作为新的 UTXO。
// 更新视图的“最佳区块哈希”为该区块的哈希。
// 用在哪里：
// 当新区块被接受为主链的一部分时。
// 当验证一个区块是否有效时（模拟连接）。
// 在链重组（reorg）中，连接新链的区块时。
func (view *UtxoViewpoint) connectTransaction(tx *core.Tx, blockHeight int32, stxos *[]SpentTxOut) error {
	log.Infof("将视图连接到交易...................")
	// Coinbase transactions don't have any inputs to spend.
	if IsCoinBase(tx) {
		//coinBase没有输入
		log.Infof("是一个coinbase交易%s", tx.Hash())
		// Add the transaction's outputs as available utxos.
		view.AddTxOuts(tx, blockHeight)
		return nil
	}
	log.Infof("是一个正常转账交易%s  输入长度%d", tx.Hash(), len(tx.MsgTx().TxIn))
	// Spend the referenced utxos by marking them spent in the view and,
	// if a slice was provided for the spent txout details, append an entry
	// to it.

	for _, txIn := range tx.MsgTx().TxIn {
		// Ensure the referenced utxo exists in the view.  This should
		// never happen unless there is a bug is introduced in the code.
		entry := view.entries[txIn.PreviousOutPoint]
		if entry == nil {
			return AssertError(fmt.Sprintf("view missing input %v",
				txIn.PreviousOutPoint))
		}

		// Only create the stxo details if requested.
		if stxos != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentTxOut{
				Amount:     entry.Amount(),
				PkScript:   entry.PkScript(),
				Height:     entry.BlockHeight(),
				IsCoinBase: entry.IsCoinBase(),
			}
			*stxos = append(*stxos, stxo)
		}
		entry.Spend()
		log.Infof("将交易引用的UTXO设置为已经花费%s", entry.packedFlags)
	}
	// Add the transaction's outputs as available utxos.
	view.AddTxOuts(tx, blockHeight)
	return nil
}

// ✅ “不连接交易”（disconnectTransactions）
// 含义：
// 将区块中的所有交易“撤销”或“回滚”，即：
// 将交易输入所引用的 UTXO 恢复为“未花费”（unspent）。
// 删除该区块中所有交易创建的 UTXO。
// 更新视图的“最佳区块哈希”为该区块的前一个区块的哈希。
// 用在哪里：
// 在链重组（reorg）中，断开旧链的区块时。
// 当需要回滚一个已连接的区块（例如发现无效区块时）。
func (view *UtxoViewpoint) connectTransactions(block *core.Block, stxos *[]SpentTxOut) error {
	for _, tx := range block.Transactions() {
		err := view.connectTransaction(tx, block.Height(), stxos)
		if err != nil {
			return err
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}

// fetchEntryByHash attempts to find any available utxo for the given hash by
// searching the entire set of possible outputs for the given hash.  It checks
// the view first and then falls back to the database if needed.
func (view *UtxoViewpoint) fetchEntryByHash(db db.KeyValueStore, hash *chainhash.Hash) (*UtxoEntry, error) {
	// First attempt to find a utxo with the provided hash in the view.
	prevOut := core.OutPoint{Hash: *hash}
	for idx := uint32(0); idx < MaxOutputsPerBlock; idx++ {
		prevOut.Index = idx
		entry := view.LookupEntry(prevOut)
		if entry != nil {
			return entry, nil
		}
	}

	// Check the database since it doesn't exist in the view.  This will
	// often by the case since only specifically referenced utxos are loaded
	// into the view.
	var entry *UtxoEntry
	/*	err := db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = dbFetchUtxoEntryByHash(dbTx, hash)
		return err
	})*/
	return entry, nil
}

//	updates the view by removing all of the transactions
//
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
func (view *UtxoViewpoint) disconnectTransactions(db db.KeyValueStore, block *core.Block, stxos []SpentTxOut) error {
	// Sanity check the correct number of stxos are provided.
	if len(stxos) != countSpentOutputs(block) {
		return AssertError("disconnectTransactions called with bad " +
			"spent transaction out information")
	}

	// Loop backwards through all transactions so everything is unspent in
	// reverse order.  This is necessary since transactions later in a block
	// can spend from previous ones.
	stxoIdx := len(stxos) - 1
	transactions := block.Transactions()
	for txIdx := len(transactions) - 1; txIdx > -1; txIdx-- {
		tx := transactions[txIdx]

		// All entries will need to potentially be marked as a coinbase.
		var packedFlags txoFlags
		isCoinBase := txIdx == 0
		if isCoinBase {
			packedFlags |= tfCoinBase
		}

		// Mark all of the spendable outputs originally created by the
		// transaction as spent.  It is instructive to note that while
		// the outputs aren't actually being spent here, rather they no
		// longer exist, since a pruned utxo set is used, there is no
		// practical difference between a utxo that does not exist and
		// one that has been spent.
		//
		// When the utxo does not already exist in the view, add an
		// entry for it and then mark it spent.  This is done because
		// the code relies on its existence in the view in order to
		// signal modifications have happened.
		txHash := tx.Hash()
		prevOut := core.OutPoint{Hash: *txHash}
		for txOutIdx, txOut := range tx.MsgTx().TxOut {
			if txscript.IsUnspendable(txOut.PkScript) {
				continue
			}

			prevOut.Index = uint32(txOutIdx)
			entry := view.entries[prevOut]
			if entry == nil {
				entry = &UtxoEntry{
					amount:      txOut.Value,
					pkScript:    txOut.PkScript,
					blockHeight: block.Height(),
					packedFlags: packedFlags,
				}

				view.entries[prevOut] = entry
			}

			entry.Spend()
		}

		// Loop backwards through all of the transaction inputs (except
		// for the coinbase which has no inputs) and unspend the
		// referenced txos.  This is necessary to match the order of the
		// spent txout entries.
		if isCoinBase {
			continue
		}
		for txInIdx := len(tx.MsgTx().TxIn) - 1; txInIdx > -1; txInIdx-- {
			// Ensure the spent txout index is decremented to stay
			// in sync with the transaction input.
			stxo := &stxos[stxoIdx]
			stxoIdx--

			// When there is not already an entry for the referenced
			// output in the view, it means it was previously spent,
			// so create a new utxo entry in order to resurrect it.
			originOut := &tx.MsgTx().TxIn[txInIdx].PreviousOutPoint
			entry := view.entries[*originOut]
			if entry == nil {
				entry = new(UtxoEntry)
				view.entries[*originOut] = entry
			}

			// The legacy v1 spend journal format only stored the
			// coinbase flag and height when the output was the last
			// unspent output of the transaction.  As a result, when
			// the information is missing, search for it by scanning
			// all possible outputs of the transaction since it must
			// be in one of them.
			//
			// It should be noted that this is quite inefficient,
			// but it realistically will almost never run since all
			// new entries include the information for all outputs
			// and thus the only way this will be hit is if a long
			// enough reorg happens such that a block with the old
			// spend data is being disconnected.  The probability of
			// that in practice is extremely low to begin with and
			// becomes vanishingly small the more new blocks are
			// connected.  In the case of a fresh database that has
			// only ever run with the new v2 format, this code path
			// will never run.
			if stxo.Height == 0 {
				utxo, err := view.fetchEntryByHash(db, txHash)
				if err != nil {
					return err
				}
				if utxo == nil {
					return AssertError(fmt.Sprintf("unable "+
						"to resurrect legacy stxo %v",
						*originOut))
				}

				stxo.Height = utxo.BlockHeight()
				stxo.IsCoinBase = utxo.IsCoinBase()
			}

			// Restore the utxo using the stxo data from the spend
			// journal and mark it as modified.
			entry.amount = stxo.Amount
			entry.pkScript = stxo.PkScript
			entry.blockHeight = stxo.Height
			entry.packedFlags = tfModified
			if stxo.IsCoinBase {
				entry.packedFlags |= tfCoinBase
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view *UtxoViewpoint) RemoveEntry(outpoint core.OutPoint) {
	delete(view.entries, outpoint)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *UtxoViewpoint) Entries() map[core.OutPoint]*UtxoEntry {
	return view.entries
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *UtxoViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || (entry.isModified() && entry.IsSpent()) {
			delete(view.entries, outpoint)
			continue
		}
		entry.packedFlags ^= tfModified
	}
}

func (view *UtxoViewpoint) fetchUtxosFromCache(cache *utxoCache, outpoints []core.OutPoint) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 {
		return nil
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.  Any missing entries will be
	// fetched from the database and be cached.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	entries, err := cache.fetchEntries(outpoints)
	if err != nil {
		return err
	}
	for i, entry := range entries {
		view.entries[outpoints[i]] = entry.Clone()
	}
	return nil
}

func (view *UtxoViewpoint) fetchUtxos(cache *utxoCache, outpoints []core.OutPoint) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 {
		return nil
	}

	// Filter entries that are already in the view.
	needed := make([]core.OutPoint, 0, len(outpoints))
	for i := range outpoints {
		// Already loaded into the current view.
		if _, ok := view.entries[outpoints[i]]; ok {
			continue
		}
		needed = append(needed, outpoints[i])
	}
	// Request the input utxos from the database.
	return view.fetchUtxosFromCache(cache, needed)
}

// findInputsToFetch goes through all the blocks and returns all the outpoints of
// the entries that need to be fetched in order to validate the block.  Outpoints
// for the entries that are already in the block are not included in the returned
// outpoints.
func (view *UtxoViewpoint) findInputsToFetch(block *core.Block) []core.OutPoint {
	// Build a map of in-flight transactions because some of the inputs in
	// this block could be referencing other transactions earlier in this
	// block which are not yet in the chain.
	txInFlight := map[chainhash.Hash]int{}
	transactions := block.Transactions()
	for i, tx := range transactions {
		txInFlight[*tx.Hash()] = i
	}

	// Loop through all of the transaction inputs (except for the coinbase
	// which has no inputs) collecting them into sets of what is needed and
	// what is already known (in-flight).
	needed := make([]core.OutPoint, 0, len(transactions))
	for i, tx := range transactions[1:] {
		for _, txIn := range tx.MsgTx().TxIn {
			// It is acceptable for a transaction input to reference
			// the output of another transaction in this block only
			// if the referenced transaction comes before the
			// current one in this block.  Add the outputs of the
			// referenced transaction as available utxos when this
			// is the case.  Otherwise, the utxo details are still
			// needed.
			//
			// NOTE: The >= is correct here because i is one less
			// than the actual position of the transaction within
			// the block due to skipping the coinbase.
			originHash := &txIn.PreviousOutPoint.Hash
			if inFlightIndex, ok := txInFlight[*originHash]; ok &&
				i >= inFlightIndex {

				originTx := transactions[inFlightIndex]
				view.AddTxOuts(originTx, block.Height())
				continue
			}

			// Don't request entries that are already in the view
			// from the database.
			if _, ok := view.entries[txIn.PreviousOutPoint]; ok {
				continue
			}

			needed = append(needed, txIn.PreviousOutPoint)
		}
	}

	return needed
}

func (view *UtxoViewpoint) fetchInputUtxos(cache *utxoCache, block *core.Block) error {
	return view.fetchUtxosFromCache(cache, view.findInputsToFetch(block))
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewUtxoViewpoint() *UtxoViewpoint {
	return &UtxoViewpoint{
		entries: make(map[core.OutPoint]*UtxoEntry),
	}
}

func (b *BlockChain) FetchUtxoView(tx *core.Tx) (*UtxoViewpoint, error) {

	neededLen := len(tx.MsgTx().TxOut)
	if !IsCoinBase(tx) {
		neededLen += len(tx.MsgTx().TxIn)
	}
	needed := make([]core.OutPoint, 0, neededLen)
	prevOut := core.OutPoint{Hash: *tx.Hash()}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)
		needed = append(needed, prevOut)
	}
	if !IsCoinBase(tx) {
		for _, txIn := range tx.MsgTx().TxIn {
			needed = append(needed, txIn.PreviousOutPoint)
		}
	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	view := NewUtxoViewpoint()
	b.chainLock.RLock()

	// 打印循环needed中的内容
	for i, outPoint := range needed {
		// 打印索引、哈希和索引值
		log.Infof("  索引[%d] - Hash: %s, Index: %d",
			i,
			outPoint.Hash.String(),
			outPoint.Index)
	}

	err := view.fetchUtxosFromCache(b.utxoCache, needed)
	b.chainLock.RUnlock()
	return view, err
}

func (b *BlockChain) FetchUtxoEntry(outpoint core.OutPoint) (*UtxoEntry, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()
	entries, err := b.utxoCache.fetchEntries([]core.OutPoint{outpoint})
	if err != nil {
		return nil, err
	}
	return entries[0], nil
}

//	将区块中的所有交易应用到UTXO视图，更新未花费交易输出状态
//
// 相当于将区块"连接"到UTXO视图，处理所有交易的输入（标记为已花费）和输出（添加为新UTXO）
func (view *UtxoViewpoint) ApplyBlock(block *core.Block) error {
	// 调用已有的connectTransactions方法，传递nil作为spentTxOuts（重建索引时无需收集这些信息）
	return view.connectTransactions(block, nil)
}

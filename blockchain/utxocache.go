// Copyright (c) 2023 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bitcoin/txscript"
	"bitcoin/wire"
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"
	"sync"
	"time"
)

// mapSlice is a slice of maps for utxo entries.  The slice of maps are needed to
// guarantee that the map will only take up N amount of bytes.  As of v1.20, the
// go runtime will allocate 2^N + few extra buckets, meaning that for large N, we'll
// allocate a lot of extra memory if the amount of entries goes over the previously
// allocated buckets.  A slice of maps allows us to have a better control of how much
// total memory gets allocated by all the maps.
type mapSlice struct {
	// mtx protects against concurrent access for the map slice.
	mtx sync.Mutex

	// maps are the underlying maps in the slice of maps.
	maps []map[core.OutPoint]*UtxoEntry

	// maxEntries is the maximum amount of elements that the map is allocated for.
	maxEntries []int

	// maxTotalMemoryUsage is the maximum memory usage in bytes that the state
	// should contain in normal circumstances.
	maxTotalMemoryUsage uint64
}

// length returns the length of all the maps in the map slice added together.
//
// This function is safe for concurrent access.
func (ms *mapSlice) length() int {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	var l int
	for _, m := range ms.maps {
		l += len(m)
	}

	return l
}

// size returns the size of all the maps in the map slice added together.
//
// This function is safe for concurrent access.
func (ms *mapSlice) size() int {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	var size int
	for _, num := range ms.maxEntries {
		size += calculateRoughMapSize(num, bucketSize)
	}

	return size
}

// get looks for the outpoint in all the maps in the map slice and returns
// the entry.  nil and false is returned if the outpoint is not found.
//
// This function is safe for concurrent access.
func (ms *mapSlice) get(op core.OutPoint) (*UtxoEntry, bool) {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	var entry *UtxoEntry
	var found bool

	for _, m := range ms.maps {
		entry, found = m[op]
		if found {
			return entry, found
		}
	}

	return nil, false
}

// put puts the outpoint and the entry into one of the maps in the map slice.  If the
// existing maps are all full, it will allocate a new map based on how much memory we
// have left over.  Leftover memory is calculated as:
// maxTotalMemoryUsage - (totalEntryMemory + mapSlice.size())
//
// This function is safe for concurrent access.
func (ms *mapSlice) put(op core.OutPoint, entry *UtxoEntry, totalEntryMemory uint64) {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	// Look for the key in the maps.
	for i := range ms.maxEntries {
		m := ms.maps[i]
		_, found := m[op]
		if found {
			// If the key is found, overwrite it.
			m[op] = entry
			return // Return as we were successful in adding the entry.
		}
	}

	for i, maxNum := range ms.maxEntries {
		m := ms.maps[i]
		if len(m) >= maxNum {
			// Don't try to insert if the map already at max since
			// that'll force the map to allocate double the memory it's
			// currently taking up.
			continue
		}

		m[op] = entry
		return // Return as we were successful in adding the entry.
	}

	// We only reach this code if we've failed to insert into the map above as
	// all the current maps were full.  We thus make a new map and insert into
	// it.
	m := ms.makeNewMap(totalEntryMemory)
	m[op] = entry
}

// delete attempts to delete the given outpoint in all of the maps. No-op if the
// outpoint doesn't exist.
//
// This function is safe for concurrent access.
func (ms *mapSlice) delete(op core.OutPoint) {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	for i := 0; i < len(ms.maps); i++ {
		delete(ms.maps[i], op)
	}
}

// makeNewMap makes and appends the new map into the map slice.
//
// This function is NOT safe for concurrent access and must be called with the
// lock held.
func (ms *mapSlice) makeNewMap(totalEntryMemory uint64) map[core.OutPoint]*UtxoEntry {
	// Get the size of the leftover memory.
	memSize := ms.maxTotalMemoryUsage - totalEntryMemory
	for _, maxNum := range ms.maxEntries {
		memSize -= uint64(calculateRoughMapSize(maxNum, bucketSize))
	}

	// Get a new map that's sized to house inside the leftover memory.
	// -1 on the returned value will make the map allocate half as much total
	// bytes.  This is done to make sure there's still room left for utxo
	// entries to take up.
	numMaxElements := calculateMinEntries(int(memSize), bucketSize+avgEntrySize)
	numMaxElements -= 1
	ms.maxEntries = append(ms.maxEntries, numMaxElements)
	ms.maps = append(ms.maps, make(map[core.OutPoint]*UtxoEntry, numMaxElements))

	return ms.maps[len(ms.maps)-1]
}

// deleteMaps deletes all maps except for the first one which should be the biggest.
//
// This function is safe for concurrent access.
func (ms *mapSlice) deleteMaps() {
	ms.mtx.Lock()
	defer ms.mtx.Unlock()

	size := ms.maxEntries[0]
	ms.maxEntries = []int{size}
	ms.maps = ms.maps[:1]
}

const (
	// utxoFlushPeriodicInterval is the interval at which a flush is performed
	// when the flush mode FlushPeriodic is used.  This is used when the initial
	// block download is complete and it's useful to flush periodically in case
	// of unforeseen shutdowns.
	utxoFlushPeriodicInterval = time.Minute * 5
)

// FlushMode is used to indicate the different urgency types for a flush.
type FlushMode uint8

const (
	// FlushRequired is the flush mode that means a flush must be performed
	// regardless of the cache state.  For example right before shutting down.
	FlushRequired FlushMode = iota

	// FlushPeriodic is the flush mode that means a flush can be performed
	// when it would be almost needed.  This is used to periodically signal when
	// no I/O heavy operations are expected soon, so there is time to flush.
	FlushPeriodic

	// FlushIfNeeded is the flush mode that means a flush must be performed only
	// if the cache is exceeding a safety threshold very close to its maximum
	// size.  This is used mostly internally in between operations that can
	// increase the cache size.
	FlushIfNeeded
)

// utxoCache is a cached utxo view in the chainstate of a BlockChain.
type utxoCache struct {
	db db.KeyValueStore

	// maxTotalMemoryUsage is the maximum memory usage in bytes that the state
	// should contain in normal circumstances.
	maxTotalMemoryUsage uint64

	// cachedEntries keeps the internal cache of the utxo state.  The tfModified
	// flag indicates that the state of the entry (potentially) deviates from the
	// state in the database.  Explicit nil values in the map are used to
	// indicate that the database does not contain the entry.
	cachedEntries    mapSlice
	totalEntryMemory uint64 // Total memory usage in bytes.

	lastFlushHash chainhash.Hash
	lastFlushTime time.Time
}

//	initiates a new utxo cache instance with its memory usage limited
//
// to the given maximum.
func newUtxoCache(db db.KeyValueStore, maxTotalMemoryUsage uint64) *utxoCache {
	// While the entry isn't included in the map size, add the average size to the
	// bucket size so we get some leftover space for entries to take up.
	numMaxElements := calculateMinEntries(int(maxTotalMemoryUsage), bucketSize+avgEntrySize)
	numMaxElements -= 1

	log.Infof("Pre-alloacting for %d MiB", maxTotalMemoryUsage/(1024*1024)+1)

	m := make(map[core.OutPoint]*UtxoEntry, numMaxElements)

	return &utxoCache{
		db:                  db,
		maxTotalMemoryUsage: maxTotalMemoryUsage,
		cachedEntries: mapSlice{
			maps:                []map[core.OutPoint]*UtxoEntry{m},
			maxEntries:          []int{numMaxElements},
			maxTotalMemoryUsage: maxTotalMemoryUsage,
		},
	}
}

// totalMemoryUsage returns the total memory usage in bytes of the UTXO cache.
func (s *utxoCache) totalMemoryUsage() uint64 {
	// Total memory is the map size + the size that the utxo entries are
	// taking up.
	size := uint64(s.cachedEntries.size())
	size += s.totalEntryMemory

	return size
}

func (s *utxoCache) fetchEntries(outpoints []core.OutPoint) ([]*UtxoEntry, error) {
	entries := make([]*UtxoEntry, len(outpoints))
	var (
		missingOps    []core.OutPoint
		missingOpsIdx []int
	)
	for i := range outpoints {
		entry, found := s.cachedEntries.get(outpoints[i])
		if found {
			entries[i] = entry
			continue
		}

		// 准备记录缺失的UTXO
		if len(missingOps) == 0 {
			missingOps = make([]core.OutPoint, 0, len(outpoints))
			missingOpsIdx = make([]int, 0, len(outpoints))
		}

		log.Infof("缺失的utxo")

		missingOpsIdx = append(missingOpsIdx, i)
		missingOps = append(missingOps, outpoints[i])
	}

	// 没有缺失的UTXO，直接返回
	if len(missingOps) == 0 {
		return entries, nil
	}

	// 从数据库获取缺失的UTXO
	dbEntries := make([]*UtxoEntry, len(missingOps))
	for i := range missingOps {
		point := missingOps[i]
		key := s.UTXOKey(point.Hash, point.Index)
		var utxoBytes []byte

		// 查询数据库，不将"键不存在"视为错误
		err := s.db.Get(key, func(value []byte) error {
			if value != nil {
				utxoBytes = make([]byte, len(value))
				copy(utxoBytes, value)
			} else {
				log.Infof("未找到Value %s %s", point.Hash, point.Index)
			}
			return nil // 始终返回nil，即使value为nil
		})

		// 关键修复：区分错误类型
		if err != nil {
			// 判断是否为“键不存在”错误（需确保db包导出了ErrKeyNotFound）
			if err == db.ErrKeyNotFound {
				// 正常情况：未找到UTXO，记录日志并设为nil
				dbEntries[i] = nil
				continue // 跳过报错，继续处理下一个UTXO
			} else {
				// 异常情况：真正的数据库错误（如连接失败、IO错误等）
				return nil, err // 中断流程，返回错误
			}
		}

		// 如果未找到数据，直接存nil
		if utxoBytes == nil {
			dbEntries[i] = nil
			continue
		}

		// 解析找到的UTXO数据
		var protoUTXO wire.ProtoUtxoEntry
		if err := proto.Unmarshal(utxoBytes, &protoUTXO); err != nil {
			return nil, fmt.Errorf("反序列化UTXO失败 (TxHash: %s, Index: %d): %w",
				point.Hash.String(), point.Index, err)
		}

		var utxoEntry UtxoEntry
		if err := utxoEntry.FromProto(&protoUTXO); err != nil {
			return nil, fmt.Errorf("转换ProtoUTXO为UtxoEntry失败 (TxHash: %s, Index: %d): %w",
				point.Hash.String(), point.Index, err)
		}
		dbEntries[i] = &utxoEntry
	}

	// 将数据库查询结果加入缓存（包括nil值，避免重复查询）
	for i := range dbEntries {
		s.cachedEntries.put(missingOps[i], dbEntries[i], s.totalEntryMemory)
		if dbEntries[i] != nil {
			s.totalEntryMemory += dbEntries[i].memoryUsage()
		}
	}

	// 填充最终结果
	for i := range missingOpsIdx {
		entries[missingOpsIdx[i]] = dbEntries[i]
	}

	return entries, nil
}

// addTxOut adds the specified output to the cache if it is not provably
// unspendable.  When the cache already has an entry for the output, it will be
// overwritten with the given output.  All fields will be updated for existing
// entries since it's possible it has changed during a reorg.
func (s *utxoCache) addTxOut(outpoint core.OutPoint, txOut *core.TxOut, isCoinBase bool,
	blockHeight int32) error {

	// Don't add provably unspendable outputs.
	if txscript.IsUnspendable(txOut.PkScript) {
		return nil
	}

	entry := new(UtxoEntry)
	entry.amount = txOut.Value

	// Deep copy the script when the script in the entry differs from the one in
	// the txout.  This is required since the txout script is a subslice of the
	// overall contiguous buffer that the msg tx houses for all scripts within
	// the tx.  It is deep copied here since this entry may be added to the utxo
	// cache, and we don't want the utxo cache holding the entry to prevent all
	// of the other tx scripts from getting garbage collected.
	entry.pkScript = make([]byte, len(txOut.PkScript))
	copy(entry.pkScript, txOut.PkScript)

	entry.blockHeight = blockHeight
	entry.packedFlags = tfFresh | tfModified
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}

	s.cachedEntries.put(outpoint, entry, s.totalEntryMemory)
	s.totalEntryMemory += entry.memoryUsage()

	return nil
}

// addTxOuts adds all outputs in the passed transaction which are not provably
// unspendable to the view.  When the view already has entries for any of the
// outputs, they are simply marked unspent.  All fields will be updated for
// existing entries since it's possible it has changed during a reorg.
func (s *utxoCache) addTxOuts(tx *core.Tx, blockHeight int32) error {
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
		err := s.addTxOut(prevOut, txOut, isCoinBase, blockHeight)
		if err != nil {
			return err
		}
	}

	return nil
}

// addTxIn will add the given input to the cache if the previous outpoint the txin
// is pointing to exists in the utxo set.  The utxo that is being spent by the input
// will be marked as spent and if the utxo is fresh (meaning that the database on disk
// never saw it), it will be removed from the cache.
func (s *utxoCache) addTxIn(txIn *core.TxIn, stxos *[]SpentTxOut) error {
	// Ensure the referenced utxo exists in the view.  This should
	// never happen unless there is a bug is introduced in the code.
	entries, err := s.fetchEntries([]core.OutPoint{txIn.PreviousOutPoint})
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0] == nil {
		return AssertError(fmt.Sprintf("missing input %v",
			txIn.PreviousOutPoint))
	}

	// Only create the stxo details if requested.
	entry := entries[0]
	if stxos != nil {
		// Populate the stxo details using the utxo entry.
		stxo := SpentTxOut{
			Amount:     entry.Amount(),
			PkScript:   entry.PkScript(),
			Height:     entry.BlockHeight(),
			IsCoinBase: entry.IsCoinBase(),
		}

		*stxos = append(*stxos, stxo)
	}

	// Mark the entry as spent.
	entry.Spend()

	// If an entry is fresh it indicates that this entry was spent before it could be
	// flushed to the database. Because of this, we can just delete it from the map of
	// cached entries.
	if entry.isFresh() {
		// If the entry is fresh, we will always have it in the cache.
		s.cachedEntries.delete(txIn.PreviousOutPoint)
		s.totalEntryMemory -= entry.memoryUsage()
	} else {
		// Can leave the entry to be garbage collected as the only purpose
		// of this entry now is so that the entry on disk can be deleted.
		entry = nil
		s.totalEntryMemory -= entry.memoryUsage()
	}

	return nil
}

// addTxIns will add the given inputs of the tx if it's not a coinbase tx and if
// the previous output that the input is pointing to exists in the utxo set.  The
// utxo that is being spent by the input will be marked as spent and if the utxo
// is fresh (meaning that the database on disk never saw it), it will be removed
// from the cache.
func (s *utxoCache) addTxIns(tx *core.Tx, stxos *[]SpentTxOut) error {
	// Coinbase transactions don't have any inputs to spend.
	if IsCoinBase(tx) {
		return nil
	}

	for _, txIn := range tx.MsgTx().TxIn {
		err := s.addTxIn(txIn, stxos)
		if err != nil {
			return err
		}
	}

	return nil
}

// connectTransaction updates the cache by adding all new utxos created by the
// passed transaction and marking and/or removing all utxos that the transactions
// spend as spent.  In addition, when the 'stxos' argument is not nil, it will
// be updated to append an entry for each spent txout.  An error will be returned
// if the cache and the database does not contain the required utxos.
func (s *utxoCache) connectTransaction(
	tx *core.Tx, blockHeight int32, stxos *[]SpentTxOut) error {

	err := s.addTxIns(tx, stxos)
	if err != nil {
		return err
	}

	// Add the transaction's outputs as available utxos.
	return s.addTxOuts(tx, blockHeight)
}

// connectTransactions updates the cache by adding all new utxos created by all
// of the transactions in the passed block, marking and/or removing all utxos
// the transactions spend as spent, and setting the best hash for the view to
// the passed block.  In addition, when the 'stxos' argument is not nil, it will
// be updated to append an entry for each spent txout.
func (s *utxoCache) connectTransactions(block *core.Block, stxos *[]SpentTxOut) error {
	for _, tx := range block.Transactions() {
		err := s.connectTransaction(tx, block.Height(), stxos)
		if err != nil {
			return err
		}
	}
	return nil
}

// writeCache 将UTXO缓存中所有修改过的条目批量写入数据库，并重置缓存
// 操作通过数据库事务保证原子性，仅在事务成功后更新缓存状态
func (s *utxoCache) writeCache(bestState *BestState) error {
	// 1. 锁定缓存，防止并发修改（与cachedEntries的put/delete等方法锁逻辑一致）
	s.cachedEntries.mtx.Lock()
	defer s.cachedEntries.mtx.Unlock()

	// 2. 检查最佳状态合法性（避免空指针）
	if bestState == nil {
		return fmt.Errorf("writeCache failed: bestState is nil (invalid chain state)")
	}

	// 3. 开启数据库事务，批量处理UTXO（原子性保证）
	err := s.db.Update(func(batch db.IndexedBatch) error {
		// 3.1 遍历所有缓存map，处理每个UTXO条目
		for mapIdx, m := range s.cachedEntries.maps {
			for outpoint, entry := range m {
				// 生成UTXO在数据库中的存储键（复用已有UTXOKey逻辑，确保与读取一致）
				utxoKey := s.UTXOKey(outpoint.Hash, outpoint.Index)

				switch {
				// 情况1：条目为nil（数据库无此UTXO）或已花费 → 从数据库删除
				case entry == nil || entry.IsSpent():
					if err := batch.Delete(utxoKey); err != nil {
						return fmt.Errorf("batch delete UTXO failed (mapIdx: %d, txHash: %s, index: %d): %w",
							mapIdx, outpoint.Hash.String(), outpoint.Index, err)
					}

				// 情况2：条目未修改 → 跳过（无需同步到数据库）
				case !entry.isModified():
					continue

				// 情况3：条目已修改（新增/状态变更） → 序列化后写入数据库
				default:
					// 3.1.1 将UtxoEntry转换为Proto格式（需确保UtxoEntry实现ToProto方法）
					protoUTXO, err := entry.ToProto()
					if err != nil {
						return fmt.Errorf("UTXO to Proto failed (mapIdx: %d, txHash: %s, index: %d): %w",
							mapIdx, outpoint.Hash.String(), outpoint.Index, err)
					}

					// 3.1.2 序列化Proto为字节（与读取时的proto.Unmarshal对应）
					protoBytes, err := proto.Marshal(protoUTXO)
					if err != nil {
						return fmt.Errorf("Proto marshal failed (mapIdx: %d, txHash: %s, index: %d): %w",
							mapIdx, outpoint.Hash.String(), outpoint.Index, err)
					}

					// 3.1.3 写入事务（批量提交）
					if err := batch.Put(utxoKey, protoBytes); err != nil {
						return fmt.Errorf("batch put UTXO failed (mapIdx: %d, txHash: %s, index: %d): %w",
							mapIdx, outpoint.Hash.String(), outpoint.Index, err)
					}
				}
			}
		}

		// 作用：重启后验证UTXO状态是否与链状态对齐，防止数据损坏
		consistencyKey := db.UTXOStateConsistencyBucket.Key([]byte("best_hash")) // 假设db包定义该桶
		if err := batch.Put(consistencyKey, bestState.Hash[:]); err != nil {
			return fmt.Errorf("save UTXO consistency state failed (best hash: %s): %w",
				bestState.Hash.String(), err)
		}

		// 事务内所有操作成功，返回nil触发提交
		return nil
	})

	// 4. 处理事务错误（事务失败则不修改缓存状态）
	if err != nil {
		return fmt.Errorf("UTXO write transaction aborted: %w", err)
	}

	// 5. 事务成功后，重置缓存（保留第一个map以复用内存，避免频繁创建）
	s.cachedEntries.deleteMaps() // 原有方法：保留第一个map，清空其他
	s.totalEntryMemory = 0       // 重置内存统计（所有条目已写入数据库）

	// 6. 更新最后刷新状态（用于后续FlushMode判断）
	s.lastFlushHash = bestState.Hash
	s.lastFlushTime = time.Now()

	// 7. 日志记录（便于运维跟踪）
	totalMiB := uint64(s.cachedEntries.size()) / (1024 * 1024)
	log.Infof("UTXO cache written to DB successfully. Details: [best hash: %s, flushed entries: %d, size: %d MiB, time: %v]",
		s.lastFlushHash.String(), s.cachedEntries.length(), totalMiB, s.lastFlushTime)

	return nil
}

// FlushUtxoCache 按照指定模式刷新UTXO缓存到数据库
// 模式说明：
// - FlushRequired：强制刷新（如关机前）
// - FlushPeriodic：周期性刷新（如每5分钟）
// - FlushIfNeeded：缓存超限时刷新（避免内存溢出）
func (b *BlockChain) FlushUtxoCache(mode FlushMode) error {
	// 1. 加链锁：确保刷新与区块连接、链状态修改等操作互斥
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// 2. 校验链状态（未初始化时无最佳区块，无法对齐UTXO状态）
	if b.stateSnapshot == nil {
		return fmt.Errorf("FlushUtxoCache failed: chain not initialized (no best block state)")
	}

	// 3. 校验UTXO缓存初始化状态（避免空指针异常）
	if b.utxoCache == nil {
		return fmt.Errorf("FlushUtxoCache failed: UTXO cache not initialized (internal error)")
	}

	// 4. 打印触发日志（便于跟踪刷新时机）
	modeStr := map[FlushMode]string{
		FlushRequired: "FlushRequired (forced)",
		FlushPeriodic: "FlushPeriodic (scheduled)",
		FlushIfNeeded: "FlushIfNeeded (memory threshold)",
	}[mode]
	log.Debugf("FlushUtxoCache triggered. Mode: %s, current best block: [hash: %s, height: %d]",
		modeStr, b.stateSnapshot.Hash.String(), b.stateSnapshot.Height)

	// 5. 触发底层UTXO缓存刷新逻辑
	if err := b.utxoCache.flush(mode, b.stateSnapshot); err != nil {
		return fmt.Errorf("FlushUtxoCache failed (mode: %s, best hash: %s): %w",
			modeStr, b.stateSnapshot.Hash.String(), err)
	}

	// 6. 刷新成功日志（包含缓存当前状态）
	cacheSizeMiB := b.utxoCache.totalMemoryUsage() / (1024 * 1024)
	log.Infof("FlushUtxoCache completed. Mode: %s, cache status: [size: %d MiB, entries: %d], aligned with best block: [hash: %s, height: %d]",
		modeStr, cacheSizeMiB, b.utxoCache.cachedEntries.length(),
		b.stateSnapshot.Hash.String(), b.stateSnapshot.Height)

	return nil
}

func (s *utxoCache) flush(mode FlushMode, bestState *BestState) error {
	var threshold uint64
	switch mode {
	case FlushRequired:
		threshold = 0

	case FlushIfNeeded:
		// If we performed a flush in the current best state, we have nothing to do.
		if bestState.Hash == s.lastFlushHash {
			return nil
		}

		threshold = s.maxTotalMemoryUsage

	case FlushPeriodic:
		// If the time since the last flush is over the periodic interval,
		// force a flush.  Otherwise just flush when the cache is full.
		if time.Since(s.lastFlushTime) > utxoFlushPeriodicInterval {
			threshold = 0
		} else {
			threshold = s.maxTotalMemoryUsage
		}
	}

	if s.totalMemoryUsage() >= threshold {
		// Add one to round up the integer division.
		totalMiB := s.totalMemoryUsage() / ((1024 * 1024) + 1)
		log.Infof("Flushing UTXO cache of %d MiB with %d entries to disk. For large sizes, "+
			"this can take up to several minutes...", totalMiB, s.cachedEntries.length())

		return s.writeCache(bestState)
	}
	return nil
}

func (b *utxoCache) UTXOKey(txHash chainhash.Hash, index uint32) []byte {
	outPointBytes := make([]byte, chainhash.HashSize+4)
	copy(outPointBytes[:chainhash.HashSize], txHash[:])
	binary.LittleEndian.PutUint32(outPointBytes[chainhash.HashSize:], index)
	utxoKey := db.UTXOBucket.Key(outPointBytes)
	return utxoKey
}

//	返回缓存中所有未花费的UTXO条目
//
// 该方法会遍历缓存中的所有映射，收集所有非nil且未被花费的UTXO
// 返回的map包含所有有效的UTXO，键为交易输出点，值为对应的UTXO条目
func (s *utxoCache) GetAllUTXOs() map[core.OutPoint]*UtxoEntry {
	// 加锁保证并发安全，与其他操作缓存的方法保持一致
	s.cachedEntries.mtx.Lock()
	defer s.cachedEntries.mtx.Unlock()

	// 初始化结果集合
	allUTXOs := make(map[core.OutPoint]*UtxoEntry)

	// 遍历所有map中的条目
	for _, m := range s.cachedEntries.maps {
		for outpoint, entry := range m {
			// 只包含有效的未花费UTXO：
			// 1. 条目不为nil（nil表示数据库中不存在该UTXO）
			// 2. 条目未被标记为已花费
			if entry != nil && !entry.IsSpent() {
				allUTXOs[outpoint] = entry
			}
		}
	}

	return allUTXOs
}

// MarkAsSpent 将指定的UTXO标记为已花费并更新缓存状态
func (s *utxoCache) MarkAsSpent(point core.OutPoint) error {
	// 从缓存中查找UTXO条目
	entry, found := s.cachedEntries.get(point)
	if !found {
		return fmt.Errorf("UTXO not found in cache: %v", point)
	}

	// 如果已经花费则无需处理
	if entry.IsSpent() {
		return nil
	}

	// 标记UTXO为已花费
	entry.Spend()

	// 处理内存统计：已花费条目内存占用不变，无需调整totalEntryMemory
	// 但需要更新缓存状态

	// 如果是新创建的UTXO（尚未写入数据库），直接从缓存中删除
	/*	if entry.isFresh() {
		s.cachedEntries.delete(point)
		s.totalEntryMemory -= entry.memoryUsage()
		return nil
	}*/

	// 对于已持久化的UTXO，更新缓存中的状态
	s.cachedEntries.put(point, entry, s.totalEntryMemory)
	return nil
}

// AddUTXO 向缓存中添加新的UTXO条目
func (s *utxoCache) AddUTXO(point core.OutPoint, out *core.TxOut, isCoinBase bool, height int32) error {
	// 不添加无法花费的输出
	if txscript.IsUnspendable(out.PkScript) {
		return fmt.Errorf("cannot add unspendable UTXO: %v", point)
	}

	// 创建新的UTXO条目
	entry := new(UtxoEntry)
	entry.amount = out.Value

	// 深拷贝脚本以避免外部引用导致的内存泄漏
	entry.pkScript = make([]byte, len(out.PkScript))
	copy(entry.pkScript, out.PkScript)

	entry.blockHeight = height
	entry.packedFlags = tfFresh | tfModified // 标记为新创建且已修改

	// 如果是coinbase交易输出，添加相应标记
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}

	// 检查缓存中是否已有该UTXO（可能发生在重新组织链时）
	existingEntry, exists := s.cachedEntries.get(point)
	if exists {
		// 移除现有条目的内存占用
		if existingEntry != nil {
			s.totalEntryMemory -= existingEntry.memoryUsage()
		}
	}

	// 将新条目添加到缓存
	s.cachedEntries.put(point, entry, s.totalEntryMemory)
	// 更新总内存占用
	s.totalEntryMemory += entry.memoryUsage()

	return nil
}

func (s *utxoCache) getUtxoByOutPointFromCache(txHash *chainhash.Hash, index uint32) (*UtxoEntry, error) {
	// 创建要查询的交易输出点
	outpoint := core.OutPoint{
		Hash:  *txHash,
		Index: index,
	}

	// 复用fetchEntries方法处理缓存查询和数据库加载逻辑
	entries, err := s.fetchEntries([]core.OutPoint{outpoint})
	if err != nil {
		return nil, fmt.Errorf("获取UTXO失败 (TxHash: %s, Index: %d): %w",
			txHash.String(), index, err)
	}

	// fetchEntries返回的切片长度应与输入一致（此处为1）
	if len(entries) != 1 {
		return nil, AssertError(fmt.Sprintf("获取UTXO返回异常条目数量: 预期1, 实际%d", len(entries)))
	}

	// 返回查询结果（可能为nil，表示数据库中也不存在该UTXO）
	return entries[0], nil
}

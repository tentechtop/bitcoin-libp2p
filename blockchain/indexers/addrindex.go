package indexers

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

//确认的交易（Confirmed Transaction）指的是已经被打包进主链区块，并且随着后续区块的添加，获得了一定数量 “确认数” 的交易。

const (
	addrIndexName = "address index"

	// addrKeySize is the number of bytes an address key consumes in the
	// index.  It consists of 1 byte address type + 20 bytes hash160.
	addrKeySize = 1 + 20

	// addrKeyTypePubKeyHash is the address type in an address key which
	// represents both a pay-to-pubkey-hash and a pay-to-pubkey address.
	// This is done because both are identical for the purposes of the
	// address index.
	addrKeyTypePubKeyHash = 0

	// addrKeyTypeScriptHash is the address type in an address key which
	// represents a pay-to-script-hash address.  This is necessary because
	// the hash of a pubkey address might be the same as that of a script
	// hash.
	addrKeyTypeScriptHash = 1

	// addrKeyTypePubKeyHash is the address type in an address key which
	// represents a pay-to-witness-pubkey-hash address. This is required
	// as the 20-byte data push of a p2wkh witness program may be the same
	// data push used a p2pkh address.
	addrKeyTypeWitnessPubKeyHash = 2

	// addrKeyTypeScriptHash is the address type in an address key which
	// represents a pay-to-witness-script-hash address. This is required,
	// as p2wsh are distinct from p2sh addresses since they use a new
	// script template, as well as a 32-byte data push.
	addrKeyTypeWitnessScriptHash = 3

	// addrKeyTypeTaprootPubKey is the address type in an address key that
	// represents a pay-to-taproot address. We use this to denote addresses
	// related to the segwit v1 that are encoded in the bech32m format.
	addrKeyTypeTaprootPubKey = 4

	// Size of a transaction entry.  It consists of 4 bytes block id + 4
	// bytes offset + 4 bytes length.
	txEntrySize = 4 + 4 + 4
)

var (
	addrKey = []byte("txbyaddridx")
	//  is an error that is used to signal an
	// unsupported address type has been used.
	errUnsupportedAddressType = errors.New("address type is not supported by the address index")
)

type AddrIndex struct {
	db              db.KeyValueStore
	chainParams     *core.Params
	unconfirmedLock sync.RWMutex

	//嵌套的 map 外层Key是 [addrKeySize]byte 内层Key是 交易Hash  作用就是保存一个地址下所有的交易
	txnsByAddr map[[addrKeySize]byte]map[chainhash.Hash]*core.Tx

	//addrsByTx 是一个用于维护未确认交易（内存池中的交易）与地址关联关系的反向索引，
	//其核心作用是高效地跟踪 “某笔交易涉及哪些地址”，以便在交易被移除（如打包进区块或失效）
	//时快速更新地址索引，保证数据一致性。
	//外层 key 是交易哈希（chainhash.Hash），唯一标识一笔未确认交易。
	//内层 value 是一个 map，key 是地址的哈希键（[addrKeySize]byte，由地址类型 + hash160 组成），
	//value 是空结构体（struct{}，仅用于占位，不占用额外内存，仅需判断 “存在性”）。
	//addrsByTx 是 txnsByAddr（地址→交易的正向索引）的 “反向索引”。
	//txnsByAddr 用于快速查询 “某个地址涉及哪些未确认交易”；
	//addrsByTx 用于快速查询 “某笔未确认交易涉及哪些地址”。
	addrsByTx map[chainhash.Hash]map[[addrKeySize]byte]struct{}
}

// // 地址索引键结构: [地址键][区块高度][交易在区块中的索引]
// // 这样设计可以利用Pebble的前缀查询功能，高效获取某个地址的所有交易
// 生成地址索引的键
func addrIndexKey(addrKey [addrKeySize]byte, blockHeight uint32, txIndex uint32) []byte {
	key := make([]byte, 0, addrKeySize+4+4) // 地址键 + 区块高度 + 交易索引
	key = append(key, addrKey[:]...)

	// 区块高度用大端序存储，确保排序正确
	heightBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(heightBytes, blockHeight)
	key = append(key, heightBytes...)

	// 交易索引用大端序存储
	txIndexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(txIndexBytes, txIndex)
	key = append(key, txIndexBytes...)
	return db.AddressToTx.Key(key)
}

// 从索引键中解析出地址键
func addrKeyFromIndexKey(indexKey []byte) ([addrKeySize]byte, error) {
	prefix := db.AddressToTx.Key([]byte{})
	if !bytes.HasPrefix(indexKey, prefix) {
		return [addrKeySize]byte{}, errors.New("不是有效的地址索引键")
	}
	data := indexKey[len(prefix):]
	if len(data) < addrKeySize {
		return [addrKeySize]byte{}, errors.New("索引键长度不足")
	}
	var addrKey [addrKeySize]byte
	copy(addrKey[:], data[:addrKeySize])
	return addrKey, nil
}

func (idx *AddrIndex) addrToKey(addr utils.Address) ([addrKeySize]byte, error) {
	switch addr := addr.(type) {
	case *utils.AddressPubKeyHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressScriptHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeScriptHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressPubKey:
		var result [addrKeySize]byte
		result[0] = addrKeyTypePubKeyHash
		copy(result[1:], addr.AddressPubKeyHash().Hash160()[:])
		return result, nil

	case *utils.AddressWitnessScriptHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeWitnessScriptHash
		copy(result[1:], utils.Hash160(addr.ScriptAddress()))
		return result, nil

	case *utils.AddressWitnessPubKeyHash:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeWitnessPubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressTaproot:
		var result [addrKeySize]byte
		result[0] = addrKeyTypeTaprootPubKey
		copy(result[1:], utils.Hash160(addr.ScriptAddress()))
		return result, nil
	}
	return [addrKeySize]byte{}, errUnsupportedAddressType
}

// indexPkScript 索引公钥脚本中的地址
func (idx *AddrIndex) indexPkScript(data map[[addrKeySize]byte][]int, pkScript []byte, txIdx int) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, idx.chainParams)
	if err != nil || len(addrs) == 0 {
		return
	}
	for _, addr := range addrs {
		addrKey, err := idx.addrToKey(addr)
		if err != nil {
			continue
		}
		indexedTxns := data[addrKey]
		numTxns := len(indexedTxns)
		if numTxns > 0 && indexedTxns[numTxns-1] == txIdx {
			continue
		}
		indexedTxns = append(indexedTxns, txIdx)
		data[addrKey] = indexedTxns
	}
}

// 索引区块中的所有地址
func (idx *AddrIndex) indexBlock(data map[[addrKeySize]byte][]int, block *core.Block, stxos []blockchain.SpentTxOut) {
	stxoIndex := 0
	for txIdx, tx := range block.Transactions() {
		if txIdx != 0 { // 不是coinbase交易
			for range tx.MsgTx().TxIn {
				if stxoIndex >= len(stxos) {
					break
				}
				pkScript := stxos[stxoIndex].PkScript
				idx.indexPkScript(data, pkScript, txIdx)
				stxoIndex++
			}
		}
		for _, txOut := range tx.MsgTx().TxOut {
			idx.indexPkScript(data, txOut.PkScript, txIdx)
		}
	}
}

func (idx *AddrIndex) Init() error {
	// Nothing to do.
	return nil
}

// ConnectBlock 当新块连接到主链时更新地址索引
func (idx *AddrIndex) ConnectBlock(block *core.Block, stxos []blockchain.SpentTxOut) error {
	blockHeight := block.Height()
	transactions := block.Transactions()
	addrsToTxns := make(map[[addrKeySize]byte][]int)

	// 1. 分析区块中的所有交易，建立地址与交易索引的映射
	idx.indexBlock(addrsToTxns, block, stxos)

	// 2. 使用数据库批量操作高效写入索引数据
	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 遍历所有地址对应的交易索引
		for addrKey, txIdxs := range addrsToTxns {
			for _, txIdx := range txIdxs {
				// 验证交易索引有效性
				if txIdx < 0 || txIdx >= len(transactions) {
					continue
				}

				// 获取当前交易及哈希
				tx := transactions[txIdx]
				txHash := tx.Hash()

				// 生成索引键（地址键 + 区块高度 + 交易索引）
				key := addrIndexKey(addrKey, uint32(blockHeight), uint32(txIdx))

				// 存储交易哈希作为值（便于后续通过索引查找完整交易）
				value := txHash.GetBytes()

				// 将键值对加入批量操作
				if err := batch.Put(key, value); err != nil {
					return fmt.Errorf("批量写入地址索引失败 (地址键: %x, 交易: %s): %w",
						addrKey, txHash, err)
				}
			}
		}
		return nil
	})
}

// DisconnectBlock 当块从主链断开时删除该区块对应的地址索引条目
func (idx *AddrIndex) DisconnectBlock(block *core.Block, stxos []blockchain.SpentTxOut) error {
	blockHeight := block.Height()
	transactions := block.Transactions()
	addrsToTxns := make(map[[addrKeySize]byte][]int)

	// 1. 重新分析区块，获取该区块中所有地址与交易的关联关系
	idx.indexBlock(addrsToTxns, block, stxos)

	// 2. 使用数据库批量操作删除相关索引条目
	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 遍历所有地址对应的交易索引
		for addrKey, txIdxs := range addrsToTxns {
			for _, txIdx := range txIdxs {
				// 验证交易索引有效性
				if txIdx < 0 || txIdx >= len(transactions) {
					continue
				}

				// 生成与ConnectBlock时完全一致的索引键
				key := addrIndexKey(addrKey, uint32(blockHeight), uint32(txIdx))

				// 从数据库中删除该索引条目
				if err := batch.Delete(key); err != nil {
					return fmt.Errorf("批量删除地址索引失败 (地址键: %x, 区块高度: %d, 交易索引: %d): %w",
						addrKey, blockHeight, txIdx, err)
				}
			}
		}
		return nil
	})
}

// 获取地址相关的交易哈希
func (idx *AddrIndex) TxHashesForAddress(addr utils.Address, numToSkip, numRequested uint32, reverse bool) ([]*chainhash.Hash, uint32, error) {
	addrKey, err := idx.addrToKey(addr)
	if err != nil {
		return nil, 0, err
	}

	// 构建地址前缀，用于范围查询
	prefix := db.AddressToTx.Key(addrKey[:])

	// 创建数据库迭代器
	iter, err := idx.db.NewIterator(prefix, true)
	if err != nil {
		return nil, 0, fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close() // 确保迭代器最终会被关闭

	// 收集所有交易哈希
	var allTxHashes []*chainhash.Hash

	// 正向遍历所有匹配前缀的键值对
	if iter.First() {
		for iter.Valid() {
			key := iter.Key()
			// 验证当前键是否仍然匹配前缀（防止超出范围）
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			// 解析交易哈希
			value, err := iter.Value()
			if err != nil {
				return nil, uint32(len(allTxHashes)), fmt.Errorf("获取值失败: %w", err)
			}

			txHash, err := chainhash.NewHash(value)
			if err != nil {
				return nil, uint32(len(allTxHashes)), fmt.Errorf("解析交易哈希失败: %w", err)
			}

			allTxHashes = append(allTxHashes, txHash)

			// 移动到下一个元素
			iter.Next()
		}
	}

	totalCount := uint32(len(allTxHashes))

	// 如果需要反向查询，反转交易列表
	if reverse {
		for i, j := 0, len(allTxHashes)-1; i < j; i, j = i+1, j-1 {
			allTxHashes[i], allTxHashes[j] = allTxHashes[j], allTxHashes[i]
		}
	}

	// 应用分页逻辑
	start := numToSkip
	if start >= totalCount {
		return []*chainhash.Hash{}, totalCount, nil
	}

	end := start + numRequested
	if end > totalCount {
		end = totalCount
	}

	result := allTxHashes[start:end]

	return result, totalCount, nil
}

func (idx *AddrIndex) indexUnconfirmedAddresses(pkScript []byte, tx *core.Tx) {
	_, addresses, _, _ := txscript.ExtractPkScriptAddrs(pkScript, idx.chainParams)
	for _, addr := range addresses {
		addrKey, err := idx.addrToKey(addr)
		if err != nil {
			continue
		}
		idx.unconfirmedLock.Lock()
		addrIndexEntry := idx.txnsByAddr[addrKey]
		if addrIndexEntry == nil {
			addrIndexEntry = make(map[chainhash.Hash]*core.Tx)
			idx.txnsByAddr[addrKey] = addrIndexEntry
		}
		addrIndexEntry[*tx.Hash()] = tx

		addrsByTxEntry := idx.addrsByTx[*tx.Hash()]
		if addrsByTxEntry == nil {
			addrsByTxEntry = make(map[[addrKeySize]byte]struct{})
			idx.addrsByTx[*tx.Hash()] = addrsByTxEntry
		}
		addrsByTxEntry[addrKey] = struct{}{}
		idx.unconfirmedLock.Unlock()
	}
}

func (idx *AddrIndex) AddUnconfirmedTx(tx *core.Tx, utxoView *blockchain.UtxoViewpoint) {
	for _, txIn := range tx.MsgTx().TxIn {
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry == nil {
			continue
		}
		idx.indexUnconfirmedAddresses(entry.PkScript(), tx)
	}

	for _, txOut := range tx.MsgTx().TxOut {
		idx.indexUnconfirmedAddresses(txOut.PkScript, tx)
	}
}

func (idx *AddrIndex) RemoveUnconfirmedTx(hash *chainhash.Hash) {
	idx.unconfirmedLock.Lock()
	defer idx.unconfirmedLock.Unlock()

	for addrKey := range idx.addrsByTx[*hash] {
		delete(idx.txnsByAddr[addrKey], *hash)
		if len(idx.txnsByAddr[addrKey]) == 0 {
			delete(idx.txnsByAddr, addrKey)
		}
	}

	delete(idx.addrsByTx, *hash)
}

func (idx *AddrIndex) UnconfirmedTxnsForAddress(addr utils.Address) []*core.Tx {
	addrKey, err := idx.addrToKey(addr)
	if err != nil {
		return nil
	}

	idx.unconfirmedLock.RLock()
	defer idx.unconfirmedLock.RUnlock()

	if txns, exists := idx.txnsByAddr[addrKey]; exists {
		addressTxns := make([]*core.Tx, 0, len(txns))
		for _, tx := range txns {
			addressTxns = append(addressTxns, tx)
		}
		return addressTxns
	}

	return nil
}

func NewAddrIndex(db db.KeyValueStore, chainParams *core.Params) *AddrIndex {
	return &AddrIndex{
		db:          db,
		chainParams: chainParams,
		txnsByAddr:  make(map[[addrKeySize]byte]map[chainhash.Hash]*core.Tx),
		addrsByTx:   make(map[chainhash.Hash]map[[addrKeySize]byte]struct{}),
	}
}

// 新增常量定义，用于标识地址索引是否已初始化
const (
	// addrIndexInitializedKey 是用于跟踪地址索引是否已初始化的键
	addrIndexInitializedKey = "addrindexinitialized"
)

// DropAddrIndex 删除数据库中所有地址索引相关的条目
func DropAddrIndex(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		// 获取地址索引的键前缀
		prefix := db.AddressToTx.Key([]byte{})

		// 创建迭代器遍历所有地址索引条目
		iter, err := dataBase.NewIterator(prefix, false)
		if err != nil {
			return fmt.Errorf("创建迭代器失败: %w", err)
		}
		defer iter.Close()

		// 遍历并删除所有匹配前缀的键
		for iter.First(); iter.Valid(); iter.Next() {
			key := iter.Key()
			// 确保只删除当前前缀的键
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			if err := batch.Delete(key); err != nil {
				return fmt.Errorf("删除索引键 %x 失败: %w", key, err)
			}
		}
		// 删除初始化状态标志
		if err := batch.Delete([]byte(addrIndexInitializedKey)); err != nil {
			return fmt.Errorf("删除初始化标志失败: %w", err)
		}
		return nil
	})
}

// AddrIndexInitialized 检查地址索引是否已初始化
func AddrIndexInitialized(dataBase db.KeyValueStore) bool {
	// 使用Has方法检查初始化标志是否存在
	exists, err := dataBase.Has([]byte(addrIndexInitializedKey))
	if err != nil {
		// 发生错误时默认视为未初始化
		return false
	}
	return exists
}

// MarkAddrIndexInitialized 标记地址索引已初始化
func MarkAddrIndexInitialized(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		// 存储一个非空值表示索引已初始化
		return batch.Put([]byte(addrIndexInitializedKey), []byte("1"))
	})
}

func (idx *AddrIndex) Key() []byte {
	return addrKey
}

func (idx *AddrIndex) Name() string {
	return addrIndexName
}

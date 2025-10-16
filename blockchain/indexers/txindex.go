package indexers

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// 交易到区块的索引常量定义
const (
	txIndexName = "transaction index"

	// txIndexValueSize 是索引值的大小：32字节区块哈希 + 4字节区块高度 + 4字节交易索引
	txIndexValueSize = chainhash.HashSize + 4 + 4
)

var (
	txIndexKey             = []byte("txbyhashidx")
	errNoTxIndexEntry      = errors.New("no transaction index entry found")
	errInvalidTxIndexValue = errors.New("invalid transaction index value")
	txIndexInitializedKey  = []byte("txindexinitialized")
)

// TxIndex 维护交易到区块的映射索引
type TxIndex struct {
	db          db.KeyValueStore
	chainParams *core.Params
	mutex       sync.RWMutex
}

// txIndexKey 生成交易索引的键
// 结构: [交易哈希]
func (idx *TxIndex) txIndexKey(txHash *chainhash.Hash) []byte {
	return db.TxToBlockBucket.Key(txHash[:])
}

// serializeTxIndexValue 序列化交易索引的值
// 包含：区块哈希(32字节) + 区块高度(4字节) + 交易在区块中的索引(4字节)
func (idx *TxIndex) serializeTxIndexValue(blockHash *chainhash.Hash, blockHeight uint32, txIndex uint32) []byte {
	value := make([]byte, txIndexValueSize)

	// 存储区块哈希
	copy(value[:chainhash.HashSize], blockHash[:])

	// 存储区块高度（大端序）
	binary.BigEndian.PutUint32(value[chainhash.HashSize:chainhash.HashSize+4], blockHeight)

	// 存储交易索引（大端序）
	binary.BigEndian.PutUint32(value[chainhash.HashSize+4:], txIndex)

	return value
}

// deserializeTxIndexValue 反序列化交易索引的值
func (idx *TxIndex) deserializeTxIndexValue(data []byte) (*chainhash.Hash, uint32, uint32, error) {
	if len(data) != txIndexValueSize {
		return nil, 0, 0, errInvalidTxIndexValue
	}

	var blockHash chainhash.Hash
	copy(blockHash[:], data[:chainhash.HashSize])

	blockHeight := binary.BigEndian.Uint32(data[chainhash.HashSize : chainhash.HashSize+4])
	txIndex := binary.BigEndian.Uint32(data[chainhash.HashSize+4:])

	return &blockHash, blockHeight, txIndex, nil
}

// Init 初始化交易索引
func (idx *TxIndex) Init() error {
	return nil
}

// ConnectBlock 当新块连接到主链时更新交易索引
func (idx *TxIndex) ConnectBlock(block *core.Block, _ []blockchain.SpentTxOut) error {
	blockHash := block.Hash()
	blockHeight := block.Height()
	transactions := block.Transactions()

	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 为区块中的每笔交易建立索引
		for txIdx, tx := range transactions {
			txHash := tx.Hash()
			key := idx.txIndexKey(txHash)

			// 序列化交易索引信息
			value := idx.serializeTxIndexValue(blockHash, uint32(blockHeight), uint32(txIdx))

			// 保存到数据库
			if err := batch.Put(key, value); err != nil {
				return fmt.Errorf("无法添加交易索引 (交易: %s, 区块: %s): %w",
					txHash, blockHash, err)
			}
		}
		return nil
	})
}

// DisconnectBlock 当块从主链断开时删除对应的交易索引
func (idx *TxIndex) DisconnectBlock(block *core.Block, _ []blockchain.SpentTxOut) error {
	transactions := block.Transactions()

	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 删除区块中所有交易的索引
		for _, tx := range transactions {
			txHash := tx.Hash()
			key := idx.txIndexKey(txHash)

			if err := batch.Delete(key); err != nil {
				return fmt.Errorf("无法删除交易索引 (交易: %s): %w",
					txHash, err)
			}
		}
		return nil
	})
}

// GetBlockInfoForTx 根据交易哈希获取该交易所在的区块信息
// 返回值：区块哈希、交易在区块中的索引（从0开始）、区块高度、错误信息
func (idx *TxIndex) GetBlockInfoForTx(txHash *chainhash.Hash) (*chainhash.Hash, uint32, uint32, error) {
	// 1. 参数合法性校验
	if txHash == nil {
		return nil, 0, 0, errors.New("交易哈希不能为空")
	}
	txHashStr := txHash.String() // 预存哈希字符串用于错误信息

	// 2. 加读锁保证并发安全（与其他索引查询方法保持一致）
	idx.mutex.RLock()
	defer idx.mutex.RUnlock()

	// 3. 构造交易索引键（与存储时的键生成逻辑一致）
	key := idx.txIndexKey(txHash)
	if key == nil {
		return nil, 0, 0, fmt.Errorf("生成交易索引键失败 (tx hash: %s)", txHashStr)
	}

	// 4. 从数据库读取交易对应的区块信息
	var value []byte
	err := idx.db.Get(key, func(v []byte) error {
		if v == nil {
			return db.ErrKeyNotFound // 键不存在，交易未被索引
		}
		// 深拷贝数据避免引用数据库内部临时切片
		value = make([]byte, len(v))
		copy(value, v)
		return nil
	})
	if err != nil {
		return nil, 0, 0, fmt.Errorf("查询交易索引失败 (tx hash: %s): %w", txHashStr, err)
	}

	// 5. 验证数据长度（区块哈希32字节 + 区块高度4字节 + 交易索引4字节 = 40字节）
	const expectedLen = chainhash.HashSize + 4 + 4 // 32+4+4=40
	if len(value) != expectedLen {
		return nil, 0, 0, fmt.Errorf("交易索引数据格式错误 (tx hash: %s): 预期长度%d，实际长度%d",
			txHashStr, expectedLen, len(value))
	}

	// 6. 解析数据
	// 6.1 解析区块哈希（前32字节）
	var blockHash chainhash.Hash
	copy(blockHash[:], value[:chainhash.HashSize])

	// 6.2 解析区块高度（接下来4字节，大端序 - 修复点1）
	blockHeight := binary.BigEndian.Uint32(value[chainhash.HashSize : chainhash.HashSize+4])

	// 6.3 解析交易在区块中的索引（最后4字节，大端序 - 修复点2）
	txIndex := binary.BigEndian.Uint32(value[chainhash.HashSize+4:])
	return &blockHash, txIndex, blockHeight, nil
}

// DropTxIndex 删除所有交易索引条目
func DropTxIndex(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		prefix := db.TxToBlockBucket.Key([]byte{})
		iter, err := dataBase.NewIterator(prefix, false)
		if err != nil {
			return fmt.Errorf("创建迭代器失败: %w", err)
		}
		defer iter.Close()

		for iter.First(); iter.Valid(); iter.Next() {
			key := iter.Key()
			if !bytes.HasPrefix(key, prefix) {
				break
			}
			if err := batch.Delete(key); err != nil {
				return fmt.Errorf("删除交易索引键 %x 失败: %w", key, err)
			}
		}

		// 删除初始化标志
		if err := batch.Delete(txIndexInitializedKey); err != nil {
			return fmt.Errorf("删除交易索引初始化标志失败: %w", err)
		}
		return nil
	})
}

// TxIndexInitialized 检查交易索引是否已初始化
func TxIndexInitialized(dataBase db.KeyValueStore) bool {
	exists, err := dataBase.Has(txIndexInitializedKey)
	if err != nil {
		return false
	}
	return exists
}

// MarkTxIndexInitialized 标记交易索引已初始化
func MarkTxIndexInitialized(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		return batch.Put(txIndexInitializedKey, []byte("1"))
	})
}

// NewTxIndex 创建新的交易索引实例
func NewTxIndex(db db.KeyValueStore, chainParams *core.Params) *TxIndex {
	return &TxIndex{
		db:          db,
		chainParams: chainParams,
	}
}

func (idx *TxIndex) Key() []byte {
	return txIndexKey
}

func (idx *TxIndex) Name() string {
	return txIndexName
}

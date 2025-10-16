package indexers

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wire"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
)

// 地址到UTXO的索引

const (
	addrUtxoIdxName = "address to utxo index"

	// utxoKeySize 是地址键在索引中占用的字节数，由1字节地址类型 + 20字节hash160组成
	utxoKeySize = 1 + 20

	// 以下常量与AddrIndex保持一致，确保地址类型处理一致
	utxoKeyTypePubKeyHash        = 0
	utxoKeyTypeScriptHash        = 1
	utxoKeyTypeWitnessPubKeyHash = 2
	utxoKeyTypeWitnessScriptHash = 3
	utxoKeyTypeTaprootPubKey     = 4

	// UTXO索引条目的值大小：8字节金额 + 4字节区块高度 + 1字节是否为coinbase标志
	utxoValueSize = 8 + 4 + 1
)

var (
	addrUtxoKey                = []byte("addrutxoidx")
	errUnsupportedUtxoAddrType = errors.New("address type is not supported by the address utxo index")
)

// AddrUtxoIndex 维护地址到UTXO的映射索引
type AddrUtxoIndex struct {
	db          db.KeyValueStore
	chainParams *core.Params
}

//	生成UTXO索引的键
//
// 结构: [地址键][交易哈希][输出索引]
func UtxoIndexKey(addrKey [utxoKeySize]byte, txHash *chainhash.Hash, outIndex uint32) []byte {
	key := make([]byte, 0, utxoKeySize+chainhash.HashSize+4)
	key = append(key, addrKey[:]...)
	key = append(key, txHash[:]...)

	// 输出索引用大端序存储
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, outIndex)
	key = append(key, indexBytes...)

	return db.AddrToUtxo.Key(key)
}

// addrKeyFromUtxoIndexKey 从UTXO索引键中解析出地址键
func AddrKeyFromUtxoIndexKey(indexKey []byte) ([utxoKeySize]byte, error) {
	prefix := db.AddrToUtxo.Key([]byte{})
	if !bytes.HasPrefix(indexKey, prefix) {
		return [utxoKeySize]byte{}, errors.New("不是有效的UTXO索引键")
	}
	data := indexKey[len(prefix):]
	if len(data) < utxoKeySize {
		return [utxoKeySize]byte{}, errors.New("UTXO索引键长度不足")
	}
	var addrKey [utxoKeySize]byte
	copy(addrKey[:], data[:utxoKeySize])
	return addrKey, nil
}

// utxoKeyFromAddr 将地址转换为索引键
func (idx *AddrUtxoIndex) utxoKeyFromAddr(addr utils.Address) ([utxoKeySize]byte, error) {
	switch addr := addr.(type) {
	case *utils.AddressPubKeyHash:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypePubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressScriptHash:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypeScriptHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressPubKey:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypePubKeyHash
		copy(result[1:], addr.AddressPubKeyHash().Hash160()[:])
		return result, nil

	case *utils.AddressWitnessScriptHash:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypeWitnessScriptHash
		copy(result[1:], utils.Hash160(addr.ScriptAddress()))
		return result, nil

	case *utils.AddressWitnessPubKeyHash:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypeWitnessPubKeyHash
		copy(result[1:], addr.Hash160()[:])
		return result, nil

	case *utils.AddressTaproot:
		var result [utxoKeySize]byte
		result[0] = utxoKeyTypeTaprootPubKey
		copy(result[1:], utils.Hash160(addr.ScriptAddress()))
		return result, nil
	}
	return [utxoKeySize]byte{}, errUnsupportedUtxoAddrType
}

// serializeUtxoValue 序列化UTXO的值信息
func (idx *AddrUtxoIndex) serializeUtxoValue(amount int64, blockHeight uint32, isCoinBase bool) []byte {
	value := make([]byte, utxoValueSize)

	// 存储金额（8字节）
	binary.BigEndian.PutUint64(value[0:8], uint64(amount))

	// 存储区块高度（4字节）
	binary.BigEndian.PutUint32(value[8:12], blockHeight)

	// 存储是否为coinbase标志（1字节）
	if isCoinBase {
		value[12] = 1
	} else {
		value[12] = 0
	}

	return value
}

// deserializeUtxoValue 反序列化UTXO的值信息
func (idx *AddrUtxoIndex) deserializeUtxoValue(data []byte) (amount int64, blockHeight uint32, isCoinBase bool, err error) {
	if len(data) != utxoValueSize {
		return 0, 0, false, errors.New("无效的UTXO值长度")
	}

	amount = int64(binary.BigEndian.Uint64(data[0:8]))
	blockHeight = binary.BigEndian.Uint32(data[8:12])
	isCoinBase = data[12] == 1

	return amount, blockHeight, isCoinBase, nil
}

// Init 初始化索引
func (idx *AddrUtxoIndex) Init() error {
	// 初始化操作，如果需要的话
	return nil
}

// ConnectBlock 当新块连接到主链时更新UTXO索引
func (idx *AddrUtxoIndex) ConnectBlock(block *core.Block, stxos []blockchain.SpentTxOut) error {
	blockHeight := block.Height()
	transactions := block.Transactions()

	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 处理交易输出，添加新的UTXO索引
		for txIdx, tx := range transactions {
			msgTx := tx.MsgTx()
			isCoinBase := txIdx == 0 // 第一个交易是coinbase交易

			for outIdx, txOut := range msgTx.TxOut {
				// 从脚本中提取地址
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, idx.chainParams)
				if err != nil || len(addrs) == 0 {
					continue
				}

				// 为每个地址创建UTXO索引
				for _, addr := range addrs {
					addrKey, err := idx.utxoKeyFromAddr(addr)
					if err != nil {
						continue
					}

					// 生成索引键
					key := UtxoIndexKey(addrKey, tx.Hash(), uint32(outIdx))

					// 序列化UTXO信息作为值
					value := idx.serializeUtxoValue(txOut.Value, uint32(blockHeight), isCoinBase)

					// 存入数据库
					if err := batch.Put(key, value); err != nil {
						return fmt.Errorf("无法添加UTXO索引 (地址: %s, 交易: %s, 输出索引: %d): %w",
							addr.EncodeAddress(), tx.Hash(), outIdx, err)
					}
				}
			}
		}

		// 处理交易输入，删除被花费的UTXO索引
		stxoIndex := 0
		for txIdx, tx := range transactions {
			if txIdx == 0 { // 跳过coinbase交易，它没有输入
				continue
			}

			msgTx := tx.MsgTx()
			for inIdx, txIn := range msgTx.TxIn {
				// 获取被花费的UTXO的OutPoint（从交易输入中）
				outPoint := txIn.PreviousOutPoint

				if stxoIndex >= len(stxos) {
					break
				}

				stxo := stxos[stxoIndex]
				// 从被花费的UTXO脚本中提取地址
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(stxo.PkScript, idx.chainParams)
				if err != nil || len(addrs) == 0 {
					stxoIndex++
					continue
				}

				// 为每个地址删除对应的UTXO索引
				for _, addr := range addrs {
					addrKey, err := idx.utxoKeyFromAddr(addr)
					if err != nil {
						continue
					}

					// 生成索引键（使用从交易输入获取的outPoint）
					key := UtxoIndexKey(addrKey, &outPoint.Hash, outPoint.Index)

					// 从数据库中删除
					if err := batch.Delete(key); err != nil {
						return fmt.Errorf("无法删除UTXO索引 (地址: %s, 交易: %s, 输出索引: %d, 输入索引: %d): %w",
							addr.EncodeAddress(), outPoint.Hash, outPoint.Index, inIdx, err)
					}
				}

				stxoIndex++
			}
		}

		return nil
	})
}

// DisconnectBlock 当块从主链断开时删除对应的UTXO索引条目
func (idx *AddrUtxoIndex) DisconnectBlock(block *core.Block, stxos []blockchain.SpentTxOut) error {
	transactions := block.Transactions()

	return idx.db.Update(func(batch db.IndexedBatch) error {
		// 恢复被该区块花费的UTXO（添加回来）
		stxoIndex := 0
		for txIdx, tx := range transactions {
			if txIdx == 0 { // 跳过coinbase交易
				continue
			}

			msgTx := tx.MsgTx()
			for inIdx, txIn := range msgTx.TxIn {
				// 获取被花费的UTXO的OutPoint（从交易输入中）
				outPoint := txIn.PreviousOutPoint

				if stxoIndex >= len(stxos) {
					break
				}

				stxo := stxos[stxoIndex]
				// 从被花费的UTXO脚本中提取地址
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(stxo.PkScript, idx.chainParams)
				if err != nil || len(addrs) == 0 {
					stxoIndex++
					continue
				}

				// 为每个地址恢复UTXO索引
				for _, addr := range addrs {
					addrKey, err := idx.utxoKeyFromAddr(addr)
					if err != nil {
						continue
					}

					// 生成索引键（使用从交易输入获取的outPoint）
					key := UtxoIndexKey(addrKey, &outPoint.Hash, outPoint.Index)

					// 序列化UTXO信息作为值
					value := idx.serializeUtxoValue(stxo.Amount, uint32(stxo.Height), stxo.IsCoinBase)

					// 存入数据库
					if err := batch.Put(key, value); err != nil {
						return fmt.Errorf("无法恢复UTXO索引 (地址: %s, 交易: %s, 输出索引: %d, 输入索引: %d): %w",
							addr.EncodeAddress(), outPoint.Hash, outPoint.Index, inIdx, err)
					}
				}

				stxoIndex++
			}
		}

		// 删除该区块创建的UTXO索引
		for _, tx := range transactions {
			msgTx := tx.MsgTx()

			for outIdx := range msgTx.TxOut {
				// 从脚本中提取地址
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(msgTx.TxOut[outIdx].PkScript, idx.chainParams)
				if err != nil || len(addrs) == 0 {
					continue
				}

				// 为每个地址删除UTXO索引
				for _, addr := range addrs {
					addrKey, err := idx.utxoKeyFromAddr(addr)
					if err != nil {
						continue
					}

					// 生成索引键
					key := UtxoIndexKey(addrKey, tx.Hash(), uint32(outIdx))

					// 从数据库中删除
					if err := batch.Delete(key); err != nil {
						return fmt.Errorf("无法删除区块创建的UTXO索引 (地址: %s, 交易: %s, 输出索引: %d): %w",
							addr.EncodeAddress(), tx.Hash(), outIdx, err)
					}
				}
			}
		}

		return nil
	})
}

// UtxosForAddress 查询指定地址的UTXO
func (idx *AddrUtxoIndex) UtxosForAddress(addr utils.Address, numToSkip, numRequested uint32, reverse bool) ([]*core.OutPoint, []int64, uint32, error) {
	addrKey, err := idx.utxoKeyFromAddr(addr)
	if err != nil {
		return nil, nil, 0, err
	}

	// 构建地址前缀，用于范围查询
	prefix := db.AddrToUtxo.Key(addrKey[:])

	// 创建数据库迭代器
	iter, err := idx.db.NewIterator(prefix, true)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close()

	// 收集所有UTXO信息
	var outPoints []*core.OutPoint
	var amounts []int64

	// 正向遍历所有匹配前缀的键值对
	if iter.First() {
		for iter.Valid() {
			key := iter.Key()
			// 验证当前键是否仍然匹配前缀（防止超出范围）
			if !bytes.HasPrefix(key, prefix) {
				break
			}

			// 解析键获取交易哈希和输出索引
			data := key[len(prefix):]
			if len(data) < chainhash.HashSize+4 {
				iter.Next()
				continue
			}

			var txHash chainhash.Hash
			copy(txHash[:], data[:chainhash.HashSize])
			outIndex := binary.BigEndian.Uint32(data[chainhash.HashSize : chainhash.HashSize+4])

			// 获取并解析值（金额等信息）
			value, err := iter.Value()
			if err != nil {
				return nil, nil, uint32(len(outPoints)), fmt.Errorf("获取值失败: %w", err)
			}

			amount, _, _, err := idx.deserializeUtxoValue(value)
			if err != nil {
				iter.Next()
				continue
			}

			// 添加到结果集
			outPoints = append(outPoints, &core.OutPoint{
				Hash:  txHash,
				Index: outIndex,
			})
			amounts = append(amounts, amount)

			// 移动到下一个元素
			iter.Next()
		}
	}

	totalCount := uint32(len(outPoints))

	// 如果需要反向查询，反转结果列表
	if reverse {
		for i, j := 0, len(outPoints)-1; i < j; i, j = i+1, j-1 {
			outPoints[i], outPoints[j] = outPoints[j], outPoints[i]
			amounts[i], amounts[j] = amounts[j], amounts[i]
		}
	}

	// 应用分页逻辑
	start := numToSkip
	if start >= totalCount {
		return []*core.OutPoint{}, []int64{}, totalCount, nil
	}

	end := start + numRequested
	if end > totalCount {
		end = totalCount
	}

	return outPoints[start:end], amounts[start:end], totalCount, nil
}

// 新增常量定义，用于标识UTXO索引是否已初始化
const (
	addrUtxoIndexInitializedKey = "addrutxoidxinitialized"
)

// DropAddrUtxoIndex 删除数据库中所有UTXO索引相关的条目
func DropAddrUtxoIndex(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		// 获取UTXO索引的键前缀
		prefix := db.AddrToUtxo.Key([]byte{})

		// 创建迭代器遍历所有UTXO索引条目
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
				return fmt.Errorf("删除UTXO索引键 %x 失败: %w", key, err)
			}
		}
		// 删除初始化状态标志
		if err := batch.Delete([]byte(addrUtxoIndexInitializedKey)); err != nil {
			return fmt.Errorf("删除UTXO索引初始化标志失败: %w", err)
		}
		return nil
	})
}

// AddrUtxoIndexInitialized 检查UTXO索引是否已初始化
func AddrUtxoIndexInitialized(dataBase db.KeyValueStore) bool {
	// 使用Has方法检查初始化标志是否存在
	exists, err := dataBase.Has([]byte(addrUtxoIndexInitializedKey))
	if err != nil {
		// 发生错误时默认视为未初始化
		return false
	}
	return exists
}

// MarkAddrUtxoIndexInitialized 标记UTXO索引已初始化
func MarkAddrUtxoIndexInitialized(dataBase db.KeyValueStore) error {
	return dataBase.Update(func(batch db.IndexedBatch) error {
		// 存储一个非空值表示索引已初始化
		return batch.Put([]byte(addrUtxoIndexInitializedKey), []byte("1"))
	})
}

// NewAddrUtxoIndex 创建一个新的AddrUtxoIndex实例
func NewAddrUtxoIndex(db db.KeyValueStore, chainParams *core.Params) *AddrUtxoIndex {
	return &AddrUtxoIndex{
		db:          db,
		chainParams: chainParams,
	}
}

func (idx *AddrUtxoIndex) Key() []byte {
	return addrUtxoKey
}

func (idx *AddrUtxoIndex) Name() string {
	return addrUtxoIdxName
}

// GetAddressAllUTXO 查询指定地址的所有未花费UTXO
func (idx *AddrUtxoIndex) GetAddressAllUTXO(addr utils.Address) ([]*blockchain.UtxoEntry, error) {
	// 获取地址对应的键
	addrKey, err := idx.utxoKeyFromAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("无法转换地址为索引键: %w", err)
	}

	// 构建地址前缀，用于范围查询
	prefix := db.AddrToUtxo.Key(addrKey[:])

	// 创建数据库迭代器
	iter, err := idx.db.NewIterator(prefix, true)
	if err != nil {
		return nil, fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close()

	// 收集所有UTXO信息
	var utxoEntries []*blockchain.UtxoEntry

	// 遍历所有匹配前缀的键值对
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		// 验证当前键是否仍然匹配前缀
		if !bytes.HasPrefix(key, prefix) {
			break
		}

		// 获取并解析值（金额等信息）
		/*		value, err := iter.Value()
				if err != nil {
					return nil, fmt.Errorf("获取值失败: %w", err)
				}

				amount, blockHeight, isCoinBase, err := idx.deserializeUtxoValue(value)
				if err != nil {
					continue
				}*/

		// 从键中解析出交易哈希和输出索引
		data := key[len(prefix):]
		if len(data) < chainhash.HashSize+4 {
			continue
		}

		var txHash chainhash.Hash
		copy(txHash[:], data[:chainhash.HashSize])
		outIndex := binary.BigEndian.Uint32(data[chainhash.HashSize : chainhash.HashSize+4])

		// 根据交易哈希和输出索引获取完整的UTXO信息
		// 这里假设存在获取UTXO完整信息的方法
		utxo, err := idx.getUTXOByOutPoint(&txHash, outIndex)
		if err != nil {
			// 如果UTXO已被花费，跳过
			if errors.Is(err, db.ErrKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("获取UTXO信息失败: %w", err)
		}

		utxoEntries = append(utxoEntries, utxo)
	}

	return utxoEntries, nil
}

// 查询指定地址的所有未花费UTXO，包含完整信息
func (idx *AddrUtxoIndex) GetAddressAllUTXOFull(addr utils.Address) ([]*blockchain.UtxoEntryFull, error) {
	// 获取地址对应的键
	addrKey, err := idx.utxoKeyFromAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("无法转换地址为索引键: %w", err)
	}

	// 构建地址前缀，用于范围查询
	prefix := db.AddrToUtxo.Key(addrKey[:])

	// 创建数据库迭代器
	iter, err := idx.db.NewIterator(prefix, true)
	if err != nil {
		return nil, fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close()

	// 收集所有UTXO信息
	var utxoEntries []*blockchain.UtxoEntryFull

	// 遍历所有匹配前缀的键值对
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		// 验证当前键是否仍然匹配前缀
		if !bytes.HasPrefix(key, prefix) {
			break
		}

		/*		// 获取并解析值（金额等信息）
				value, err := iter.Value()
				if err != nil {
					return nil, fmt.Errorf("获取值失败: %w", err)
				}

				amount, blockHeight, isCoinBase, err := idx.deserializeUtxoValue(value)
				if err != nil {
					continue
				}*/

		// 从键中解析出交易哈希和输出索引
		data := key[len(prefix):]
		if len(data) < chainhash.HashSize+4 {
			continue
		}

		var txHash chainhash.Hash
		copy(txHash[:], data[:chainhash.HashSize])
		outIndex := binary.BigEndian.Uint32(data[chainhash.HashSize : chainhash.HashSize+4])

		// 根据交易哈希和输出索引获取完整的UTXO信息
		utxo, err := idx.getUTXOByOutPoint(&txHash, outIndex)
		if err != nil {
			// 如果UTXO已被花费，跳过
			if errors.Is(err, db.ErrKeyNotFound) {
				continue
			}
			return nil, fmt.Errorf("获取UTXO信息失败: %w", err)
		}

		// 创建包含完整信息的UTXO条目
		utxoFull := &blockchain.UtxoEntryFull{
			UtxoEntry: *utxo,
			Hash:      txHash,
			Index:     outIndex,
		}

		utxoEntries = append(utxoEntries, utxoFull)
	}

	return utxoEntries, nil
}

// getUTXOByOutPoint 根据交易哈希和输出索引获取UTXO完整信息
// 这个方法需要根据实际的UTXO存储实现进行调整
func (idx *AddrUtxoIndex) getUTXOByOutPoint(txHash *chainhash.Hash, index uint32) (*blockchain.UtxoEntry, error) {
	// 构造UTXO查询键
	// 这里假设UTXO存储在db.UTXOBucket中，键的格式为交易哈希+输出索引
	outPointBytes := make([]byte, chainhash.HashSize+4)
	copy(outPointBytes[:chainhash.HashSize], txHash[:])
	binary.LittleEndian.PutUint32(outPointBytes[chainhash.HashSize:], index)
	utxoKey := db.UTXOBucket.Key(outPointBytes)

	// 从数据库读取UTXO数据
	var utxoBytes []byte
	err := idx.db.Get(utxoKey, func(value []byte) error {
		if value == nil {
			return db.ErrKeyNotFound
		}
		utxoBytes = make([]byte, len(value))
		copy(utxoBytes, value)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 反序列化UTXO数据
	var protoUTXO wire.ProtoUtxoEntry
	if err := proto.Unmarshal(utxoBytes, &protoUTXO); err != nil {
		return nil, fmt.Errorf("反序列化UTXO失败: %w", err)
	}

	utxoEntry := &blockchain.UtxoEntry{}
	if err := utxoEntry.FromProto(&protoUTXO); err != nil {
		return nil, fmt.Errorf("转换UTXO格式失败: %w", err)
	}

	// 检查UTXO是否已被花费
	if utxoEntry.IsSpent() {
		return nil, db.ErrKeyNotFound
	}

	return utxoEntry, nil
}

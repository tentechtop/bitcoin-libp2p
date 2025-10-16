package db

import (
	"encoding/binary"
	"slices"
)

type Bucket byte

const (
	MainLatestHeight  = "MainLatestHeight"
	MainLatestHash    = "MainLatestHash"
	MainLatestWork    = "MainLatestWork"
	PeerKeyBucket     = "peer_key_bucket"  // 存储节点密钥的桶
	PeerPrivateKeyKey = "peer_private_key" // 密钥在桶中的键
)

// BlockHeaderBucket 把“桶编号 + 任意多的 key 片段”拼成一个最终的数据库 key。
// 桶（Bucket）类型与取值
// 数据库里可以划分多个“逻辑分区/命名空间”，每个分区用一个 byte 编号表示，叫 Bucket。
const (
	// hash到区块头
	BlockHeaderBucket    Bucket = iota //
	BlockBodyBucket                    // 仅仅交易部分
	HeightToBlockBucket                // 主链高度到区块Hash的索引
	TxToBlockBucket                    // 新增：交易ID到区块hash+索引的映射
	UTXOBucket                         // 新增：UTXO数据
	HashToChinaWork                    // Hash到工作总量缓存
	HashToHeight                       // Hash到高度的缓存
	MainStatus                         // 主链状态
	PersistentPeerBucket               // 节点信息
	UTXOStateConsistencyBucket

	AddressToTx //地址到交易
	AddrToUtxo
	AddressToTxExists
)

// Int64Key 处理int64类型的键，将其编码为8字节后与桶编号拼接
// 采用大端序（BigEndian）编码，保证数值比较与字节序比较一致
func (bu Bucket) Int64Key(num int64) []byte {
	// 为int64分配8字节缓冲区（固定长度）
	buf := make([]byte, 8)
	// 使用大端序编码int64（网络字节序，保证跨平台一致性）
	binary.BigEndian.PutUint64(buf, uint64(num))
	// 拼接桶编号和编码后的int64字节
	return append([]byte{byte(bu)}, buf...)
}

func (bu Bucket) Int32Key(value int32) []byte {
	// 为int32分配4字节缓冲区（固定长度）
	buf := make([]byte, 4)
	// 使用大端序编码int32（网络字节序，保证跨平台一致性）
	binary.BigEndian.PutUint32(buf, uint32(value))
	// 拼接桶编号和编码后的int32字节（与Int64Key保持相同格式）
	return append([]byte{byte(bu)}, buf...)
}

// Key 调用者：StateTrie.Key(k1, k2, k3 …)
// 返回值：把以下部分按顺序拼成一条完整的 key
// 桶编号（1 字节）
// 后面所有 []byte 片段直接顺序拼接
// 把“桶 + 子 key 片段”编码成数据库里真正存储的 key，从而
// 保证不同桶的数据不会冲突；
// 方便前缀扫描：想遍历 StateTrie 桶，只需用 0x00 作为前缀即可。
func (bu Bucket) Key(key ...[]byte) []byte {
	return append([]byte{byte(bu)}, slices.Concat(key...)...)
}

package db

import (
	"bitcoin/utils"
)

// DefaultBatchSize 默认的批处理（batch）容量：10 MB。
// 当上层代码想“先攒够 10 MB 再一次性写盘”时，可以直接用这个常量。
const DefaultBatchSize = 10 * utils.Megabyte

// Batch 是一个“只写”的暂存区：所有改动先放在内存里，最后 Write() 一次性原子地刷到磁盘。
// 同一个 Batch 实例不能并发使用；但你可以给每个线程各开一个 Batch，并行写不同的 Batch 是没问题的。
type Batch interface {
	KeyValueWriter
	KeyValueRangeDeleter
	// Size Retrieves the value size of the data stored in the batch for writing
	Size() int
	// Write Flushes the data stored to disk
	Write() error
	// Reset Resets the batch
	Reset()
}

// Batcher 用来“生产” Batch 实例，典型实现是某个 DB 对象：
// db.NewBatch() —— 拿到一个默认大小的 Batch
// db.NewBatchWithSize(size) —— 预分配指定内存大小，避免中途扩容
type Batcher interface {
	// NewBatch Creates a write-only batch 拿到一个默认大小的 Batch
	NewBatch() Batch
	// NewBatchWithSize Creates a write-only batch with a pre-allocated size 预分配指定内存大小，避免中途扩容
	NewBatchWithSize(size int) Batch
}

// IndexedBatch = Batch + 读能力：
// 不仅能攒写入，还能同时读取
// 已提交到磁盘的数据
// 当前 Batch 里还没落盘的“脏数据”
// 只有当你必须“边写边读”并且读的范围横跨磁盘 + 内存时才用它。
// 因为每次写都要维护额外的索引（为了可读），写性能比普通 Batch 差。
// 官方建议：能不用就不用。
// 写就用普通 Batch，读就直接读 DB。只有在“事务里必须看到自己未提交的修改”这种罕见场景才考虑 IndexedBatch。
type IndexedBatch interface {
	Batch
	KeyValueReader
	Iterable
}

// IndexedBatcher 用来“生产” IndexedBatch 实例，和 Batcher 对应：
type IndexedBatcher interface {
	NewIndexedBatch() IndexedBatch
	NewIndexedBatchWithSize(size int) IndexedBatch
}

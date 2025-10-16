package db

import "io"

// KeyValueReader 这是一套Go 语言里的键值数据库抽象层（接口族），把常见的“读、写、删、批量、事务、快照、遍历、事件监听”全部拆成最小粒度的接口，再组合成一个“超级接口” KeyValueStore。
// 任何底层存储（RocksDB、Pebble、LevelDB、内存 KV 等）只要把这些接口全部实现，上层的业务代码就能无感替换。
// KeyValueReader Exposes a read-only interface to the db
type KeyValueReader interface {
	// Has Checks if a key exists in the data store
	Has(key []byte) (bool, error)
	// Get If a given key exists, the callback will be called with the value
	// Example:
	//
	//	var value []byte
	//	db.Get([]byte("key"), func(v []byte) error {
	//		value = v
	//		return nil
	//	})
	Get(key []byte, cb func(value []byte) error) error
}

// KeyValueWriter Exposes a write-only interface to the db
type KeyValueWriter interface {
	// Put Inserts a given value into the data store
	Put(key []byte, value []byte) error
	// Delete Deletes a given key from the data store
	Delete(key []byte) error
}

// KeyValueRangeDeleter Exposes a range-deletion interface to the db
type KeyValueRangeDeleter interface {
	// DeleteRange Deletes a range of keys from start (inclusive) to end (exclusive)
	DeleteRange(start, end []byte) error
}

// Helper interface
type Helper interface {
	// Update This will create a read-write transaction, apply the callback to it, and flush the changes
	Update(func(IndexedBatch) error) error
	// View This will create a read-only snapshot and apply the callback to it
	View(func(Snapshot) error) error
	// Impl TODO(weiihann): honestly this doesn't make sense, but it's currently needed for the metrics
	// remove this once the metrics are refactored
	// Returns the underlying db
	Impl() any
}

// KeyValueStore Represents a key-value data store that can handle different operations
type KeyValueStore interface {
	// KeyValueReader 只读 Has 判断 key 是否存在；Get 读取 value（用回调避免复制）
	KeyValueReader
	// KeyValueWriter 只写 Put 写；Delete 删单条
	KeyValueWriter
	// KeyValueRangeDeleter 范围删除 DeleteRange(start, end) 把 [start, end) 区间内的 key 一次性全部删掉
	KeyValueRangeDeleter
	// Batcher  IndexedBatches 批量写 创建 Batch 或 IndexedBatch 攒一批改动再原子刷盘（
	Batcher
	IndexedBatcher
	// Snapshotter 快照 拿一个只读快照，保证读视图不受后续写影响
	Snapshotter
	// Iterable 遍历 从任意前缀开始顺序/倒序扫描
	Iterable
	// Helper 简化事务 Update 自动开读写事务并提交；View 自动开只读快照
	Helper
	// Listener 事件监听 注册回调，在写/删发生时做钩子（如缓存失效、指标统计）
	Listener
	// Closer 生命周期 关闭数据库、释放资源
	io.Closer
}

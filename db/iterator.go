package db

import "io"

// Iterator “可迭代键值数据库” 的最小接口，作用就是： 用完必须调用 Close()，否则会泄露资源（文件句柄/内存等）。
// 一个迭代器实例不能并发使用；但你可以同时开多个迭代器，各自独立遍历。
// 让你可以在数据库里按照字典序（升序）遍历、查找指定前缀范围内的 key/value。
type Iterator interface {
	io.Closer

	// Valid 当前是否指向一条有效的记录
	Valid() bool

	// First 跳到第一条记录
	First() bool

	// Prev 跳到上一条记录（反向）
	Prev() bool

	// Next 跳到下一条记录（正向）
	Next() bool

	// Key 返回当前记录的 key
	Key() []byte

	// Value 返回当前记录的 value
	Value() ([]byte, error)

	// Seek 二分查找：先定位到 ≥ key 的第一条记录，找不到就定位到下一条更大的
	Seek(key []byte) bool
}

// Iterable Iterable（迭代器工厂接口）
// 你可以指定：
// prefix – 只遍历以该前缀开头的 key；传 nil 时遍历全库
// withUpperBound – 是否自动用上界截断（内部通常用 UpperBound 计算）
type Iterable interface {
	NewIterator(prefix []byte, withUpperBound bool) (Iterator, error)
}

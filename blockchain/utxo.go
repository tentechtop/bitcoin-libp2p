package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/wire"
	"errors"
)

type txoFlags uint8

const (
	// tfCoinBase indicates that a txout was contained in a coinbase tx.
	tfCoinBase txoFlags = 1 << iota

	// tfSpent indicates that a txout is spent.
	tfSpent

	// tfModified indicates that a txout has been modified since it was
	// loaded.
	tfModified

	// tfFresh indicates that the entry is fresh.  This means that the parent
	// view never saw this entry.  Note that tfFresh is a performance
	// optimization with which we can erase entries that are fully spent if we
	// know we do not need to commit them.  It is always safe to not mark
	// tfFresh if that condition is not guaranteed.
	tfFresh
)

// UtxoEntry houses details about an individual transaction output in a utxo
// view such as whether or not it was contained in a coinbase tx, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
type UtxoEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	amount      int64
	pkScript    []byte // The public key script for the output.
	blockHeight int32  // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags txoFlags
}

type UtxoEntryFull struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.

	Hash  chainhash.Hash
	Index uint32
	UtxoEntry
}

func (u *UtxoEntry) ToProto() (*wire.ProtoUtxoEntry, error) {
	return &wire.ProtoUtxoEntry{
		Amount:      u.amount,              // int64 → int64（直接映射）
		PkScript:    u.pkScript,            // []byte → bytes（Go 中本质一致，直接映射）
		BlockHeight: u.blockHeight,         // int32 → int32（直接映射）
		PackedFlags: uint32(u.packedFlags), // txoFlags → uint32（类型转换，依赖 txoFlags 是 uint32 别名）
	}, nil
}

// ---------------- ProtoUtxoEntry → UtxoEntry ----------------
// FromProto 从 Protobuf 结构体 ProtoUtxoEntry 加载数据到当前 UtxoEntry
// 支持复用已有 UtxoEntry 实例，避免重复分配内存
func (u *UtxoEntry) FromProto(pb *wire.ProtoUtxoEntry) error {
	// 基础校验：入参不能为 nil
	if pb == nil {
		return errors.New("proto UtxoEntry is nil")
	}

	// 核心字段校验：金额非负
	if pb.Amount < 0 {
		return errors.New("proto utxo amount cannot be negative")
	}

	// 字段一一反向映射
	u.amount = pb.Amount
	u.pkScript = pb.PkScript // bytes → []byte（直接赋值，Go 中为引用类型，若需深拷贝可使用 copy）
	u.blockHeight = pb.BlockHeight
	u.packedFlags = txoFlags(pb.PackedFlags) // uint32 → txoFlags（类型转换）

	return nil
}

// NewUtxoEntryFromProto 从 ProtoUtxoEntry 创建新的 UtxoEntry 实例
// 适用于需要新建实例的场景，内部复用 FromProto 实现校验逻辑
func NewUtxoEntryFromProto(pb *wire.ProtoUtxoEntry) (*UtxoEntry, error) {
	u := &UtxoEntry{}
	if err := u.FromProto(pb); err != nil {
		return nil, err
	}
	return u, nil
}

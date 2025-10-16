package wire

import (
	"bitcoin/chaincfg/chainhash"
)

const (
	// MaxInvPerMsg is the maximum number of inventory vectors that can be in a
	// single bitcoin inv message.
	MaxInvPerMsg = 50000

	// Maximum payload size for an inventory vector.
	maxInvVectPayload = 4 + chainhash.HashSize

	// InvWitnessFlag denotes that the inventory vector type is requesting,
	// or sending a version which includes witness data.
	InvWitnessFlag = 1 << 30
)

type InvVect struct {
	Type InvType        // Type of data
	Hash chainhash.Hash // Hash of the data
}

func NewInvVect(typ InvType, hash *chainhash.Hash) *InvVect {
	return &InvVect{
		Type: typ,
		Hash: *hash,
	}
}

const (
	InvTypeError                InvType = 0
	InvTypeTx                   InvType = 1
	InvTypeBlock                InvType = 2
	InvTypeFilteredBlock        InvType = 3
	InvTypeWitnessBlock         InvType = InvTypeBlock | InvWitnessFlag
	InvTypeWitnessTx            InvType = InvTypeTx | InvWitnessFlag
	InvTypeFilteredWitnessBlock InvType = InvTypeFilteredBlock | InvWitnessFlag
)

var ivStrings = map[InvType]string{
	InvTypeError:                "ERROR",
	InvTypeTx:                   "MSG_TX",
	InvTypeBlock:                "MSG_BLOCK",
	InvTypeFilteredBlock:        "MSG_FILTERED_BLOCK",
	InvTypeWitnessBlock:         "MSG_WITNESS_BLOCK",
	InvTypeWitnessTx:            "MSG_WITNESS_TX",
	InvTypeFilteredWitnessBlock: "MSG_FILTERED_WITNESS_BLOCK",
}

// 实现ProtoInvVect的ToProto方法：转换为protobuf结构体
func (iv *InvVect) ToProto() *ProtoInvVect {
	return &ProtoInvVect{
		Type: iv.Type,
		Hash: iv.Hash.GetBytes(), // 直接使用bytes类型的hash
	}
}

// 实现ProtoInvVect的FromProto方法：从protobuf结构体转换回来
func (iv *InvVect) FromProto(pb *ProtoInvVect) {
	hash, _ := chainhash.BytesToHash(pb.Hash)
	iv.Type = pb.Type
	iv.Hash = hash
}

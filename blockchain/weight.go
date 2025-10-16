package blockchain

import (
	"bitcoin/core"
	"bitcoin/txscript"
	"fmt"
)

const (
	// MaxBlockWeight defines the maximum block weight, where "block
	// weight" is interpreted as defined in BIP0141. A block's weight is
	// calculated as the sum of the of bytes in the existing transactions
	// and header, plus the weight of each byte within a transaction. The
	// weight of a "base" byte is 4, while the weight of a witness byte is
	// 1. As a result, for a block to be valid, the BlockWeight MUST be
	// less than, or equal to MaxBlockWeight.
	MaxBlockWeight = 4000000

	// MaxBlockBaseSize is the maximum number of bytes within a block
	// which can be allocated to non-witness data.
	MaxBlockBaseSize = 1000000

	// MaxBlockSigOpsCost is the maximum number of signature operations
	// allowed for a block. It is calculated via a weighted algorithm which
	// weights segregated witness sig ops lower than regular sig ops.
	MaxBlockSigOpsCost = 80000

	// WitnessScaleFactor determines the level of "discount" witness data
	// receives compared to "base" data. A scale factor of 4, denotes that
	// witness data is 1/4 as cheap as regular non-witness data.
	WitnessScaleFactor = 4

	// MinTxOutputWeight is the minimum possible weight for a transaction
	// output.
	MinTxOutputWeight = WitnessScaleFactor * core.MinTxOutPayload

	// MaxOutputsPerBlock is the maximum number of transaction outputs there
	// can be in a block of max weight size.
	MaxOutputsPerBlock = MaxBlockWeight / MinTxOutputWeight
)

func GetTransactionWeight(tx *core.Tx) int64 {
	msgTx := tx.MsgTx()

	baseSize := msgTx.SerializeSizeStripped()
	totalSize := msgTx.SerializeSize()

	// (baseSize * 3) + totalSize
	return int64((baseSize * (WitnessScaleFactor - 1)) + totalSize)
}

func GetSigOpCost(tx *core.Tx, isCoinBaseTx bool, utxoView *UtxoViewpoint) (int, error) {
	numSigOps := CountSigOps(tx) * WitnessScaleFactor
	numP2SHSigOps, err := CountP2SHSigOps(tx, isCoinBaseTx, utxoView)
	if err != nil {
		return 0, nil
	}
	numSigOps += (numP2SHSigOps * WitnessScaleFactor)

	if !isCoinBaseTx {
		msgTx := tx.MsgTx()
		for txInIndex, txIn := range msgTx.TxIn {
			// Ensure the referenced output is available and hasn't
			// already been spent.
			utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
			if utxo == nil || utxo.IsSpent() {
				str := fmt.Sprintf("output %v referenced from "+
					"transaction %s:%d either does not "+
					"exist or has already been spent",
					txIn.PreviousOutPoint, tx.Hash(),
					txInIndex)
				return 0, ruleError(ErrMissingTxOut, str)
			}

			witness := txIn.Witness
			sigScript := txIn.SignatureScript
			pkScript := utxo.PkScript()
			numSigOps += txscript.GetWitnessSigOpCount(sigScript, pkScript, witness)
		}

	}

	return numSigOps, nil
}

func GetBlockWeight(blk *core.Block) int64 {
	msgBlock := blk.MsgBlock()

	baseSize := msgBlock.SerializeSizeStripped()
	totalSize := msgBlock.SerializeSize()

	// (baseSize * 3) + totalSize
	return int64((baseSize * (WitnessScaleFactor - 1)) + totalSize)
}

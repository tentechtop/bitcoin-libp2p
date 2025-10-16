package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/txscript"
	"io"
	"math/bits"
)

var (
	// WitnessMagicBytes is the prefix marker within the public key script
	// of a coinbase output to indicate that this output holds the witness
	// commitment for a block.
	WitnessMagicBytes = []byte{
		txscript.OP_RETURN,
		txscript.OP_DATA_36,
		0xaa,
		0x21,
		0xa9,
		0xed,
	}
)

const (
	// CoinbaseWitnessDataLen is the required length of the only element within
	// the coinbase's witness data if the coinbase transaction contains a
	// witness commitment.
	CoinbaseWitnessDataLen = 32

	// CoinbaseWitnessPkScriptLength is the length of the public key script
	// containing an OP_RETURN, the WitnessMagicBytes, and the witness
	// commitment itself. In order to be a valid candidate for the output
	// containing the witness commitment
	CoinbaseWitnessPkScriptLength = 38
)

type rollingMerkleTreeStore struct {
	// roots are where the temporary merkle roots get stored while the
	// merkle root is being calculated.
	roots []chainhash.Hash

	// numLeaves is the total leaves the store has processed.  numLeaves
	// is required for the root calculation algorithm to work.
	numLeaves uint64
}

func CalcMerkleRoot(transactions []*core.Tx, witness bool) chainhash.Hash {
	s := newRollingMerkleTreeStore(uint64(len(transactions)))
	return s.calcMerkleRoot(transactions, witness)
}

func newRollingMerkleTreeStore(size uint64) rollingMerkleTreeStore {
	var alloc int
	if size != 0 {
		alloc = bits.Len64(size - 1)
	}
	return rollingMerkleTreeStore{roots: make([]chainhash.Hash, 0, alloc)}
}

func (s *rollingMerkleTreeStore) add(add chainhash.Hash) {
	// We can tell where the roots are by looking at the binary representation
	// of the numLeaves.  Wherever there's a 1, there's a root.
	//
	// numLeaves of 8 will be '1000' in binary, so there will be one root at
	// row 3. numLeaves of 3 will be '11' in binary, so there's two roots.  One at
	// row 0 and one at row 1.  Row 0 is the leaf row.
	//
	// In this loop below, we're looking for these roots by checking if there's
	// a '1', starting from the LSB.  If there is a '1', we'll hash the root being
	// added with that root until we hit a '0'.
	newRoot := add
	for h := uint8(0); (s.numLeaves>>h)&1 == 1; h++ {
		// Pop off the last root.
		var root chainhash.Hash
		root, s.roots = s.roots[len(s.roots)-1], s.roots[:len(s.roots)-1]

		// Calculate the hash of the new root and append it.
		newRoot = HashMerkleBranches(&root, &newRoot)
	}
	s.roots = append(s.roots, newRoot)
	s.numLeaves++
}

func HashMerkleBranches(left, right *chainhash.Hash) chainhash.Hash {
	// Concatenate the left and right nodes.
	var hash [chainhash.HashSize * 2]byte
	copy(hash[:chainhash.HashSize], left[:])
	copy(hash[chainhash.HashSize:], right[:])

	return chainhash.DoubleHashRaw(func(w io.Writer) error {
		_, err := w.Write(hash[:])
		return err
	})
}

func (s *rollingMerkleTreeStore) calcMerkleRoot(adds []*core.Tx, witness bool) chainhash.Hash {
	for i := range adds {
		// If we're computing a witness merkle root, instead of the
		// regular txid, we use the modified wtxid which includes a
		// transaction's witness data within the digest.  Additionally,
		// the coinbase's wtxid is all zeroes.
		switch {
		case witness && i == 0:
			var zeroHash chainhash.Hash
			s.add(zeroHash)
		case witness:
			s.add(*adds[i].WitnessHash())
		default:
			s.add(*adds[i].Hash())
		}
	}

	// If we only have one leaf, then the hash of that tx is the merkle root.
	if s.numLeaves == 1 {
		return s.roots[0]
	}

	// Add on the last tx again if there's an odd number of txs.
	if len(adds) > 0 && len(adds)%2 != 0 {
		switch {
		case witness:
			s.add(*adds[len(adds)-1].WitnessHash())
		default:
			s.add(*adds[len(adds)-1].Hash())
		}
	}

	// If we still have more than 1 root after adding on the last tx again,
	// we need to do the same for the upper rows.
	//
	// For example, the below tree has 6 leaves.  For row 1, you'll need to
	// hash 'F' with itself to create 'C' so you have something to hash with
	// 'B'.  For bigger trees we may need to do the same in rows 2 or 3 as
	// well.
	//
	// row :3         A
	//              /   \
	// row :2     B       C
	//           / \     / \
	// row :1   D   E   F   F
	//         / \ / \ / \
	// row :0  1 2 3 4 5 6
	for len(s.roots) > 1 {
		// If we have to keep adding the last node in the set, bitshift
		// the num leaves right by 1.  This effectively moves the row up
		// for calculation.  We do this until we reach a row where there's
		// an odd number of leaves.
		//
		// row :3         A
		//              /   \
		// row :2     B       C        D
		//           / \     / \     /   \
		// row :1   E   F   G   H   I     J
		//         / \ / \ / \ / \ / \   / \
		// row :0  1 2 3 4 5 6 7 8 9 10 11 12
		//
		// In the above tree, 12 leaves were added and there's an odd amount
		// of leaves at row 2.  Because of this, we'll bitshift right twice.
		currentLeaves := s.numLeaves
		for h := uint8(0); (currentLeaves>>h)&1 == 0; h++ {
			s.numLeaves >>= 1
		}

		// Add the last root again so that it'll get hashed with itself.
		h := s.roots[len(s.roots)-1]
		s.add(h)
	}

	return s.roots[0]
}

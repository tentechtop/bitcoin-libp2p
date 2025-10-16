package chainhash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"lukechampine.com/blake3"
)

// HashSize 是用于存储哈希值的数组大小。参见 Hash。
const HashSize = 32

// Hash 用于比特币消息和常见结构中的多个地方。它通常表示数据的双 sha256 哈希值。
type Hash [HashSize]byte

var (
	// TagBIP0340Challenge is the BIP-0340 tag for challenges.
	TagBIP0340Challenge = []byte("BIP0340/challenge")

	// TagBIP0340Aux is the BIP-0340 tag for aux data.
	TagBIP0340Aux = []byte("BIP0340/aux")

	// TagBIP0340Nonce is the BIP-0340 tag for nonces.
	TagBIP0340Nonce = []byte("BIP0340/nonce")

	// TagTapSighash is the tag used by BIP 341 to generate the sighash
	// flags.
	TagTapSighash = []byte("TapSighash")

	// TagTagTapLeaf is the message tag prefix used to compute the hash
	// digest of a tapscript leaf.
	TagTapLeaf = []byte("TapLeaf")

	// TagTapBranch is the message tag prefix used to compute the
	// hash digest of two tap leaves into a taproot branch node.
	TagTapBranch = []byte("TapBranch")

	// TagTapTweak is the message tag prefix used to compute the hash tweak
	// used to enable a public key to commit to the taproot branch root
	// for the witness program.
	TagTapTweak = []byte("TapTweak")

	// precomputedTags is a map containing the SHA-256 hash of the BIP-0340
	// tags.
	precomputedTags = map[string]Hash{
		string(TagBIP0340Challenge): sha256.Sum256(TagBIP0340Challenge),
		string(TagBIP0340Aux):       sha256.Sum256(TagBIP0340Aux),
		string(TagBIP0340Nonce):     sha256.Sum256(TagBIP0340Nonce),
		string(TagTapSighash):       sha256.Sum256(TagTapSighash),
		string(TagTapLeaf):          sha256.Sum256(TagTapLeaf),
		string(TagTapBranch):        sha256.Sum256(TagTapBranch),
		string(TagTapTweak):         sha256.Sum256(TagTapTweak),
	}
)

// MaxHashStringSize 是哈希字符串的最大长度。
const MaxHashStringSize = HashSize * 2

// ErrHashStrSize 描述了一个错误，表明调用者指定了一个过长的哈希字符串。
var ErrHashStrSize = fmt.Errorf("最大哈希字符串长度为 %v 字节", MaxHashStringSize)

// String 返回哈希作为字节反转哈希的十六进制字符串。
func (hash Hash) String() string {
	for i := 0; i < HashSize/2; i++ {
		hash[i], hash[HashSize-1-i] = hash[HashSize-1-i], hash[i]
	}
	return hex.EncodeToString(hash[:])
}

// CloneBytes 返回表示哈希的字节的副本作为字节切片。
//
// 注意：通常直接切片哈希更便宜，而不是调用此方法，从而重用相同的字节。
func (hash *Hash) CloneBytes() []byte {
	newHash := make([]byte, HashSize)
	copy(newHash, hash[:])
	return newHash
}

// SetBytes 设置表示哈希的字节。如果传入的字节数不是 HashSize，则返回错误。
func (hash *Hash) SetBytes(newHash []byte) error {
	nhlen := len(newHash)
	if nhlen != HashSize {
		return fmt.Errorf("无效的哈希长度 %v，需要 %v", nhlen,
			HashSize)
	}
	copy(hash[:], newHash)

	return nil
}

// IsEqual 如果目标与哈希相同，则返回 true。
func (hash *Hash) IsEqual(target *Hash) bool {
	if hash == nil && target == nil {
		return true
	}
	if hash == nil || target == nil {
		return false
	}
	return *hash == *target
}

// MarshalJSON 将哈希序列化为适当的 JSON 字符串值。
func (hash Hash) MarshalJSON() ([]byte, error) {
	return json.Marshal(hash.String())
}

// UnmarshalJSON 解析具有适当 JSON 字符串值的哈希。
func (hash *Hash) UnmarshalJSON(input []byte) error {
	// 如果第一个字节表示数组，则哈希可能已使用旧方法进行序列化并持久化。
	if len(input) > 0 && input[0] == '[' {
		return decodeLegacy(hash, input)
	}

	var sh string
	err := json.Unmarshal(input, &sh)
	if err != nil {
		return err
	}
	newHash, err := NewHashFromStr(sh)
	if err != nil {
		return err
	}

	return hash.SetBytes(newHash[:])
}

func (h *Hash) GetBytes() []byte {
	return h[:]
}

// NewHash 从字节切片返回一个新的哈希。如果传入的字节数不是 HashSize，则返回错误。
func NewHash(newHash []byte) (*Hash, error) {
	var sh Hash
	err := sh.SetBytes(newHash)
	if err != nil {
		return nil, err
	}
	return &sh, err
}

// NewHashFromStr 从哈希字符串创建一个哈希。该字符串应该是字节反转哈希的十六进制字符串，但任何缺失的字符都会在哈希的末尾用零填充。
func NewHashFromStr(hash string) (*Hash, error) {
	ret := new(Hash)
	err := Decode(ret, hash)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// Decode 将哈希的字节反转十六进制字符串解码到目标。
func Decode(dst *Hash, src string) error {
	// 如果哈希字符串过长，则返回错误。
	if len(src) > MaxHashStringSize {
		return ErrHashStrSize
	}

	// 十六进制解码器期望哈希是 2 的倍数。如果不是，则用前导零填充。
	var srcBytes []byte
	if len(src)%2 == 0 {
		srcBytes = []byte(src)
	} else {
		srcBytes = make([]byte, 1+len(src))
		srcBytes[0] = '0'
		copy(srcBytes[1:], src)
	}

	// 将源字节十六进制解码到临时目标。
	var reversedHash Hash
	_, err := hex.Decode(reversedHash[HashSize-hex.DecodedLen(len(srcBytes)):], srcBytes)
	if err != nil {
		return err
	}

	// 从临时哈希到目标的反转复制。因为临时哈希被置零了，所以写入的结果将正确填充。
	for i, b := range reversedHash[:HashSize/2] {
		dst[i], dst[HashSize-1-i] = reversedHash[HashSize-1-i], b
	}

	return nil
}

// decodeLegacy 解码使用旧方法（即表示为字节数组）编码的哈希到目标。
func decodeLegacy(dst *Hash, src []byte) error {
	var hashBytes []byte
	err := json.Unmarshal(src, &hashBytes)
	if err != nil {
		return err
	}
	if len(hashBytes) != HashSize {
		return ErrHashStrSize
	}
	return dst.SetBytes(hashBytes)
}

// HashB calculates hash(b) and returns the resulting bytes.
func HashB(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}

// HashH calculates hash(b) and returns the resulting bytes as a Hash.
func HashH(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// DoubleHashH calculates hash(hash(b)) and returns the resulting bytes as a
// Hash.
func DoubleHashH(b []byte) Hash {
	first := sha256.Sum256(b)
	return Hash(sha256.Sum256(first[:]))
}

// DoubleHashRaw calculates hash(hash(w)) where w is the resulting bytes from
// the given serialize function and returns the resulting bytes as a Hash.
func DoubleHashRaw(serialize func(w io.Writer) error) Hash {
	// Encode the transaction into the hash.  Ignore the error returns
	// since the only way the encode could fail is being out of memory
	// or due to nil pointers, both of which would cause a run-time panic.
	h := sha256.New()
	_ = serialize(h)

	// This buf is here because Sum() will append the result to the passed
	// in byte slice.  Pre-allocating here saves an allocation on the second
	// hash as we can reuse it.  This allocation also does not escape to the
	// heap, saving an allocation.
	buf := make([]byte, 0, HashSize)
	first := h.Sum(buf)
	h.Reset()
	h.Write(first)
	res := h.Sum(buf)
	return *(*Hash)(res)
}

func Hash256(data []byte) Hash {
	return blake3.Sum256(data)
}

func Hash256FromWriter(fn func(w io.Writer) error) Hash {
	var buf bytes.Buffer
	if err := fn(&buf); err != nil {
		return Hash{}
	}
	return blake3.Sum256(buf.Bytes())
}

func TaggedHash(tag []byte, msgs ...[]byte) *Hash {
	// Check to see if we've already pre-computed the hash of the tag. If
	// so then this'll save us an extra sha256 hash.
	shaTag, ok := precomputedTags[string(tag)]
	if !ok {
		shaTag = sha256.Sum256(tag)
	}

	// h = sha256(sha256(tag) || sha256(tag) || msg)
	h := sha256.New()
	h.Write(shaTag[:])
	h.Write(shaTag[:])

	for _, msg := range msgs {
		h.Write(msg)
	}

	taggedHash := h.Sum(nil)

	// The function can't error out since the above hash is guaranteed to
	// be 32 bytes.
	hash, _ := NewHash(taggedHash)

	return hash
}

// BytesToHash 将字节切片转换为Hash类型。如果字节长度不等于HashSize，返回错误。
func BytesToHash(b []byte) (Hash, error) {
	var hash Hash
	if len(b) != HashSize {
		return hash, fmt.Errorf("无效的字节长度 %d，需要 %d", len(b), HashSize)
	}
	// 将输入字节复制到Hash数组中
	copy(hash[:], b)
	return hash, nil
}

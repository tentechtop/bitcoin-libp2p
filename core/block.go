package core

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/wire"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io"
	"lukechampine.com/blake3"
	"math/big"
)

var byteOrder = binary.LittleEndian

type OutOfRangeError string

func (e OutOfRangeError) Error() string {
	return string(e)
}

var (
	// ErrBadPowBits 表示区块头里的 compact 难度值（bits）无效
	ErrBadPowBits = errors.New("invalid compact bits")

	// ErrPowTooHigh 表示区块哈希未满足当前目标难度
	ErrPowTooHigh = errors.New("block hash does not satisfy target difficulty")
)

// MsgBlock 业务结构体 ↔ protobuf 结构体 互相转换
type MsgBlock struct {
	Header       BlockHeader
	Transactions []*MsgTx
}

type MsgBlockBody struct {
	Hash         *chainhash.Hash
	Txs          int32
	Transactions []*MsgTx
	chainWork    *big.Int
}

const BlockHeightUnknown = int32(-1)

type TxLoc struct {
	TxStart int
	TxLen   int
}

type Block struct {
	msgBlock                 *MsgBlock
	serializedBlock          []byte
	SerializedBlockNoWitness []byte
	BlockHash                *chainhash.Hash
	BlockHeight              int32
	transactions             []*Tx
	txnsGenerated            bool
	chainWork                *big.Int
	IsMainChain              bool
}

const blockHeaderLen = 80

type BlockHeader struct {
	Version   int32
	PrevBlock chainhash.Hash
	//对区块内交易的承诺
	MerkleRoot chainhash.Hash
	Timestamp  int64
	Bits       uint32
	Nonce      uint32
}

func (h *BlockHeader) BlockHash() chainhash.Hash {
	var buf [80]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(h.Version))
	copy(buf[4:36], h.PrevBlock[:])
	copy(buf[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint32(buf[68:72], uint32(h.Timestamp)) // 注意 Timestamp 是 4 字节
	binary.LittleEndian.PutUint32(buf[72:76], h.Bits)
	binary.LittleEndian.PutUint32(buf[76:80], h.Nonce)
	return blake3.Sum256(buf[:])
}

func (b *Block) MsgBlock() *MsgBlock {
	return b.msgBlock
}

func (b *Block) SetHeight(height int32) {
	b.BlockHeight = height
}

func (msg *MsgBlock) AddTransaction(tx *MsgTx) error {
	msg.Transactions = append(msg.Transactions, tx)
	return nil
}

func NewBlock(msgBlock *MsgBlock) *Block {
	return &Block{
		msgBlock:    msgBlock,
		BlockHeight: BlockHeightUnknown,
	}
}

func NewBlockByHeaderAndBody(header *BlockHeader, body *MsgBlockBody) (*Block, error) {
	// 1. 校验输入参数非空
	if header == nil {
		return nil, errors.New("block header cannot be nil")
	}
	if body == nil {
		return nil, errors.New("block body cannot be nil")
	}

	// 2. 校验区块体中交易计数与实际交易列表长度一致（避免数据不一致）
	actualTxCount := int32(len(body.Transactions))
	if body.Txs != actualTxCount {
		return nil, fmt.Errorf("mismatched transaction count in block body: declared %d, actual %d", body.Txs, actualTxCount)
	}

	// 3. 用传入的 header 和 body 构建 MsgBlock（Block 的核心依赖）
	msgBlock := &MsgBlock{
		Header:       *header,           // 浅拷贝区块头（Header 为值类型，拷贝安全）
		Transactions: body.Transactions, // 引用交易列表（避免深拷贝，提升性能）
	}

	// 4. 基于 MsgBlock 创建 Block 实例
	block := NewBlock(msgBlock)

	// 5. 同步区块体的累积链工作量到 Block（若已设置）
	// 复用 body.ChainWork() 确保返回的是副本，避免外部修改内部状态
	block.chainWork = body.ChainWork()

	// 6. 返回构建完成的 Block 及无错误标识
	return block, nil
}

func (b *Block) Tx(txNum int) (*Tx, error) {
	// Ensure the requested transaction is in range.
	numTx := uint64(len(b.msgBlock.Transactions))
	if txNum < 0 || uint64(txNum) >= numTx {
		str := fmt.Sprintf("transaction index %d is out of range - max %d",
			txNum, numTx-1)
		return nil, OutOfRangeError(str)
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.transactions) == 0 {
		b.transactions = make([]*Tx, numTx)
	}

	// Return the wrapped transaction if it has already been generated.
	if b.transactions[txNum] != nil {
		return b.transactions[txNum], nil
	}

	// Generate and cache the wrapped transaction and return it.
	newTx := NewTx(b.msgBlock.Transactions[txNum])
	newTx.SetIndex(txNum)
	b.transactions[txNum] = newTx
	return newTx, nil
}

func (b *Block) TxHash(txNum int) (*chainhash.Hash, error) {
	// Attempt to get a wrapped transaction for the specified index.  It
	// will be created lazily if needed or simply return the cached version
	// if it has already been generated.
	tx, err := b.Tx(txNum)
	if err != nil {
		return nil, err
	}

	// Defer to the wrapped transaction which will return the cached hash if
	// it has already been generated.
	return tx.Hash(), nil
}

func (b *Block) TxLoc() ([]TxLoc, error) {
	rawMsg, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	rbuf := bytes.NewBuffer(rawMsg)

	var mblock MsgBlock
	txLocs, err := mblock.DeserializeTxLoc(rbuf)
	if err != nil {
		return nil, err
	}
	return txLocs, err
}

func (b *Block) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlock) != 0 {
		return b.serializedBlock, nil
	}
	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, b.msgBlock.SerializeSize()))
	err := b.msgBlock.serialize(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlock = serializedBlock
	return serializedBlock, nil
}

// ---------------- BlockHeader ----------------
func (h *BlockHeader) ToProto() *wire.ProtoBlockHeader {
	return &wire.ProtoBlockHeader{
		Version:    h.Version,
		PrevBlock:  h.PrevBlock[:],  // Hash → []byte
		MerkleRoot: h.MerkleRoot[:], // Hash → []byte
		Timestamp:  h.Timestamp,
		Bits:       h.Bits,
		Nonce:      h.Nonce,
	}
}

func (h *BlockHeader) FromProto(pb *wire.ProtoBlockHeader) {
	h.Version = pb.Version
	copy(h.PrevBlock[:], pb.PrevBlock)
	copy(h.MerkleRoot[:], pb.MerkleRoot)
	h.Timestamp = pb.Timestamp
	h.Bits = pb.Bits
	h.Nonce = pb.Nonce
}

func (h *BlockHeader) ParentHash() *chainhash.Hash {
	return &h.PrevBlock
}

// ChainWork 返回区块体关联的累积链工作量
// 链工作量是从创世块到当前块的所有工作量证明（PoW）的总和，用于判断最长链
func (bb *MsgBlockBody) ChainWork() *big.Int {
	if bb.chainWork == nil {
		return big.NewInt(0) // 未设置时返回 0
	}
	// 返回副本避免外部修改内部状态
	return new(big.Int).Set(bb.chainWork)
}

// SetChainWork 设置区块体的累积链工作量
// 需在区块验证通过后调用（计算当前块的PoW工作量，并累加前序区块的链工作量）
func (bb *MsgBlockBody) SetChainWork(work *big.Int) error {
	if work == nil || work.Sign() < 0 {
		return errors.New("chain work must be a non-nil non-negative big integer")
	}
	bb.chainWork = new(big.Int).Set(work)
	return nil
}

// ---------------- MsgBlock ----------------
func (mb *MsgBlock) ToProto() *wire.ProtoMsgBlock {
	pb := &wire.ProtoMsgBlock{
		Header: mb.Header.ToProto(),
	}
	for _, tx := range mb.Transactions {
		pb.Transactions = append(pb.Transactions, tx.ToProto()) // 复用 MsgTx.toProto
	}
	return pb
}

func (mb *MsgBlock) FromProto(pb *wire.ProtoMsgBlock) {
	mb.Header.FromProto(pb.Header)
	mb.Transactions = make([]*MsgTx, 0, len(pb.Transactions))
	for _, ptx := range pb.Transactions {
		tx := &MsgTx{}
		tx.FromProto(ptx) // 复用 MsgTx.fromProto
		mb.Transactions = append(mb.Transactions, tx)
	}
}

// Serialize 把 MsgBlock 编码为 protobuf 字节流
func (mb *MsgBlock) serialize(w io.Writer) error {
	pb := mb.ToProto()
	buf, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

func (mb *MsgBlock) serializeToBytes() ([]byte, error) {
	pb := mb.ToProto()
	return proto.Marshal(pb)
}

// Deserialize 从 protobuf 字节流解码到 MsgBlock
func (mb *MsgBlock) deserialize(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}
	pb := new(wire.ProtoMsgBlock)
	if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
		return err
	}
	mb.FromProto(pb)
	return nil
}

func (mb *MsgBlock) serializeNoWitness(w io.Writer) error {
	pb := &wire.ProtoMsgBlock{
		Header: mb.Header.ToProto(),
	}
	for _, tx := range mb.Transactions {
		// 使用 Tx 的无 witness 版本
		pb.Transactions = append(pb.Transactions, tx.ToProtoNoWitness())
	}
	raw, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// DeserializeNoWitness 从 protobuf 字节流解码到 MsgBlock（**不含 witness**）
func (mb *MsgBlock) deserializeNoWitness(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}

	pb := new(wire.ProtoMsgBlock)
	if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
		return err
	}

	// 先解析区块头
	mb.Header.FromProto(pb.Header)

	// 再解析交易（不带 witness）
	mb.Transactions = make([]*MsgTx, 0, len(pb.Transactions))
	for _, ptx := range pb.Transactions {
		tx := &MsgTx{}
		tx.FromProtoNoWitness(ptx) // 复用 MsgTx 的无 witness 还原
		mb.Transactions = append(mb.Transactions, tx)
	}
	return nil
}

// SerializeSize 返回 MsgBlock 带完整 witness 数据时 protobuf 编码后的字节数
func (mb *MsgBlock) SerializeSize() int {
	// 直接复用已有的 serializeToBytes，它内部会走 protobuf Marshal
	// 由于 protobuf 没有预先计算大小的 API，这里最简洁的实现就是先序列化再取长度
	b, _ := mb.serializeToBytes()
	return len(b)
}

// SerializeSizeStripped 返回 MsgBlock **不含 witness** 时 protobuf 编码后的字节数
func (mb *MsgBlock) SerializeSizeStripped() int {
	// 复用 serializeNoWitness 的实现思路
	pb := &wire.ProtoMsgBlock{
		Header: mb.Header.ToProto(),
	}
	for _, tx := range mb.Transactions {
		pb.Transactions = append(pb.Transactions, tx.ToProtoNoWitness())
	}
	b, _ := proto.Marshal(pb)
	return len(b)
}

// DeserializeTxLoc 从原始字节流中解析出每笔交易所在文件（或字节流）的偏移与长度
// wire.TxLoc 与自定义 TxLoc 字段完全一致，可直接转换
func (mb *MsgBlock) DeserializeTxLoc(r *bytes.Buffer) ([]TxLoc, error) {
	// 先反序列化整个 MsgBlock（带 witness 版本即可）
	if err := mb.deserialize(r); err != nil {
		return nil, err
	}

	// 计算 header 长度
	pos := blockHeaderLen

	// 逐个累加每笔交易的序列化长度
	locs := make([]TxLoc, 0, len(mb.Transactions))
	for _, tx := range mb.Transactions {
		txSize := tx.SerializeSize()
		locs = append(locs, TxLoc{
			TxStart: pos,
			TxLen:   txSize,
		})
		pos += txSize
	}
	return locs, nil
}

func (msg *MsgBlock) Command() string {
	return wire.CmdBlock
}

// 完整区块转区块头
func (msg *MsgBlock) BlockHeader() *BlockHeader {
	return &BlockHeader{
		Version:    msg.Header.Version,
		PrevBlock:  msg.Header.PrevBlock,
		MerkleRoot: msg.Header.MerkleRoot,
		Timestamp:  msg.Header.Timestamp,
		Bits:       msg.Header.Bits,
		Nonce:      msg.Header.Nonce,
	}
}

// 序列化：*big.Int -> []byte
func BigToBytes(v *big.Int) []byte {
	return v.Bytes() // 默认就是 big-endian
}

// 反序列化：[]byte -> *big.Int
func BytesToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

func (b *Block) Transactions() []*Tx {
	// Return transactions if they have ALL already been generated.  This
	// flag is necessary because the wrapped transactions are lazily
	// generated in a sparse fashion.
	if b.txnsGenerated {
		return b.transactions
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.transactions) == 0 {
		b.transactions = make([]*Tx, len(b.msgBlock.Transactions))
	}

	// Offset of each tx.  80 accounts for the block header size.
	offset := 80 + wire.VarIntSerializeSize(
		uint64(len(b.msgBlock.Transactions)),
	)

	// Generate and cache the wrapped transactions for all that haven't
	// already been done.
	for i, tx := range b.transactions {
		if tx == nil {
			newTx := NewTx(b.msgBlock.Transactions[i])
			newTx.SetIndex(i)

			size := b.msgBlock.Transactions[i].SerializeSize()

			// The block may not always have the serializedBlock.
			if len(b.serializedBlock) > 0 {
				// This allows for the reuse of the already
				// serialized tx.
				newTx.setBytes(
					b.serializedBlock[offset : offset+size],
				)

				// Increment offset for this block.
				offset += size
			}

			b.transactions[i] = newTx
		}
	}

	b.txnsGenerated = true
	return b.transactions
}

func (b *Block) Height() int32 {
	return b.BlockHeight
}
func (b *Block) Timestamp() int64 {
	return b.MsgBlock().BlockHeader().Timestamp
}

func (b *Block) BlockHeader() *BlockHeader {
	return b.MsgBlock().BlockHeader()
}

func (b *Block) Hash() *chainhash.Hash {
	// Return the cached block hash if it has already been generated.
	if b.BlockHash != nil {
		return b.BlockHash
	}
	// Cache the block hash and return it.
	hash := b.msgBlock.BlockHash()
	b.BlockHash = &hash
	return &hash
}

func (b *Block) SetMerkleRoot(root chainhash.Hash) {
	// 1. 穿透到 Block → MsgBlock → BlockHeader 层级，修改 MerkleRoot 字段
	b.msgBlock.Header.MerkleRoot = root

	// 2. 重置区块哈希缓存（关键步骤）
	// 原因：区块哈希是通过 BlockHeader 计算的，默克尔根变更后，原缓存的哈希已失效
	b.BlockHash = b.Hash()
}

// Size 返回区块完整序列化后的字节数（含所有见证数据），单位：字节
// 参考 Btcd 逻辑：优先使用缓存的序列化结果，未缓存则实时序列化并缓存
func (b *Block) Size() uint64 {
	// 1. 优先使用已缓存的完整序列化字节（避免重复计算）
	if len(b.serializedBlock) > 0 {
		return uint64(len(b.serializedBlock))
	}

	// 2. 未缓存则调用 Bytes() 序列化（Bytes() 会自动缓存结果）
	serialized, err := b.Bytes()
	if err != nil {
		// 异常处理：正常场景下区块应可序列化，此处参考 Btcd 返回 0（需在业务层确保区块有效性）
		return 0
	}

	// 3. 返回序列化后的字节数（转换为 uint64 符合返回类型）
	return uint64(len(serialized))
}

// Weight 返回区块的权重（SegWit 权重单位 WU），用于衡量区块对链容量的实际占用
// 参考 Btcd 与比特币协议：权重 = 基础大小（不含见证）× 3 + 完整大小（含见证）
func (b *Block) Weight() uint64 {
	// 1. 获取完整大小（含见证）：直接复用 Size() 方法（已处理缓存）
	totalSize := b.Size()

	// 2. 获取基础大小（不含见证）：复用 MsgBlock 的 SerializeSizeStripped() 方法
	strippedSize := uint64(b.msgBlock.SerializeSizeStripped())

	// 3. 按协议公式计算权重（避免浮点数，用整数直接计算）
	return (strippedSize * 3) + totalSize
}

func (b *Block) GetHeader() BlockHeader {
	return b.msgBlock.Header
}

func (b *Block) GetBody() MsgBlockBody {
	// 1. 初始化交易列表
	transactions := b.msgBlock.Transactions
	// 2. 自动设置 Txs 为交易列表长度
	txCount := int32(len(transactions))

	body := MsgBlockBody{
		Txs:          txCount,      // 同步交易数量
		Transactions: transactions, // 交易列表
	}
	// 若 Block 已有 chainWork，同步到区块体
	if b.chainWork != nil {
		_ = body.SetChainWork(b.chainWork) // 忽略错误（内部调用确保合法性）
	}
	return body
}

func (b *Block) SetHash(hash *chainhash.Hash) error {
	// 1. 校验输入哈希非空（避免后续使用空指针）
	if hash == nil {
		return errors.New("block hash cannot be nil")
	}

	// 2. 直接赋值哈希缓存（覆盖原有值）
	// 注：该方法允许外部强制设置区块哈希，跳过内部计算逻辑
	// 需确保外部传入的哈希与区块实际内容匹配（业务层需自行保证一致性）
	b.BlockHash = hash

	// 3. 无错误时返回 nil
	return nil
}

// SetChainWork 设置区块的累积链工作量
// 链工作量是从创世块到当前块的所有PoW工作量总和，用于最长链选择，必须为非空、非负的大整数
// 参数:
//
//	work - 待设置的累积链工作量
//
// 返回:
//
//	若参数非法（空指针或负值）则返回错误，否则返回nil
func (b *Block) SetChainWork(work *big.Int) error {
	// 1. 校验参数非空：chainWork作为核心共识数据，不允许为nil
	if work == nil {
		return errors.New("chain work must be a non-nil big integer")
	}

	// 2. 校验参数非负：累积工作量不可能为负数，负数属于无效数据
	if work.Sign() < 0 {
		return errors.New("chain work must be non-negative")
	}

	// 3. 深拷贝赋值：避免外部修改传入的work导致内部状态被篡改
	// big.Int是引用类型，直接赋值会共享底层数据，需通过Set()创建独立副本
	b.chainWork = new(big.Int).Set(work)

	// 4. 无错误时返回nil
	return nil
}

func (b *Block) Bits() uint32 {
	return b.msgBlock.Header.Bits
}

func (b *Block) GetChainWork() *big.Int {
	return b.chainWork
}

func (msg *MsgBlock) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

// ToProto 将 MsgBlockBody 转化为 Protobuf 结构体 ProtoMsgBlockBody
func (bb *MsgBlockBody) ToProto() *wire.ProtoMsgBlockBody {
	pb := &wire.ProtoMsgBlockBody{
		Transactions: make([]*wire.ProtoMsgTx, 0, len(bb.Transactions)),
	}

	// 1. 转化交易列表（复用 MsgTx.ToProto()）
	for _, tx := range bb.Transactions {
		pb.Transactions = append(pb.Transactions, tx.ToProto())
	}
	return pb
}

// FromProto 将 Protobuf 结构体 ProtoMsgBlockBody 转化为 MsgBlockBody
// 注意：原方法为 fromProto（未导出），此处修正为 FromProto 供外部调用
func (bb *MsgBlockBody) FromProto(pb *wire.ProtoMsgBlockBody) error {
	// 1. 反转化交易列表（复用 MsgTx.FromProto()）
	bb.Transactions = make([]*MsgTx, 0, len(pb.Transactions))
	for _, ptx := range pb.Transactions {
		tx := &MsgTx{}
		tx.FromProto(ptx)
		bb.Transactions = append(bb.Transactions, tx)
	}

	// 2. 同步交易数量（Txs = 交易列表长度，避免不一致）
	bb.Txs = int32(len(bb.Transactions))

	return nil
}

func (bb *MsgBlockBody) GetTransactions() []*MsgTx {
	return bb.Transactions
}

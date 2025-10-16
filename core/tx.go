package core

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/wire"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io"
	"strconv"
	"strings"
)

type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

type TxOut struct {
	Value    int64
	PkScript []byte
}

type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Witness          TxWitness
	Sequence         uint32
}

type TxWitness [][]byte

// OutPoint 是比特币协议里用于**唯一标识「上一笔交易中的某一个输出」**的数据结构。
// 它由两部分组成：
// Hash（交易 ID） – 32 字节的哈希，指向上一笔交易
// Index（输出序号） – 4 字节无符号整数，指向上一笔交易里的第几个输出（从 0 开始计数）
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

type Tx struct {
	msgTx         *MsgTx
	txHash        *chainhash.Hash
	txHashWitness *chainhash.Hash
	txHasWitness  *bool
	txIndex       int
	rawBytes      []byte
}

func (msg *MsgTx) Command() string {
	return wire.CmdTx
}

func (msg *MsgTx) TxHash() chainhash.Hash {
	return chainhash.Hash256FromWriter(msg.SerializeNoWitness)
}

func (msg *MsgTx) TxID() string {
	return msg.TxHash().String()
}

func (msg *MsgTx) WitnessHash() chainhash.Hash {
	if msg.HasWitness() {
		return chainhash.Hash256FromWriter(msg.Serialize)
	}
	return msg.TxHash()
}

func (msg *MsgTx) HasWitness() bool {
	for _, txIn := range msg.TxIn {
		if len(txIn.Witness) != 0 {
			return true
		}
	}
	return false
}

// WriteTxOut 把 TxOut 按 protobuf 编码写入 w
func WriteTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	if to == nil {
		return errors.New("nil TxOut")
	}
	pb := &wire.ProtoTxOut{
		Value:    to.Value,
		PkScript: to.PkScript,
	}
	raw, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func ReadTxOut(r io.Reader) (*TxOut, error) {
	var pb wire.ProtoTxOut
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(buf, &pb); err != nil {
		return nil, err
	}
	return &TxOut{Value: pb.Value, PkScript: pb.PkScript}, nil
}

func WriteOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	if op == nil {
		return errors.New("nil OutPoint")
	}
	pb := &wire.ProtoOutPoint{
		Hash:  op.Hash[:],
		Index: op.Index,
	}
	raw, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// ReadOutPoint 从 protobuf 字节流中解码出 OutPoint
func ReadOutPoint(r io.Reader) (*OutPoint, error) {
	var pb wire.ProtoOutPoint
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := proto.Unmarshal(buf, &pb); err != nil {
		return nil, err
	}
	if len(pb.Hash) != chainhash.HashSize {
		return nil, fmt.Errorf("invalid hash length %d", len(pb.Hash))
	}
	var h chainhash.Hash
	copy(h[:], pb.Hash)
	return &OutPoint{
		Hash:  h,
		Index: pb.Index,
	}, nil
}

// SerializeSize 返回 TxWitness 序列化后的字节数
// 格式: CompactSize(len(witness)) + 对每个 item: CompactSize(len(item)) + item
func (t TxWitness) SerializeSize() int {
	// 空 witness 按 1 字节 CompactSize(0x00) 计算
	if len(t) == 0 {
		return 1
	}
	// CompactSize 占用的长度
	size := wire.VarIntSerializeSize(uint64(len(t)))
	for _, item := range t {
		size += wire.VarIntSerializeSize(uint64(len(item)))
		size += len(item)
	}
	return size
}

func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// SerializeSize 获取 protobuf 字节数 含 witness 的 protobuf 字节数
func (msg *MsgTx) SerializeSize() int {
	// 1. 先把业务结构体转成 protobuf（含 witness）
	pb := msg.ToProto()
	// 2. 直接计算 protobuf 的序列化长度
	return proto.Size(pb)
}

// SerializeSizeStripped 返回不含 witness 的 protobuf 字节数
func (msg *MsgTx) SerializeSizeStripped() int {
	// 1. 先把业务结构体转成 protobuf（不含 witness）
	pb := msg.ToProtoNoWitness()

	// 2. 直接计算 protobuf 的序列化长度
	return proto.Size(pb)
}

func NewTx(msgTx *MsgTx) *Tx {
	return &Tx{
		msgTx:   msgTx,
		txIndex: TxIndexUnknown,
	}
}

func (t *Tx) Index() int {
	return t.txIndex
}

// SetIndex sets the index of the transaction in within a block.
func (t *Tx) SetIndex(index int) {
	t.txIndex = index
}

// Hash 返回交易的哈希（不含 witness）；结果会被缓存。
func (t *Tx) Hash() *chainhash.Hash {
	if t.txHash != nil {
		return t.txHash
	}
	h := chainhash.Hash256FromWriter(t.msgTx.SerializeNoWitness)
	t.txHash = &h
	return t.txHash
}

func (t *Tx) MsgTx() *MsgTx {
	// Return the cached transaction.
	return t.msgTx
}

func (t *Tx) HasWitness() bool {
	if t.txHasWitness != nil {
		return *t.txHasWitness
	}

	hasWitness := t.msgTx.HasWitness()
	t.txHasWitness = &hasWitness
	return hasWitness
}

func (t *Tx) WitnessHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHashWitness != nil {
		return t.txHashWitness
	}

	// Cache the hash and return it.
	var hash chainhash.Hash
	if len(t.rawBytes) > 0 {
		hash = chainhash.DoubleHashH(t.rawBytes)
	} else {
		hash = t.msgTx.WitnessHash()
	}

	t.txHashWitness = &hash
	return &hash
}

func NewTxIn(prevOut *OutPoint, signatureScript []byte, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Witness:          witness,
		Sequence:         MaxTxInSequenceNum,
	}
}

func (t TxWitness) ToHexStrings() []string {
	// Ensure nil is returned when there are no entries versus an empty
	// slice so it can properly be omitted as necessary.
	if len(t) == 0 {
		return nil
	}

	result := make([]string, len(t))
	for idx, wit := range t {
		result[idx] = hex.EncodeToString(wit)
	}

	return result
}

func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Deep copy the old signature script.
		var newScript []byte
		oldScript := oldTxIn.SignatureScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureScript:  newScript,
			Sequence:         oldTxIn.Sequence,
		}

		// If the transaction is witnessy, then also copy the
		// witnesses.
		if len(oldTxIn.Witness) != 0 {
			// Deep copy the old witness data.
			newTxIn.Witness = make([][]byte, len(oldTxIn.Witness))
			for i, oldItem := range oldTxIn.Witness {
				newItem := make([]byte, len(oldItem))
				copy(newItem, oldItem)
				newTxIn.Witness[i] = newItem
			}
		}

		// Finally, append this fully copied txin.
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{
			Value:    oldTxOut.Value,
			PkScript: newScript,
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return &newTx
}

// Serialize 将 MsgTx 编码为 **含 witness** 的 protobuf 字节流
func (msg *MsgTx) Serialize(w io.Writer) error {
	pb := msg.ToProto() // 前面已经实现，会把 Witness 一起编码
	raw, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// Deserialize 从 protobuf 字节流中解码出 **含 witness** 的 MsgTx
func (msg *MsgTx) Deserialize(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}

	pb := new(wire.ProtoMsgTx)
	if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
		return err
	}
	msg.FromProto(pb) // 前面已经实现，会把 Witness 还原
	return nil
}

// 序列化
func (msg *MsgTx) SerializeNoWitness(w io.Writer) error {
	pb := msg.ToProtoNoWitness()
	raw, err := proto.Marshal(pb)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

// 反序列化
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return err
	}

	pb := new(wire.ProtoMsgTx)
	if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
		return err
	}

	// 把 protobuf 结构体转回业务结构体
	msg.Version = pb.Version
	msg.LockTime = pb.LockTime
	msg.TxIn = nil
	msg.TxOut = nil

	for _, pIn := range pb.TxIn {
		var h chainhash.Hash
		copy(h[:], pIn.PrevHash)
		msg.TxIn = append(msg.TxIn, &TxIn{
			PreviousOutPoint: OutPoint{Hash: h, Index: pIn.PrevIndex},
			SignatureScript:  pIn.ScriptSig,
			Sequence:         pIn.Sequence,
			Witness:          nil, // 明确置空
		})
	}

	for _, pOut := range pb.TxOut {
		msg.TxOut = append(msg.TxOut, &TxOut{
			Value:    pOut.Value,
			PkScript: pOut.PkScript,
		})
	}

	return nil
}

func (msg *TxOut) ToProto() *wire.ProtoTxOut {
	return &wire.ProtoTxOut{
		Value:    msg.Value,
		PkScript: msg.PkScript,
	}
}

func (msg *TxOut) FromProto(pb *wire.ProtoTxOut) {
	msg.Value = pb.Value
	msg.PkScript = pb.PkScript
}

// ToProto ======================
// 转 protobuf（含 witness）
// ======================
func (msg *MsgTx) ToProto() *wire.ProtoMsgTx {
	pb := &wire.ProtoMsgTx{
		Version:  msg.Version,
		LockTime: msg.LockTime,
	}

	for _, in := range msg.TxIn {
		pbIn := &wire.ProtoTxIn{
			PrevHash:  in.PreviousOutPoint.Hash[:],
			PrevIndex: in.PreviousOutPoint.Index,
			ScriptSig: in.SignatureScript,
			Sequence:  in.Sequence,
		}
		for _, w := range in.Witness {
			pbIn.WitnessStack = append(pbIn.WitnessStack, w)
		}
		pb.TxIn = append(pb.TxIn, pbIn)
	}

	for _, out := range msg.TxOut {
		pb.TxOut = append(pb.TxOut, &wire.ProtoTxOut{
			Value:    out.Value,
			PkScript: out.PkScript,
		})
	}
	return pb
}

// FromProto ======================
// 从 protobuf 还原（含 witness）
// ======================
func (msg *MsgTx) FromProto(pb *wire.ProtoMsgTx) {
	msg.Version = pb.Version
	msg.LockTime = pb.LockTime
	msg.TxIn = nil
	msg.TxOut = nil

	for _, pIn := range pb.TxIn {
		var h chainhash.Hash
		copy(h[:], pIn.PrevHash)
		txIn := &TxIn{
			PreviousOutPoint: OutPoint{Hash: h, Index: pIn.PrevIndex},
			SignatureScript:  pIn.ScriptSig,
			Sequence:         pIn.Sequence,
			Witness:          make(TxWitness, len(pIn.WitnessStack)),
		}
		for i, w := range pIn.WitnessStack {
			txIn.Witness[i] = bytes.Clone(w)
		}
		msg.TxIn = append(msg.TxIn, txIn)
	}

	for _, pOut := range pb.TxOut {
		msg.TxOut = append(msg.TxOut, &TxOut{
			Value:    pOut.Value,
			PkScript: bytes.Clone(pOut.PkScript),
		})
	}
}

// ToProtoNoWitness 把业务结构体 MsgTx 转成 protobuf 结构体（不带 witness）
func (msg *MsgTx) ToProtoNoWitness() *wire.ProtoMsgTx {
	pb := &wire.ProtoMsgTx{
		Version:  msg.Version,
		LockTime: msg.LockTime,
	}

	for _, in := range msg.TxIn {
		pb.TxIn = append(pb.TxIn, &wire.ProtoTxIn{
			PrevHash:  in.PreviousOutPoint.Hash[:],
			PrevIndex: in.PreviousOutPoint.Index,
			ScriptSig: in.SignatureScript,
			Sequence:  in.Sequence,
		})
	}

	for _, out := range msg.TxOut {
		pb.TxOut = append(pb.TxOut, &wire.ProtoTxOut{
			Value:    out.Value,
			PkScript: out.PkScript,
		})
	}

	return pb
}

// FromProtoNoWitness fromProtoNoWitness 把 protobuf 结构体（不含 witness）还原成业务结构体 MsgTx
func (msg *MsgTx) FromProtoNoWitness(pb *wire.ProtoMsgTx) {
	msg.Version = pb.Version
	msg.LockTime = pb.LockTime

	// 清空旧数据
	msg.TxIn = msg.TxIn[:0]
	msg.TxOut = msg.TxOut[:0]

	for _, pIn := range pb.TxIn {
		var h chainhash.Hash
		copy(h[:], pIn.PrevHash)
		txIn := &TxIn{
			PreviousOutPoint: OutPoint{
				Hash:  h,
				Index: pIn.PrevIndex,
			},
			SignatureScript: bytes.Clone(pIn.ScriptSig),
			Sequence:        pIn.Sequence,
			Witness:         nil, // 明确置空
		}
		msg.TxIn = append(msg.TxIn, txIn)
	}

	for _, pOut := range pb.TxOut {
		txOut := &TxOut{
			Value:    pOut.Value,
			PkScript: bytes.Clone(pOut.PkScript),
		}
		msg.TxOut = append(msg.TxOut, txOut)
	}
}

func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// NewOutPointFromString 人类可读的字符串 "txid:index"
func NewOutPointFromString(outpoint string) (*OutPoint, error) {
	parts := strings.Split(outpoint, ":")
	if len(parts) != 2 {
		return nil, errors.New("outpoint should be of the form txid:index")
	}

	if len(parts[0]) != chainhash.MaxHashStringSize {
		return nil, errors.New("outpoint txid should be 64 hex chars")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return nil, err
	}

	outputIndex, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid output index: %v", err)
	}

	return &OutPoint{
		Hash:  *hash,
		Index: uint32(outputIndex),
	}, nil
}

// 把 OutPoint 转换成人类一眼就能看懂的 字符串形式：
// <64-hex-txid>:<output-index>
// 例如：
// 作用：
// 日志、调试、RPC 结果、命令行、配置文件里 方便阅读；
// 解析时再用 NewOutPointFromString 还原成结构体。
//
//a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d:0
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

const (
	// TxVersion 当前最新支持的交易版本号。
	TxVersion = 1

	// MaxTxInSequenceNum 交易输入序列号（sequence）的最大值。
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex 前一笔输出索引（outpoint.index）的最大值。
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled 若置位，则该输入的序列号不再表示相对锁定时间（nSequence 最高位）。
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds 若置位，则相对锁定时间单位为 512 秒（BIP-68）。
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask 用于从序列号中提取相对锁定时间值的掩码。
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity 基于秒的相对锁定时间粒度为 512 秒（2^9 秒）。
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc 为输入/输出切片预分配的默认容量，避免多次扩容。
	defaultTxInOutAlloc = 15

	// minTxInPayload 单个交易输入的最小字节数：
	// 32 字节 prevHash + 4 字节 prevIndex + 1 字节 varint + 4 字节序列号。
	minTxInPayload = 9 + chainhash.HashSize

	// maxTxInPerMessage 一条消息内最多可容纳的交易输入个数（上限估算）。
	maxTxInPerMessage = (wire.MaxMessagePayload / minTxInPayload) + 1

	// MinTxOutPayload 单个交易输出的最小字节数：8 字节 value + 1 字节脚本长度 varint。
	MinTxOutPayload = 9

	// maxTxOutPerMessage 一条消息内最多可容纳的交易输出个数（上限估算）。
	maxTxOutPerMessage = (wire.MaxMessagePayload / MinTxOutPayload) + 1

	// minTxPayload 交易本身的最小可能字节数（不含任何输入输出，仅版本、计数、锁定时间）。
	minTxPayload = 10

	// freeListMaxScriptSize 反序列化脚本时自由列表中每个缓冲区的最大长度，
	// 略高于大多数标准脚本大小的两倍。
	freeListMaxScriptSize = 512

	// freeListMaxItems 自由列表中保留的缓冲区数量，保证高并发场景下的内存复用。
	freeListMaxItems = 125

	// maxWitnessItemsPerInput 单个输入见证栈中最多可包含的 witness 数量上限，
	// 按最坏 2 字节/项估算，受交易权重 4,000,000 限制。
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize 见证栈中单个 witness 项的最大字节数，
	// 受 SegWit v1（Taproot）后的最大区块大小限制。
	maxWitnessItemSize = 4_000_000
)
const TxIndexUnknown = -1
const TxFlagMarker = 0x00

// TxFlag 标志字节 1：区分“可能带 witness 的交易”与“传统交易” 项目支持混合
type TxFlag = byte

// WitnessFlag  类型与 TxFlag = 0x01 标志字节 2：进一步说明 witness 类型
const WitnessFlag TxFlag = 0x01

// 一次性申请的大块缓冲区大小 用于 批量分配脚本数据，减少 GC 压力；小脚本直接切分使用，大脚本再额外分配。
const scriptSlabSize = 1 << 22

//protobuf 在 proto.Unmarshal 阶段会 一次性分配 所有需要的内存，内部已经做了切片复用和对象池优化。
//你不再需要自己写 readScript/readVarBytes 这类逐字节拷贝逻辑，也就不会出现大量 make([]byte, n) 的临时对象。
//因此 Borrow/Return 4 MiB 块的收益几乎为 0，反而白白占用 500 MiB 峰值内存。

// 4 MiB 的静态字节数组类型 在反序列化大量脚本时，可以一次性从 scriptSlab 中 切割出所需内存，避免频繁 make([]byte, …)。
type scriptSlab [scriptSlabSize]byte

// type scriptFreeList chan *scriptSlab 就是一个 固定大小 4 MiB 内存块的对象池，用来反复利用脚本缓冲区，减少 GC 和内存分配。
type scriptFreeList chan *scriptSlab

// Borrow 从池子里拿一块：
// 有空闲就立即返回；
// 没有就 new(scriptSlab) 现做一块。
// 调用者拿到后切成自己需要的大小即可使用。
func (c scriptFreeList) Borrow() *scriptSlab {
	var buf *scriptSlab
	select {
	case buf = <-c:
	default:
		buf = new(scriptSlab)
	}
	return buf
}

// Return
// 用完放回去：
// 池子未满就放回 channel；
// 满了直接丢弃，让 GC 回收。
// 对大于 4 MiB 的块自动忽略，不会误放回。
func (c scriptFreeList) Return(buf *scriptSlab) {
	// Return the buffer to the free list when it's not full.  Otherwise let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

var scriptPool = make(scriptFreeList, freeListMaxItems)

func (t *Tx) setBytes(bytes []byte) {
	t.rawBytes = bytes
}

func (t *TxOut) SerializeSize() int {
	if t == nil {
		return 0
	}
	pb := &wire.ProtoTxOut{
		Value:    t.Value,
		PkScript: t.PkScript,
	}
	return proto.Size(pb)
}

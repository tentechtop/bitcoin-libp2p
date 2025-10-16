package rpc

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/txscript"
	"bitcoin/wire"
	"encoding/hex"
	"fmt"
)

// MsgBlockToDTO 将业务层的 MsgBlock 转换为 DTO 层的 ProtoMsgBlockDTO
// 用于 gRPC 等场景下的可读格式传输（哈希字段转为 Hex 字符串）
func MsgBlockToDTO(msgBlock *core.MsgBlock) *wire.ProtoMsgBlockDTO {
	if msgBlock == nil {
		return nil
	}

	// 1. 转换区块头
	headerDTO := blockHeaderToDTO(&msgBlock.Header)

	// 2. 转换交易列表
	txsDTO := make([]*wire.ProtoMsgTxDTO, 0, len(msgBlock.Transactions))
	for _, tx := range msgBlock.Transactions {
		txsDTO = append(txsDTO, MsgTxToDTO(tx))
	}

	// 3. 转换链工作量（*big.Int → Hex 字符串）
	/*	var chainWorkHex string
		if msgBlock.ChainWork != nil {
			chainWorkHex = msgBlock.ChainWork.Text(16) // 转为十六进制字符串
		}
	*/
	return &wire.ProtoMsgBlockDTO{
		Header:       headerDTO,
		Transactions: txsDTO,
		/*ChainWork:    chainWorkHex,*/
	}
}

// blockHeaderToDTO 将 BlockHeader 转换为 ProtoBlockHeaderDTO
func blockHeaderToDTO(header *core.BlockHeader) *wire.ProtoBlockHeaderDTO {
	if header == nil {
		return nil
	}

	return &wire.ProtoBlockHeaderDTO{
		Version:    header.Version,
		PrevBlock:  hex.EncodeToString(header.PrevBlock[:]),  // Hash → Hex 字符串
		MerkleRoot: hex.EncodeToString(header.MerkleRoot[:]), // Hash → Hex 字符串
		Timestamp:  header.Timestamp,
		Bits:       header.Bits,
		Nonce:      header.Nonce,
	}
}

// msgTxToDTO 将 MsgTx 转换为 ProtoMsgTxDTO
func MsgTxToDTO(tx *core.MsgTx) *wire.ProtoMsgTxDTO {
	if tx == nil {
		return nil
	}

	// 转换交易输入列表
	txInsDTO := make([]*wire.ProtoTxInDTO, 0, len(tx.TxIn))
	for _, txIn := range tx.TxIn {
		txInsDTO = append(txInsDTO, txInToDTO(txIn))
	}

	// 转换交易输出列表
	txOutsDTO := make([]*wire.ProtoTxOutDTO, 0, len(tx.TxOut))
	for _, txOut := range tx.TxOut {
		txOutsDTO = append(txOutsDTO, txOutToDTO(txOut))
	}

	return &wire.ProtoMsgTxDTO{
		Version:  tx.Version,
		TxIn:     txInsDTO,
		TxOut:    txOutsDTO,
		LockTime: tx.LockTime,
	}
}

// DTOToMsgTx 把 ProtoMsgTxDTO 还原成 core.MsgTx
func DTOToMsgTx(dto *wire.ProtoMsgTxDTO) *core.MsgTx {
	if dto == nil {
		return nil
	}
	tx := &core.MsgTx{
		Version:  dto.Version,
		TxIn:     make([]*core.TxIn, len(dto.TxIn)),
		TxOut:    make([]*core.TxOut, len(dto.TxOut)),
		LockTime: dto.LockTime,
	}

	for i, inDTO := range dto.TxIn {
		tx.TxIn[i] = &core.TxIn{
			PreviousOutPoint: core.OutPoint{
				Hash:  *mustHashFromHex(inDTO.PrevHash),
				Index: inDTO.PrevIndex,
			},
			SignatureScript: []byte(inDTO.ScriptSig),
			Sequence:        inDTO.Sequence,
			Witness:         inDTO.WitnessStack, // [][]byte 直接复用
		}
	}

	for i, outDTO := range dto.TxOut {
		tx.TxOut[i] = &core.TxOut{
			Value:    outDTO.Value,
			PkScript: []byte(outDTO.PkScript),
		}
	}
	return tx
}

// mustHashFromHex 把 64 位 hex 字符串还原成 32 字节数组并塞进 Hash 类型
// 如果 hex 不合法会直接 panic，生产代码可以改成返回 error
func mustHashFromHex(s string) *chainhash.Hash {
	if len(s) != 64 {
		panic("invalid hash hex length")
	}
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = hex2byte(s[i*2])<<4 | hex2byte(s[i*2+1])
	}
	h := chainhash.Hash(b)
	return &h
}

func hex2byte(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

// txInToDTO 将 TxIn 转换为 ProtoTxInDTO
func txInToDTO(txIn *core.TxIn) *wire.ProtoTxInDTO {
	if txIn == nil {
		return nil
	}

	// 转换前序输出点的哈希（Hash → Hex 字符串）
	prevHashHex := txIn.PreviousOutPoint.Hash.String()
	disasmString, _ := txscript.DisasmString(txIn.SignatureScript)
	fmt.Println(disasmString)
	return &wire.ProtoTxInDTO{
		PrevHash:     prevHashHex,
		PrevIndex:    txIn.PreviousOutPoint.Index,
		ScriptSig:    disasmString,
		Sequence:     txIn.Sequence,
		WitnessStack: txIn.Witness, // 见证数据保持二进制
	}
}

// txOutToDTO 将 TxOut 转换为 ProtoTxOutDTO
func txOutToDTO(txOut *core.TxOut) *wire.ProtoTxOutDTO {
	if txOut == nil {
		return nil
	}
	disasmString, _ := txscript.DisasmString(txOut.PkScript)
	return &wire.ProtoTxOutDTO{
		Value:    txOut.Value,
		PkScript: disasmString, // 锁定脚本保持二进制
	}
}

// OutPointToDTO 将 OutPoint 转换为 ProtoOutPointDTO
// 用于单独转换交易引用点（如 UTXO 中的前序交易引用）
func OutPointToDTO(op *core.OutPoint) *wire.ProtoOutPointDTO {
	if op == nil {
		return nil
	}

	return &wire.ProtoOutPointDTO{
		Hash:  op.Hash.String(), // Hash → Hex 字符串
		Index: op.Index,
	}
}

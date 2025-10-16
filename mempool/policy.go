package mempool

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	"bitcoin/mining"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wire"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"math"
	"time"
)

const (
	// maxStandardP2SHSigOps is the maximum number of signature operations
	// that are considered standard in a pay-to-script-hash script.
	maxStandardP2SHSigOps = 15

	// maxStandardTxCost is the max weight permitted by any transaction
	// according to the current default policy.
	maxStandardTxWeight = 400000

	// maxStandardSigScriptSize is the maximum size allowed for a
	// transaction input signature script to be considered standard.  This
	// value allows for a 15-of-15 CHECKMULTISIG pay-to-script-hash with
	// compressed keys.
	//
	// The form of the overall script is: OP_0 <15 signatures> OP_PUSHDATA2
	// <2 bytes len> [OP_15 <15 pubkeys> OP_15 OP_CHECKMULTISIG]
	//
	// For the p2sh script portion, each of the 15 compressed pubkeys are
	// 33 bytes (plus one for the OP_DATA_33 opcode), and the thus it totals
	// to (15*34)+3 = 513 bytes.  Next, each of the 15 signatures is a max
	// of 73 bytes (plus one for the OP_DATA_73 opcode).  Also, there is one
	// extra byte for the initial extra OP_0 push and 3 bytes for the
	// OP_PUSHDATA2 needed to specify the 513 bytes for the script push.
	// That brings the total to 1+(15*74)+3+513 = 1627.  This value also
	// adds a few extra bytes to provide a little buffer.
	// (1 + 15*74 + 3) + (15*34 + 3) + 23 = 1650
	maxStandardSigScriptSize = 1650

	// DefaultMinRelayTxFee is the minimum fee in satoshi that is required
	// for a transaction to be treated as free for relay and mining
	// purposes.  It is also used to help determine if a transaction is
	// considered dust and as a base for calculating minimum required fees
	// for larger transactions.  This value is in Satoshi/1000 bytes.
	DefaultMinRelayTxFee = utils.Amount(1000)

	// maxStandardMultiSigKeys is the maximum number of public keys allowed
	// in a multi-signature transaction output script for it to be
	// considered standard.
	maxStandardMultiSigKeys = 3
)

func CheckTransactionStandard(tx *core.Tx, height int32,
	medianTimePast time.Time, minRelayTxFee utils.Amount,
	maxTxVersion int32) error {

	// The transaction must be a currently supported version.
	msgTx := tx.MsgTx()
	if msgTx.Version > maxTxVersion || msgTx.Version < 1 {
		str := fmt.Sprintf("transaction version %d is not in the "+
			"valid range of %d-%d", msgTx.Version, 1,
			maxTxVersion)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// The transaction must be finalized to be standard and therefore
	// considered for inclusion in a block.
	if !blockchain.IsFinalizedTransaction(tx, height, medianTimePast) {
		return txRuleError(wire.RejectNonstandard,
			"transaction is not finalized")
	}

	// Since extremely large transactions with a lot of inputs can cost
	// almost as much to process as the sender fees, limit the maximum
	// size of a transaction.  This also helps mitigate CPU exhaustion
	// attacks.
	txWeight := blockchain.GetTransactionWeight(tx)
	if txWeight > maxStandardTxWeight {
		str := fmt.Sprintf("weight of transaction is larger than max "+
			"allowed: %v > %v", txWeight, maxStandardTxWeight)
		return txRuleError(wire.RejectNonstandard, str)
	}

	for i, txIn := range msgTx.TxIn {
		// Each transaction input signature script must not exceed the
		// maximum size allowed for a standard transaction.  See
		// the comment on maxStandardSigScriptSize for more details.
		sigScriptLen := len(txIn.SignatureScript)
		if sigScriptLen > maxStandardSigScriptSize {
			str := fmt.Sprintf("transaction input %d: signature "+
				"script size is larger than max allowed: "+
				"%d > %d bytes", i, sigScriptLen,
				maxStandardSigScriptSize)
			return txRuleError(wire.RejectNonstandard, str)
		}

		// Each transaction input signature script must only contain
		// opcodes which push data onto the stack.
		if !txscript.IsPushOnlyScript(txIn.SignatureScript) {
			str := fmt.Sprintf("transaction input %d: signature "+
				"script is not push only", i)
			return txRuleError(wire.RejectNonstandard, str)
		}
	}

	// None of the output public key scripts can be a non-standard script or
	// be "dust" (except when the script is a null data script).
	numNullDataOutputs := 0
	for i, txOut := range msgTx.TxOut {
		scriptClass := txscript.GetScriptClass(txOut.PkScript)
		err := checkPkScriptStandard(txOut.PkScript, scriptClass)
		if err != nil {
			// Attempt to extract a reject code from the error so
			// it can be retained.  When not possible, fall back to
			// a non standard error.
			rejectCode := wire.RejectNonstandard
			if rejCode, found := extractRejectCode(err); found {
				rejectCode = rejCode
			}
			str := fmt.Sprintf("transaction output %d: %v", i, err)
			return txRuleError(rejectCode, str)
		}

		// Accumulate the number of outputs which only carry data.  For
		// all other script types, ensure the output value is not
		// "dust".
		if scriptClass == txscript.NullDataTy {
			numNullDataOutputs++
		} else if IsDust(txOut, minRelayTxFee) {
			str := fmt.Sprintf("transaction output %d: payment is "+
				"dust: %v", i, txOut.Value)
			return txRuleError(wire.RejectDust, str)
		}
	}

	// A standard transaction must not have more than one output script that
	// only carries data.
	if numNullDataOutputs > 1 {
		str := "more than one transaction output in a nulldata script"
		return txRuleError(wire.RejectNonstandard, str)
	}

	return nil
}

func checkPkScriptStandard(pkScript []byte, scriptClass txscript.ScriptClass) error {
	switch scriptClass {
	case txscript.MultiSigTy:
		numPubKeys, numSigs, err := txscript.CalcMultiSigStats(pkScript)
		if err != nil {
			str := fmt.Sprintf("multi-signature script parse "+
				"failure: %v", err)
			return txRuleError(wire.RejectNonstandard, str)
		}

		// A standard multi-signature public key script must contain
		// from 1 to maxStandardMultiSigKeys public keys.
		if numPubKeys < 1 {
			str := "multi-signature script with no pubkeys"
			return txRuleError(wire.RejectNonstandard, str)
		}
		if numPubKeys > maxStandardMultiSigKeys {
			str := fmt.Sprintf("multi-signature script with %d "+
				"public keys which is more than the allowed "+
				"max of %d", numPubKeys, maxStandardMultiSigKeys)
			return txRuleError(wire.RejectNonstandard, str)
		}

		// A standard multi-signature public key script must have at
		// least 1 signature and no more signatures than available
		// public keys.
		if numSigs < 1 {
			return txRuleError(wire.RejectNonstandard,
				"multi-signature script with no signatures")
		}
		if numSigs > numPubKeys {
			str := fmt.Sprintf("multi-signature script with %d "+
				"signatures which is more than the available "+
				"%d public keys", numSigs, numPubKeys)
			return txRuleError(wire.RejectNonstandard, str)
		}

	case txscript.NonStandardTy:
		return txRuleError(wire.RejectNonstandard,
			"non-standard script form")
	}

	return nil
}

// 这个 IsDust 方法的作用是判断一个交易输出（txOut）是否属于 “灰尘交易输出（dust output）”，判断依据是该输出的金额是否过低，以至于花费它的网络成本超过其本身价值。
// 核心定义：什么是 “灰尘交易输出”？
// 根据代码注释和逻辑，“灰尘” 的定义是：如果花费该输出对网络造成的成本超过最小交易中继费（minRelayTxFee）的 1/3，则该输出被视为灰尘。
//
// 这种输出通常因金额过低而不具备实际使用价值 —— 花费它所需的手续费可能超过其本身的价值，因此网络通常会拒绝处理这类输出。
// 代码逻辑拆解：
// 不可花费的输出直接视为灰尘
// 首先通过 txscript.IsUnspendable(txOut.PkScript) 检查该输出是否不可花费（例如，脚本无法被满足的输出）。这类输出因永远无法被使用，直接判定为灰尘（返回 true）。
// 通过成本比例判断灰尘
// 对于可花费的输出，通过以下逻辑判断：
// 计算 (输出金额 × 1000) ÷ 灰尘阈值（GetDustThreshold(txOut)），如果结果小于最小交易中继费（minRelayTxFee），则视为灰尘。
// 这一计算等价于判断 (输出金额 / 花费该输出的总成本) × (1/3) × 1000 < 最小中继费（避免浮点数运算的整数实现）。
// 其中，GetDustThreshold(txOut) 用于计算 “花费该输出所需的最小成本阈值”（通常与输出的脚本类型相关，例如 P2PKH 脚本的阈值是固定值）。
// 实际意义：
// 典型场景：对于默认的最小中继费（1000 satoshi/KB），P2PKH 类型的输出若金额小于 546 satoshi，会被判定为灰尘。
// 目的：过滤掉价值过低的输出，避免网络资源被用于处理这类 “得不偿失” 的交易（花费它们的成本超过其本身价值），提高网络效率。
//
// 简言之，该方法是网络为了过滤低价值、无实际意义的交易输出而设计的判断逻辑。
func IsDust(txOut *core.TxOut, minRelayTxFee utils.Amount) bool {
	// Unspendable outputs are considered dust.
	if txscript.IsUnspendable(txOut.PkScript) {
		return true
	}

	// The output is considered dust if the cost to the network to spend the
	// coins is more than 1/3 of the minimum free transaction relay fee.
	// minFreeTxRelayFee is in Satoshi/KB, so multiply by 1000 to
	// convert to bytes.
	//
	// Using the typical values for a pay-to-pubkey-hash transaction from
	// the breakdown above and the default minimum free transaction relay
	// fee of 1000, this equates to values less than 546 satoshi being
	// considered dust.
	//
	// The following is equivalent to (value/totalSize) * (1/3) * 1000
	// without needing to do floating point math.
	return txOut.Value*1000/GetDustThreshold(txOut) < int64(minRelayTxFee)
}

func GetDustThreshold(txOut *core.TxOut) int64 {
	totalSize := txOut.SerializeSize()
	if txscript.IsWitnessProgram(txOut.PkScript) {
		totalSize += (107 / blockchain.WitnessScaleFactor) //// SegWit 折扣
	} else {
		totalSize += 107
	}
	return 3 * int64(totalSize)
}

// checkInputsStandard 确保一笔交易的「每一个输入」所引用的上一笔输出的脚本（scriptPubKey）是「标准类型」，
// 且 P2SH 输入的签名操作数不超过上限，否则拒绝该交易为“非标准”。
func checkInputsStandard(tx *core.Tx, utxoView *blockchain.UtxoViewpoint) error {
	// NOTE: The reference implementation also does a coinbase check here,
	// but coinbases have already been rejected prior to calling this
	// function so no need to recheck.

	for i, txIn := range tx.MsgTx().TxIn {
		// It is safe to elide existence and index checks here since
		// they have already been checked prior to calling this
		// function.
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		originPkScript := entry.PkScript()
		switch txscript.GetScriptClass(originPkScript) {
		case txscript.ScriptHashTy:
			numSigOps := txscript.GetPreciseSigOpCount(
				txIn.SignatureScript, originPkScript, true)
			if numSigOps > maxStandardP2SHSigOps {
				str := fmt.Sprintf("transaction input #%d has "+
					"%d signature operations which is more "+
					"than the allowed max amount of %d",
					i, numSigOps, maxStandardP2SHSigOps)
				return txRuleError(wire.RejectNonstandard, str)
			}

		case txscript.NonStandardTy:
			str := fmt.Sprintf("transaction input #%d has a "+
				"non-standard script form", i)
			return txRuleError(wire.RejectNonstandard, str)
		}
	}

	return nil
}

// GetTxVirtualSize 这个GetTxVirtualSize方法的作用是计算比特币交易的虚拟大小（Virtual Size，简称 vSize）。虚拟大小是比特币网络中衡量交易占用区块空间的一种标准化指标，其核心设计与 “隔离见证（Segregated Witness, SegWit）” 升级密切相关。
// 函数具体作用
// 从代码和注释可以看出，虚拟大小的计算基于交易的权重（weight），公式简化为：
// vSize = (交易权重 + (WitnessScaleFactor - 1)) / WitnessScaleFactor
//
// 在比特币中，WitnessScaleFactor（见证缩放因子）固定为 4，因此公式可进一步简化为：
// vSize = (交易权重 + 3) / 4（本质是对权重除以 4 的结果向上取整）
// 为什么需要虚拟大小？
// 虚拟大小的引入是为了解决比特币区块空间管理的问题，尤其是配合 SegWit 升级的设计目标：
//
// 区分交易数据类型，实现体积折扣
// SegWit 将交易数据分为两部分：
// 基础数据（Base Data）：包含交易的核心信息（如输入输出、发送方地址等），是传统未升级节点也能理解的数据。
// 见证数据（Witness Data）：用于验证交易的签名等辅助信息，是 SegWit 新增的、可被优化存储的数据。
// 为了鼓励使用 SegWit（减少区块链膨胀、提升安全性），虚拟大小对两类数据采用了不同的 “体积计算权重”：
// 基础数据每字节计为 4 个 “权重单位”；
// 见证数据每字节仅计为 1 个 “权重单位”。
// 最终通过虚拟大小（vSize = 总权重 / 4）将见证数据的体积 “打折”（相当于按 1/4 计算），使得包含更多见证数据的交易在区块中占用更少的 “有效空间”。
// 兼容区块大小限制
// 比特币最初的区块大小限制为 1MB（即 100 万字节），但 SegWit 通过虚拟大小实现了 “隐性扩容”：
// 区块的虚拟大小限制仍保持在 1MB（即总 vSize 不超过 100 万），但由于见证数据被打折计算，实际区块可容纳的交易总字节数会超过 1MB（最多约 4MB），提升了网络吞吐量。
// 统一交易体积度量标准
// 虚拟大小成为衡量交易 “区块空间占用成本” 的统一标准，无论是包含见证数据的 SegWit 交易，还是传统交易，都能通过 vSize 公平比较其对区块空间的消耗，确保节点在打包交易时的规则一致性。
//
// 总结：虚拟大小是 SegWit 升级后为优化区块链空间利用、鼓励更高效的交易格式而设计的度量方式，既兼容了原有的区块大小限制，又
// 通过折扣机制提升了网络的实际处理能力。
func GetTxVirtualSize(tx *core.Tx) int64 {
	// vSize := (weight(tx) + 3) / 4
	//       := (((baseSize * 3) + totalSize) + 3) / 4
	// We add 3 here as a way to compute the ceiling of the prior arithmetic
	// to 4. The division by 4 creates a discount for wit witness data.
	return (blockchain.GetTransactionWeight(tx) + (blockchain.WitnessScaleFactor - 1)) /
		blockchain.WitnessScaleFactor
}

// 这个validateRelayFeeMet方法的核心作用是验证交易是否满足在节点间中继（传播）的费用相关规则，
// 确保只有符合网络策略的交易才能被节点接收并转发给其他节点。
// 它主要通过检查交易的费用、大小、优先级以及速率限制等条件，防止低质量或恶意交易占用网络资源。
func (mp *TxPool) validateRelayFeeMet(tx *core.Tx, txFee, txSize int64,
	utxoView *blockchain.UtxoViewpoint, nextBlockHeight int32,
	isNew, rateLimit bool) error {

	txHash := tx.Hash()

	// Most miners allow a free transaction area in blocks they mine to go
	// alongside the area used for high-priority transactions as well as
	// transactions with fees. A transaction size of up to 1000 bytes is
	// considered safe to go into this section. Further, the minimum fee
	// calculated below on its own would encourage several small
	// transactions to avoid fees rather than one single larger transaction
	// which is more desirable. Therefore, as long as the size of the
	// transaction does not exceed 1000 less than the reserved space for
	// high-priority transactions, don't require a fee for it.
	minFee := calcMinRequiredTxRelayFee(txSize, mp.cfg.Policy.MinRelayTxFee)

	if txSize >= (DefaultBlockPrioritySize-1000) && txFee < minFee {
		str := fmt.Sprintf("transaction %v has %d fees which is under "+
			"the required amount of %d", txHash, txFee, minFee)

		return txRuleError(wire.RejectInsufficientFee, str)
	}

	// Exit early if the min relay fee is met.
	if txFee >= minFee {
		return nil
	}

	// Exit early if this is neither a new tx or rate limited.
	if !isNew && !rateLimit {
		return nil
	}

	// Require that free transactions have sufficient priority to be mined
	// in the next block. Transactions which are being added back to the
	// memory pool from blocks that have been disconnected during a reorg
	// are exempted.
	if isNew && !mp.cfg.Policy.DisableRelayPriority {
		currentPriority := mining.CalcPriority(
			tx.MsgTx(), utxoView, nextBlockHeight,
		)
		if currentPriority <= mining.MinHighPriority {
			str := fmt.Sprintf("transaction %v has insufficient "+
				"priority (%g <= %g)", txHash,
				currentPriority, mining.MinHighPriority)

			return txRuleError(wire.RejectInsufficientFee, str)
		}
	}

	// We can only end up here when the rateLimit is true. Free-to-relay
	// transactions are rate limited here to prevent penny-flooding with
	// tiny transactions as a form of attack.
	nowUnix := time.Now().Unix()

	// Decay passed data with an exponentially decaying ~10 minute window -
	// matches bitcoind handling.
	mp.pennyTotal *= math.Pow(
		1.0-1.0/600.0, float64(nowUnix-mp.lastPennyUnix),
	)
	mp.lastPennyUnix = nowUnix

	// Are we still over the limit?
	if mp.pennyTotal >= mp.cfg.Policy.FreeTxRelayLimit*10*1000 {
		str := fmt.Sprintf("transaction %v has been rejected "+
			"by the rate limiter due to low fees", txHash)

		return txRuleError(wire.RejectInsufficientFee, str)
	}

	oldTotal := mp.pennyTotal
	mp.pennyTotal += float64(txSize)
	log.Tracef("rate limit: curTotal %v, nextTotal: %v, limit %v",
		oldTotal, mp.pennyTotal, mp.cfg.Policy.FreeTxRelayLimit*10*1000)

	return nil
}

// calcMinRequiredTxRelayFee 方法的核心作用是
// 计算交易被节点接受进入内存池并中继（转发给其他节点）所需的最低费用，
// 该费用基于交易的序列化大小和网络配置的最小中继费率。
func calcMinRequiredTxRelayFee(serializedSize int64, minRelayTxFee utils.Amount) int64 {
	// Calculate the minimum fee for a transaction to be allowed into the
	// mempool and relayed by scaling the base fee (which is the minimum
	// free transaction relay fee).  minRelayTxFee is in Satoshi/kB so
	// multiply by serializedSize (which is in bytes) and divide by 1000 to
	// get minimum Satoshis.
	minFee := (serializedSize * int64(minRelayTxFee)) / 1000

	if minFee == 0 && minRelayTxFee > 0 {
		minFee = int64(minRelayTxFee)
	}

	// Set the minimum fee to the maximum possible value if the calculated
	// fee is not in the valid range for monetary amounts.
	if minFee < 0 || minFee > btcutil.MaxSatoshi {
		minFee = btcutil.MaxSatoshi
	}

	return minFee
}

package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
)

// 新增错误定义（对应 Java 中的异常场景）
var (
	ErrInsufficientBlocks = errors.New("insufficient blocks for retarget: need at least adjustment interval blocks")
	ErrFirstBlockNotFound = errors.New("first block in retarget period not found")
	ErrInvalidBlockTime   = errors.New("invalid block time (actual time ≤ 0)")
)

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// oneLsh256 is 1 shifted left 256 bits.  It is defined here to avoid
	// the overhead of creating it multiple times.
	oneLsh256 = new(big.Int).Lsh(bigOne, 256)
)

var (
	// ErrBadPowBits 表示区块头里的 compact 难度值（bits）无效
	ErrBadPowBits = errors.New("invalid compact bits")

	// ErrPowTooHigh 表示区块哈希未满足当前目标难度
	ErrPowTooHigh = errors.New("block hash does not satisfy target difficulty")
)

const INIT_DIFFICULTY_TARGET_HEX = "0000ffffffff0000000000000000000000000000000000000000000000000000"

// InitBits 把十六进制目标转成 Bitcoin-Compact 格式，可直接用作创世区块 Bits
var InitBits = BigToCompact(HexToBig(INIT_DIFFICULTY_TARGET_HEX))

//bits := uint32(0x1d00ffff)

func HexToBig(hexStr string) *big.Int {
	b, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		panic("invalid hex target")
	}
	return b
}

func CalcWork(bits uint32) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

func BigToCompact(target *big.Int) uint32 {
	// Bitcoin 规范实现
	var compact uint32
	size := (target.BitLen() + 7) / 8
	if size <= 3 {
		compact = uint32(target.Int64()) << uint(8*(3-size))
	} else {
		targetCopy := new(big.Int).Set(target)
		targetCopy.Rsh(targetCopy, uint(8*(size-3)))
		compact = uint32(targetCopy.Int64())
	}
	// 最高位符号位处理
	if compact&0x00800000 != 0 {
		compact >>= 8
		size++
	}
	compact |= uint32(size) << 24
	return compact
}

func CompactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}
	if isNegative {
		bn = bn.Neg(bn)
	}
	return bn
}

// -------------------- []byte → 16 进制字符串 --------------------
func BytesToHex(b []byte) string {
	if b == nil {
		return ""
	}
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

// -------------------- 16 进制字符串 → []byte --------------------
func HexToBytes(s string) []byte {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if len(s)%2 != 0 {
		// 与 Java 版保持一致：奇数位直接丢弃最后一位
		s = s[:len(s)-1]
	}
	if len(s) == 0 {
		return []byte{}
	}

	dst := make([]byte, len(s)/2)
	for i := 0; i < len(dst); i++ {
		hi := fromHexChar(s[i*2])
		lo := fromHexChar(s[i*2+1])
		dst[i] = (hi << 4) | lo
	}
	return dst
}

// 字符 → 4 位值；非法字符按 0 处理（与 Java Character.digit 行为一致）
func fromHexChar(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// DifficultyCmp -----------------------------------------------------------------------------
// 工具：难度比较 & 验证
// -----------------------------------------------------------------------------
// 比较两个 compact 难度（bitsA, bitsB）的“大小”：
// 返回值：
//
//	-1  => A 比 B 难（目标更小）
//	 0  => 相等
//	 1  => A 比 B 容易（目标更大）
func DifficultyCmp(bitsA, bitsB uint32) int {
	tA := CompactToBig(bitsA)
	tB := CompactToBig(bitsB)
	return tA.Cmp(tB)
}

// DifficultyCheck -----------------------------------------------------------------------------
// 工具：判定区块哈希是否满足目标难度
// 参数
//
//	hash   —— 区块哈希（任意 32 字节）
//	target —— 当前难度对应的目标值（big.Int）
//
// 返回
//
//	ok     —— true 表示 hash ≤ target（挖矿成功）
//
// -----------------------------------------------------------------------------
func DifficultyCheck(hash []byte, target *big.Int) bool {
	if len(hash) != 32 || target == nil {
		return false
	}
	hashNum := new(big.Int).SetBytes(hash)
	return hashNum.Cmp(target) <= 0
}

func VerifyPow(h *core.BlockHeader) error {
	// 1. 计算区块哈希
	hash := h.BlockHash()
	// 2. 把 Bits 转成目标值
	target := CompactToBig(uint32(h.Bits))
	if target.Sign() <= 0 {
		return ErrBadPowBits
	}
	// 3. 检查 hash ≤ target
	if !DifficultyCheck(hash[:], target) {
		return fmt.Errorf("%w: got %x, target %064x",
			ErrPowTooHigh, hash, target.Bytes())
	}
	// 4. 通过
	return nil
}

func HashToBig(hash *chainhash.Hash) *big.Int {
	// A Hash is in little-endian, but the big package wants the bytes in
	// big-endian, so reverse them.
	buf := *hash
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}
	return new(big.Int).SetBytes(buf[:])
}

// 计算当前区块的
func (b *BlockChain) CalcNextRequiredDifficulty(curHeight int32) (uint32, error) {
	b.chainLock.Lock()
	difficulty, err := calcRequiredDifficulty(curHeight, b)
	b.chainLock.Unlock()
	return difficulty, err
}

// calcRequiredDifficulty 计算指定高度区块的要求难度
// targetHeight: 要计算难度的目标区块高度
// c: 链上下文，用于获取区块数据和链参数
func calcRequiredDifficulty(targetHeight int32, c ChainCtx) (uint32, error) {
	params := c.ChainParams()
	// 如果关闭难度调整，直接返回初始难度
	if params.PoWNoRetargeting {
		return params.PowLimitBits, nil
	}

	// 处理创世区块（高度0）的特殊情况
	if targetHeight == 0 {
		return params.PowLimitBits, nil
	}

	// 获取目标区块的前一个区块（高度-1），作为难度计算的基准
	prevBlockHeight := targetHeight - 1
	prevBlock, err := c.GetMainBlockByHeight(prevBlockHeight)
	if err != nil || prevBlock == nil {
		return 0, fmt.Errorf("获取前序区块失败（高度%d）: %w", prevBlockHeight, err)
	}

	// 判断是否需要触发难度调整（目标区块高度是否为调整间隔的整数倍）
	adjustmentInterval := params.HalvingPeriod
	if targetHeight%adjustmentInterval != 0 {
		// 未到调整周期，难度与前一个区块相同
		return prevBlock.Bits(), nil
	}

	// 计算调整周期的起始区块高度（当前周期包含 adjustmentInterval 个区块）
	// 例如：调整间隔为2016，目标高度2016，则周期是1~2015（共2016个区块）
	firstBlockHeight := targetHeight - adjustmentInterval
	if firstBlockHeight < 0 {
		firstBlockHeight = 0
	}

	// 获取周期内的第一个区块
	firstBlock, err := c.GetMainBlockByHeight(firstBlockHeight)
	if err != nil || firstBlock == nil {
		return 0, fmt.Errorf("获取周期起始区块失败（高度%d）: %w", firstBlockHeight, err)
	}

	// 计算周期内的实际耗时（最后一个区块 - 第一个区块的时间差）
	firstBlockTime := firstBlock.MsgBlock().Header.Timestamp
	lastBlockTime := prevBlock.MsgBlock().Header.Timestamp // 周期内最后一个区块是目标区块的前一个区块
	actualTimeTaken := lastBlockTime - firstBlockTime
	if actualTimeTaken <= 0 {
		actualTimeTaken = 1 // 避免时间为0或负数导致计算异常
	}

	// 计算目标总耗时（调整间隔 × 单个区块目标时间）
	targetTimePerBlock := int32(params.TargetTimePerBlock / time.Second)
	targetTotalTime := adjustmentInterval * targetTimePerBlock

	// 计算调整因子（目标耗时/实际耗时），并限制范围
	factor := float64(targetTotalTime) / float64(actualTimeTaken)
	factor = math.Max(0.25, math.Min(4.0, factor)) // 限制在0.25~4倍之间

	// 基于前序区块的难度计算新难度
	oldBits := prevBlock.MsgBlock().Header.Bits
	oldTarget := CompactToBig(oldBits)

	// 新目标值 = 旧目标值 ÷ 调整因子（难度与目标值成反比）
	oldTargetFloat := new(big.Float).SetInt(oldTarget)
	newTargetFloat := new(big.Float).Quo(oldTargetFloat, big.NewFloat(factor))

	// 转换为整数（向下取整）
	newTarget := new(big.Int)
	newTargetFloat.Int(newTarget)

	// 转换为compact格式（bits）
	newBits := BigToCompact(newTarget)

	// 日志输出调整信息
	log.Infof(`计算区块%d的难度:
- 调整周期: %d个区块（高度%d~%d）
- 目标总时间: %d秒（单块目标%d秒）
- 实际总时间: %d秒（平均%.2f秒/块）
- 调整因子: %.2f
- 旧难度: %x → 新难度: %x`,
		targetHeight, adjustmentInterval, firstBlockHeight, prevBlockHeight,
		targetTotalTime, targetTimePerBlock,
		actualTimeTaken, float64(actualTimeTaken)/float64(adjustmentInterval),
		factor, oldBits, newBits,
	)

	return newBits, nil
}

func CalculateBlockWork(bits uint32) *big.Int {
	target := CompactToBig(bits)

	// 工作量定义为 2^256 / (target + 1)
	maxTarget := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	targetPlusOne := new(big.Int).Add(target, big.NewInt(1))

	work := new(big.Int).Div(maxTarget, targetPlusOne)
	return work
}

func CalculateChainWork(chainWork big.Int, newBits uint32) *big.Int {
	// 直接复用单个区块工作量计算函数
	newWork := CalculateBlockWork(newBits)
	// 累加总工作量
	totalWork := new(big.Int).Add(&chainWork, newWork)
	return totalWork
}

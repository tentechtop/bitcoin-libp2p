package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"fmt"

	"time"
)

// ThresholdState 定义共识规则变更的阈值状态
type ThresholdState byte

const (
	ThresholdDefined  ThresholdState = iota // 初始状态
	ThresholdStarted                        // 开始投票
	ThresholdLockedIn                       // 已锁定
	ThresholdActive                         // 已激活
	ThresholdFailed                         // 已失败
	numThresholdsStates
)

var thresholdStateStrings = map[ThresholdState]string{
	ThresholdDefined:  "ThresholdDefined",
	ThresholdStarted:  "ThresholdStarted",
	ThresholdLockedIn: "ThresholdLockedIn",
	ThresholdActive:   "ThresholdActive",
	ThresholdFailed:   "ThresholdFailed",
}

func (t ThresholdState) String() string {
	if s := thresholdStateStrings[t]; s != "" {
		return s
	}
	return fmt.Sprintf("Unknown ThresholdState (%d)", int(t))
}

// thresholdConditionChecker 定义阈值状态检查接口
type thresholdConditionChecker interface {
	HasStarted(*core.Block) bool
	HasEnded(*core.Block) bool
	RuleChangeActivationThreshold() uint32
	MinerConfirmationWindow() uint32
	EligibleToActivate(*core.Block) bool
	IsSpeedy() bool
	Condition(*core.Block) (bool, error)
	ForceActive(*core.Block) bool
}

// thresholdStateCache 缓存区块的阈值状态
type thresholdStateCache struct {
	entries map[chainhash.Hash]ThresholdState
}

func (c *thresholdStateCache) Lookup(hash *chainhash.Hash) (ThresholdState, bool) {
	state, ok := c.entries[*hash]
	return state, ok
}

func (c *thresholdStateCache) Update(hash *chainhash.Hash, state ThresholdState) {
	c.entries[*hash] = state
}

func newThresholdCaches(numCaches uint32) []thresholdStateCache {
	caches := make([]thresholdStateCache, numCaches)
	for i := 0; i < len(caches); i++ {
		caches[i] = thresholdStateCache{
			entries: make(map[chainhash.Hash]ThresholdState),
		}
	}
	return caches
}

// PastMedianTime 计算过去11个区块的中位数时间
func (b *BlockChain) PastMedianTime(blockHeader *core.BlockHeader) (time.Time, error) {
	// 获取当前区块哈希
	blockHash := blockHeader.BlockHash()

	// 获取当前区块
	currentBlock, err := b.GetBlockByHash(&blockHash)
	if err != nil {
		return time.Time{}, fmt.Errorf("无法获取区块 %v: %v", blockHash, err)
	}

	// 收集过去11个区块的时间
	timestamps := make([]int64, 11)
	prevBlock := currentBlock

	for i := 0; i < 11; i++ {
		// 获取前一个区块
		prevBlock, err = b.GetBlockByHash(prevBlock.BlockHash)
		if err != nil {
			return time.Time{}, fmt.Errorf("无法获取前序区块: %v", err)
		}
		if prevBlock == nil {
			return time.Time{}, fmt.Errorf("前序区块不足11个")
		}
		timestamps[i] = prevBlock.BlockHeader().Timestamp
	}

	// 排序并取中位数
	// 简化实现：实际需要完整排序逻辑
	return time.Unix(timestamps[5], 0), nil
}

// 处理阈值状态转换逻辑
func thresholdStateTransition(state ThresholdState, prevBlock *core.Block, checker thresholdConditionChecker, confirmationWindow int32, chain *BlockChain) (ThresholdState, error) {

	switch state {
	case ThresholdDefined:
		// 处理非快速部署的过期逻辑
		if !checker.IsSpeedy() && checker.HasEnded(prevBlock) {
			return ThresholdFailed, nil
		}

		// 检查是否已开始
		if checker.HasStarted(prevBlock) {
			return ThresholdStarted, nil
		}

	case ThresholdStarted:
		// 处理非快速部署的过期逻辑
		if !checker.IsSpeedy() && checker.HasEnded(prevBlock) {
			return ThresholdFailed, nil
		}

		// 计算确认窗口内的支持票数
		var count uint32
		currentBlock := prevBlock

		for i := int32(0); i < confirmationWindow; i++ {
			condition, err := checker.Condition(currentBlock)
			if err != nil {
				return ThresholdFailed, err
			}
			if condition {
				count++
			}

			// 获取前一个区块
			prev, err := chain.GetBlockByHash(&currentBlock.BlockHeader().PrevBlock)
			if err != nil {
				return ThresholdFailed, err
			}
			if prev == nil {
				break // 已到达创世块
			}
			currentBlock = prev
		}

		// 检查是否达到激活阈值
		if count >= checker.RuleChangeActivationThreshold() {
			return ThresholdLockedIn, nil
		}

		// 处理快速部署的过期逻辑
		if checker.IsSpeedy() && checker.HasEnded(prevBlock) {
			return ThresholdFailed, nil
		}

	case ThresholdLockedIn:
		// 检查是否符合激活条件
		if checker.EligibleToActivate(prevBlock) {
			return ThresholdActive, nil
		}

	// 激活和失败状态为终端状态，无需转换
	case ThresholdActive, ThresholdFailed:
	}

	return state, nil
}

// thresholdState 计算区块对应的阈值状态
func (b *BlockChain) thresholdState(prevBlock *core.Block,
	checker thresholdConditionChecker, cache *thresholdStateCache) (ThresholdState, error) {

	// 检查是否需要强制激活
	if checker.ForceActive(prevBlock) {
		return ThresholdActive, nil
	}

	confirmationWindow := int32(checker.MinerConfirmationWindow())

	// 获取当前区块高度
	currentHeight, err := b.GetBlockHeightByHash(prevBlock.Hash())
	if err != nil {
		return ThresholdFailed, err
	}

	// 创世块相关处理
	if currentHeight+1 < confirmationWindow {
		return ThresholdDefined, nil
	}

	// 计算前一个确认窗口的最后一个区块高度
	targetHeight := currentHeight - (currentHeight+1)%confirmationWindow

	// 获取目标高度的区块
	windowBlock, err := b.GetBlockByHash(prevBlock.Hash())

	if err != nil {
		return ThresholdFailed, err
	}

	// 收集需要计算状态的区块
	var neededBlocks []*core.Block
	current := windowBlock

	for current != nil {
		hash := current.BlockHeader().BlockHash()
		if _, ok := cache.Lookup(&hash); ok {
			break
		}

		// 未开始的状态直接设为Defined
		if !checker.HasStarted(current) {
			cache.Update(&hash, ThresholdDefined)
			break
		}

		neededBlocks = append(neededBlocks, current)

		// 获取上一个确认窗口的区块
		targetHeight -= confirmationWindow
		if targetHeight < 0 {
			break
		}
		current, err = b.GetBlockByHash(current.Hash())
		if err != nil {
			return ThresholdFailed, err
		}
	}

	// 从缓存中获取最近的已知状态
	state := ThresholdDefined
	if current != nil {
		hash := current.BlockHeader().BlockHash()
		if s, ok := cache.Lookup(&hash); ok {
			state = s
		} else {
			return ThresholdFailed, fmt.Errorf("缓存中未找到区块 %v 的状态", current.BlockHeader().BlockHash())
		}
	}

	// 计算所有需要的区块状态
	for i := len(neededBlocks) - 1; i >= 0; i-- {
		block := neededBlocks[i]
		newState, err := thresholdStateTransition(state, block, checker, confirmationWindow, b)
		if err != nil {
			return ThresholdFailed, err
		}

		state = newState
		hash := block.BlockHeader().BlockHash()
		cache.Update(&hash, state)
	}

	return state, nil
}

// ThresholdState 获取指定部署的当前阈值状态
func (b *BlockChain) ThresholdState(deploymentID uint32) (ThresholdState, error) {
	// 实际实现需要加锁保护
	bestHash, err := b.GetMainLatestHash() // 假设实现
	if err != nil {
		return ThresholdFailed, err
	}

	bestBlock, err := b.GetBlockByHash(&bestHash)
	if err != nil {
		return ThresholdFailed, err
	}

	return b.deploymentState(bestBlock, deploymentID)
}

// IsDeploymentActive 检查部署是否已激活
func (b *BlockChain) IsDeploymentActive(deploymentID uint32) (bool, error) {
	state, err := b.ThresholdState(deploymentID)
	if err != nil {
		return false, err
	}
	return state == ThresholdActive, nil
}

// deploymentState 获取指定部署在指定区块后的状态
func (b *BlockChain) deploymentState(prevBlock *core.Block, deploymentID uint32) (ThresholdState, error) {
	if deploymentID >= uint32(len(b.chainParams.Deployments)) {
		return ThresholdFailed, fmt.Errorf("无效的部署ID: %d", deploymentID)
	}

	deployment := &b.chainParams.Deployments[deploymentID]
	checker := deploymentChecker{deployment: deployment, chain: b}
	cache := &b.deploymentCaches[deploymentID]

	return b.thresholdState(prevBlock, checker, cache)
}

// initThresholdCaches 初始化阈值状态缓存
func (b *BlockChain) initThresholdCaches() error {
	bestBlock, err := b.GetBestBlock() // 假设实现
	if err != nil {
		return err
	}

	prevBlock, err := b.GetBlockByHash(&bestBlock.BlockHeader().PrevBlock)
	if err != nil {
		return err
	}

	// 初始化警告缓存
	for bit := uint32(0); bit < vbNumBits; bit++ {
		checker := bitConditionChecker{bit: bit, chain: b}
		cache := &b.warningCaches[bit]
		_, err := b.thresholdState(prevBlock, checker, cache)
		if err != nil {
			return err
		}
	}

	// 初始化部署缓存
	for id := 0; id < len(b.chainParams.Deployments); id++ {
		deployment := &b.chainParams.Deployments[id]
		cache := &b.deploymentCaches[id]
		checker := deploymentChecker{deployment: deployment, chain: b}
		_, err := b.thresholdState(prevBlock, checker, cache)
		if err != nil {
			return err
		}
	}

	// 检查是否需要警告未知规则激活
	if b.isCurrent() {
		if err := b.warnUnknownRuleActivations(bestBlock); err != nil {
			return err
		}
	}
	return nil
}

// 以下是辅助接口和结构体的实现示例

// deploymentChecker 部署检查器实现
type deploymentChecker struct {
	deployment *core.ConsensusDeployment
	chain      *BlockChain
}

func (d deploymentChecker) HasStarted(block *core.Block) bool {
	started, _ := d.deployment.DeploymentStarter.HasStarted(block.BlockHeader())
	return started
}

func (d deploymentChecker) HasEnded(block *core.Block) bool {
	// 实现部署结束检查逻辑
	ended, _ := d.deployment.DeploymentEnder.HasEnded(block.BlockHeader())
	return ended
}

func (d deploymentChecker) RuleChangeActivationThreshold() uint32 {
	if d.deployment.CustomActivationThreshold != 0 {
		return d.deployment.CustomActivationThreshold
	}
	return d.chain.chainParams.RuleChangeActivationThreshold
}

func (d deploymentChecker) MinerConfirmationWindow() uint32 {
	return d.chain.chainParams.MinerConfirmationWindow
}

func (d deploymentChecker) EligibleToActivate(block *core.Block) bool {
	// 实现激活条件检查
	height, _ := d.chain.GetBlockHeightByHash(block.Hash())
	return height >= int32(d.deployment.MinActivationHeight)
}

func (d deploymentChecker) IsSpeedy() bool {
	return (d.deployment.MinActivationHeight != 0 ||
		d.deployment.CustomActivationThreshold != 0)
}

func (d deploymentChecker) Condition(block *core.Block) (bool, error) {
	conditionMask := uint32(1) << d.deployment.BitNumber
	version := uint32(block.BlockHeader().Version)
	return (version&vbTopMask == vbTopBits) && (version&conditionMask != 0),
		nil
}

func (d deploymentChecker) ForceActive(block *core.Block) bool {
	if block == nil {
		return false
	}

	// If the deployment has a nonzero AlwaysActiveHeight and the next
	// block’s height is at or above that threshold, then force the state
	// to Active.
	effectiveHeight := d.deployment.EffectiveAlwaysActiveHeight()
	if uint32(block.Height())+1 >= effectiveHeight {
		log.Debugf("Force activating deployment: next block "+
			"height %d >= EffectiveAlwaysActiveHeight %d",
			uint32(block.Height())+1, effectiveHeight)
		return true
	}

	return false
}

func (b bitConditionChecker) EligibleToActivate(block *core.Block) bool {
	return true
}

func (b bitConditionChecker) IsSpeedy() bool {
	return false
}

func (b bitConditionChecker) ForceActive(block *core.Block) bool {
	return false
}

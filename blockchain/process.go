package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"errors"
	"fmt"
	"math/big"
)

type BehaviorFlags uint32

const (
	// BFFastAdd 当设置此标志时，表示可以跳过部分区块校验步骤。
	//适用场景：已知该区块已经通过验证（例如，它已被证明能正确链接到区块链中某个已知的检查点 checkpoint）。这种情况下无需重复执行完整校验，可加速处理。
	//主要用于 “headers-first”（先处理区块头再处理区块体）的同步模式，提高同步效率。
	BFFastAdd BehaviorFlags = 1 << iota

	// BFNoPoWCheck 当设置此标志时，会跳过区块的工作量证明（PoW）校验。
	//工作量证明校验的核心是检查区块哈希是否小于网络规定的目标值（即区块是否 “挖矿成功”）。
	//适用场景：处理 “区块模板”（还未完成 PoW 计算的区块草稿）时，因为模板还未进行挖矿，暂时无需验证 PoW（如之前的 CheckConnectBlockTemplate 方法就用到了这个标志）。
	BFNoPoWCheck

	// BFNone 一个 “空标志” 的便捷值，明确表示未设置任何特殊行为标志。
	//此时区块处理会执行完整的默认校验逻辑（包括 PoW、结构合法性、链上上下文等所有检查）。
	BFNone BehaviorFlags = 0
)

func (b *BlockChain) blockHeaderExists(hash *chainhash.Hash) (bool, error) {
	b.databaseLock.RLock()
	defer b.databaseLock.RUnlock()
	// 1. 如果 hash 为空直接返回
	if hash == nil {
		return false, nil
	}
	// 2. 查询
	key := db.BlockHeaderBucket.Key(hash[:])
	var found bool
	err := b.db.Get(key, func(v []byte) error {
		found = (v != nil)
		return nil
	})
	// 3. 区分“没找到”和“底层错误”
	switch {
	case err == nil:
		return found, nil
	case errors.Is(err, db.ErrKeyNotFound):
		return false, nil
	default:
		return false, fmt.Errorf("blockHeaderExists: %w", err)
	}
}

func (b *BlockChain) ProcessBlock(block *core.Block, flags BehaviorFlags) (bool, bool, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	if b == nil {
		log.Infof("区块链为空")
		return false, false, fmt.Errorf("ProcessBlock: BlockChain 实例为 nil")
	}
	blockHash := block.Hash()
	exists, err := b.blockHeaderExists(blockHash)
	log.Info("是否存在%d", exists) //重新检查更新
	if err != nil {
		return false, false, err
	}
	/*	if exists {
		str := fmt.Sprintf("已经存在这个区块 %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str)
	}*/

	// The block must not already exist as an orphan.
	if _, exists := b.orphans[*blockHash]; exists {
		str := fmt.Sprintf("孤儿区块池中已经存在 (orphan) %v", blockHash)
		return false, false, ruleError(ErrDuplicateBlock, str)
	}

	// Perform preliminary sanity checks on the block and its transactions.
	err = checkBlockSanity(block, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return false, false, err
	}
	blockHeader := &block.MsgBlock().Header
	prevHash := &blockHeader.PrevBlock
	log.Infof("父区块hash:%s", prevHash)

	isGenesisBlock := prevHash.IsEqual(&chainhash.Hash{})
	if !isGenesisBlock {
		// 非创世区块才检查父区块是否存在
		prevHashExists, err := b.blockHeaderExists(prevHash)
		log.Infof("父区块是否存在%v", prevHashExists)
		if err != nil {
			return false, false, err
		}
		if !prevHashExists {
			log.Infof("Adding orphan block %v with parent %v", blockHash, prevHash)
			b.addOrphanBlock(block)
			return false, true, nil
		}
		preBlock, _ := b.GetBlockByHash(prevHash)
		block.SetHeight(preBlock.BlockHeight + 1)
		chainWork := preBlock.GetChainWork()
		bits := block.BlockHeader().Bits
		work := CalculateBlockWork(bits)
		sum := new(big.Int).Add(work, chainWork)
		block.SetChainWork(sum)
		log.Infof("区块工作总量 %d ", work)
		log.Infof("前序区块工作总量 %d ", chainWork)
		log.Infof("高度 %d  区块链工作总量 %d ", block.BlockHeight, block.GetChainWork())
	} else {
		log.Infof("Processing genesis block %v, skipping parent check", blockHash)
	}

	// The block has passed all context independent checks and appears sane
	// enough to potentially accept it into the block chain.
	isMainChain, err := b.maybeAcceptBlock(block, flags)

	log.Infof("被主链接收%v", isMainChain)
	if err != nil {
		return false, false, err
	}

	// Accept any orphan blocks that depend on this block (they are
	// no longer orphans) and repeat for those accepted blocks until
	// there are no more.
	err = b.processOrphans(blockHash, flags, block)
	if err != nil {
		return false, false, err
	}
	log.Debugf("Accepted block %v", blockHash)

	if isMainChain {
		b.bus.Pub("block.accepted", block)
	}
	//通知  更新费用估算
	return isMainChain, false, nil
}

// 递归处理所有依赖该区块的孤儿区块
func (b *BlockChain) processOrphans(hash *chainhash.Hash, flags BehaviorFlags, block *core.Block) error {
	processHashes := make([]*chainhash.Hash, 0, 10)
	processHashes = append(processHashes, hash)
	for len(processHashes) > 0 {
		// Pop the first hash to process from the slice.
		processHash := processHashes[0]
		processHashes[0] = nil // Prevent GC leak.
		processHashes = processHashes[1:]
		for i := 0; i < len(b.prevOrphans[*processHash]); i++ {
			orphan := b.prevOrphans[*processHash][i]
			if orphan == nil {
				log.Warnf("Found a nil entry at index %d in the "+
					"orphan dependency list for block %v", i,
					processHash)
				continue
			}
			orphanHash := orphan.block.Hash()
			b.removeOrphanBlock(orphan)
			i--
			orphan.block.SetHeight(block.Height() + 1)
			chainWork := block.GetChainWork()
			bits := block.BlockHeader().Bits
			work := CalculateBlockWork(bits)
			sum := new(big.Int).Add(work, chainWork)
			orphan.block.SetChainWork(sum)
			_, err := b.maybeAcceptBlock(orphan.block, flags)
			if err != nil {
				return err
			}
			processHashes = append(processHashes, orphanHash)
		}
	}
	return nil
}

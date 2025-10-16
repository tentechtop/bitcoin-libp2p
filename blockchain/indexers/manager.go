package indexers

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	"bitcoin/db"
	"errors"
	"fmt"
)

type Manager struct {
	db             db.KeyValueStore
	enabledIndexes []Indexer
}

func (m Manager) Init(chain *blockchain.BlockChain, interrupt <-chan struct{}) error {
	// 初始化所有索引器
	for _, indexer := range m.enabledIndexes {
		if err := indexer.Init(); err != nil {
			return fmt.Errorf("索引器初始化失败: %w", err)
		}
	}

	// 检查是否需要重建索引
	if needsRebuild, err := m.needsIndexRebuild(); err != nil {
		return err
	} else if needsRebuild {
		log.Infof("开始重建索引...")
		if err := m.rebuildIndexes(chain, interrupt); err != nil {
			return fmt.Errorf("索引重建失败: %w", err)
		}
		log.Infof("索引重建完成")
	}
	return nil
}

func (m Manager) ConnectBlock(block *core.Block, outs []blockchain.SpentTxOut) error {
	log.Infof("连接区块 %s 到索引", block.Hash())
	for _, indexer := range m.enabledIndexes {
		if err := indexer.ConnectBlock(block, outs); err != nil {
			return fmt.Errorf("索引器 %T 处理区块 %s 失败: %w",
				indexer, block.Hash(), err)
		}
	}
	return nil
}

func (m Manager) DisconnectBlock(block *core.Block, outs []blockchain.SpentTxOut) error {
	log.Infof("断开区块 %s 从索引", block.Hash())
	for _, indexer := range m.enabledIndexes {
		if err := indexer.DisconnectBlock(block, outs); err != nil {
			return fmt.Errorf("索引器 %T 断开区块 %s 失败: %w",
				indexer, block.Hash(), err)
		}
	}
	return nil
}

func NewManager(database db.KeyValueStore, enabledIndexes []Indexer) *Manager {
	return &Manager{
		db:             database,
		enabledIndexes: enabledIndexes,
	}
}

// 检查是否需要重建索引
func (m *Manager) needsIndexRebuild() (bool, error) {
	for _, indexer := range m.enabledIndexes {
		switch indexer.(type) {
		case *AddrIndex:
			if !AddrIndexInitialized(m.db) {
				return true, nil
			}
		}
	}
	return false, nil
}

// 通过高度重建所有索引
func (m *Manager) rebuildIndexes(chain *blockchain.BlockChain, interrupt <-chan struct{}) error {
	// 1. 重置所有索引器状态
	for _, indexer := range m.enabledIndexes {
		if err := indexer.Init(); err != nil { // 假设Init方法会重置索引器状态
			return fmt.Errorf("重置索引器 %T 失败: %w", indexer, err)
		}
	}

	// 2. 初始化UTXO视图用于追踪未花费交易输出
	utxoView := blockchain.NewUtxoViewpoint()
	tip := chain.BestSnapshot()
	if tip == nil {
		return errors.New("区块链为空，无法重建索引")
	}
	maxHeight := tip.Height
	log.Infof("开始从高度0重建索引，目标高度: %d", maxHeight)

	// 3. 按高度顺序遍历所有区块
	for height := int32(0); height <= maxHeight; height++ {
		// 检查中断信号
		select {
		case <-interrupt:
			return errors.New("索引重建被中断")
		default:
		}

		// 通过高度获取区块哈希
		block, err := chain.GetMainBlockByHeight(height)
		if err != nil {
			return fmt.Errorf("获取高度 %d 的区块哈希失败: %w", height, err)
		}

		// 获取区块中花费的交易输出
		spentOuts, err := chain.FetchSpentTxOuts(block)
		if err != nil {
			return fmt.Errorf("获取区块 %s（高度 %d）的花费输出失败: %w", block.Hash().String(), height, err)
		}

		// 让所有索引器处理当前区块
		for _, indexer := range m.enabledIndexes {
			if err := indexer.ConnectBlock(block, spentOuts); err != nil {
				return fmt.Errorf("索引器 %T 处理区块 %s（高度 %d）失败: %w",
					indexer, block.Hash().String(), height, err)
			}
		}

		// 更新UTXO视图（移除已花费输出，添加新输出）
		if err := utxoView.ApplyBlock(block); err != nil {
			return fmt.Errorf("更新UTXO视图失败（区块 %s，高度 %d）: %w", block.Hash().String(), height, err)
		}

		// 打印进度日志（每1000个区块）
		if height%1000 == 0 {
			log.Infof("已处理到高度 %d（总进度: %.2f%%）",
				height, float64(height)/float64(maxHeight)*100)
		}
	}

	log.Infof("索引重建完成，共处理 %d 个区块", maxHeight+1)
	return nil
}

//TODO 完善重建主链索引机制
//实现资源广播 和 节点自动拾取未有资源 节省网络带宽
//实现同步时路标 和 同步

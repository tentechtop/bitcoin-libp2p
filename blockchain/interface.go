package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
)

// 抽象区块链接口
type ChainInterface interface {
	VerifyBlock() bool // 验证区块有效性
}

func (bc *BlockChain) VerifyBlock() bool {
	return true
}

// -------------- 交易相关接口 --------------

// ValidateTransaction 验证交易合法性（签名、输入输出合理性等）
func (bc *BlockChain) ValidateTransaction(tx *core.Tx) error {
	return nil
}

// ValidateUTXO 验证交易输入引用的UTXO是否合法
func (bc *BlockChain) ValidateUTXO(txIn *core.TxIn) error {
	return nil
}

// IsTransactionExists 检查交易是否已存在于主链或侧链中
func (bc *BlockChain) IsTransactionExists(txID chainhash.Hash) bool {
	return false
}

// AddTransactionToMempool 将交易添加到内存池（需先通过验证）
func (bc *BlockChain) AddTransactionToMempool(tx *core.Tx) error {
	return nil
}

// -------------- 区块相关接口 --------------

// ValidateBlock 验证区块合法性（结构、难度、交易等）
func (bc *BlockChain) ValidateBlock(block *core.Block) error {
	return nil
}

// CreateGenesisBlock 创建创世区块
func (bc *BlockChain) CreateGenesisBlock() *core.Block {
	return nil
}

// CreateGenesisTransaction 创建创世交易（创世区块中唯一的交易）
func (bc *BlockChain) CreateGenesisTransaction() *core.Tx {
	return nil
}

// CreateCoinBaseTransaction 创建CoinBase交易（每个区块的第一个交易）
func (bc *BlockChain) CreateCoinBaseTransaction(height int32, minerAddr string) *core.Tx {
	return nil
}

// IsCoinBaseTransaction 判断是否为CoinBase交易
func (bc *BlockChain) IsCoinBaseTransaction(tx *core.Tx) bool {
	return true
}

// SwitchToLongerChain 当分叉链更长时切换主链
func (bc *BlockChain) SwitchToLongerChain(newChainTip *chainhash.Hash) error {
	return nil
}

// RemoveBlock 从链中删除指定区块（通常用于回滚）
func (bc *BlockChain) RemoveBlock(hash *chainhash.Hash) error {
	return nil
}

// AddBlock 将区块添加到链中（主链或侧链）
func (bc *BlockChain) AddBlock(block *core.Block) error {
	return nil
}

// RollbackBlock 回滚最新区块（用于处理无效区块）
func (bc *BlockChain) RollbackBlock() error {
	return nil
}

// -------------- 区块查询接口 --------------

// GetGenesisBlockHash 获取创世区块哈希
func (bc *BlockChain) GetGenesisBlockHash() *chainhash.Hash {
	return bc.chainParams.GenesisHash
}

// GetGenesisBlock 获取完整创世区块
func (bc *BlockChain) GetGenesisBlock() *core.Block {
	return nil
}

// GetBlocksByHeightRange 通过高度范围查询区块
func (bc *BlockChain) GetBlocksByHeightRange(start, end int32) ([]*core.Block, error) {
	return nil, nil
}

// GetBlocksByHashes 通过哈希列表查询区块列表
func (bc *BlockChain) GetBlocksByHashes(hashes []*chainhash.Hash) ([]*core.Block, error) {
	return nil, nil
}

// GetBlockHeaderByHeight 通过高度查询区块头
func (bc *BlockChain) GetBlockHeaderByHeight(height int32) (*core.BlockHeader, error) {
	return nil, nil
}

// GetBlockBodyByHeight 通过高度查询区块体（交易列表）
func (bc *BlockChain) GetBlockBodyByHeight(height int32) (*core.MsgBlockBody, error) {
	return nil, nil
}

// GetBlockHeaderByHash 通过哈希查询区块头
func (bc *BlockChain) GetBlockHeaderByHash(hash *chainhash.Hash) (*core.BlockHeader, error) {
	return nil, nil
}

// GetBlockBodyByHash 通过哈希查询区块体（交易列表）
func (bc *BlockChain) GetBlockBodyByHash(hash *chainhash.Hash) (*core.MsgBlockBody, error) {
	return nil, nil
}

// -------------- 交易查询接口 --------------

// GetTransactionByID 通过交易ID查询交易
func (bc *BlockChain) GetTransactionByID(txID *chainhash.Hash) (*core.Tx, error) {
	return nil, nil
}

// GetBlockByTransactionID 通过交易ID查询其所在的完整区块
func (bc *BlockChain) GetBlockByTransactionID(txID *chainhash.Hash) (*core.Block, error) {
	return nil, nil
}

func HaveTransaction(hash *chainhash.Hash) bool {
	return false
}

// -------------- UTXO相关接口 --------------

// GetUTXOByTxIDAndIndex 通过交易ID和输出索引查询UTXO
func (bc *BlockChain) GetUTXOByTxIDAndIndex(txID *chainhash.Hash, index uint32) (*core.TxOut, error) {
	return nil, nil
}

// GetUTXOsByAddress 通过地址查询该地址拥有的UTXO
func (bc *BlockChain) GetUTXOsByAddress(address string) ([]*core.TxOut, error) {
	return nil, nil
}

// GetUTXOsByPublicKey 通过公钥查询其关联地址的所有UTXO
func (bc *BlockChain) GetUTXOsByPublicKey(pubKey []byte) ([]*core.TxOut, error) {
	return nil, nil
}

// ListUTXOs 分页迭代查询UTXO
func (bc *BlockChain) ListUTXOs(page, pageSize int) ([]*core.TxOut, int, error) {
	return nil, 0, nil
}

// IsUTXOUnspent 检查UTXO是否未被花费
func (bc *BlockChain) IsUTXOUnspent(txID *chainhash.Hash, index uint32) bool {
	return true
}

// IsUTXOMature 检查UTXO是否成熟（CoinBase交易需等待100个确认）
func (bc *BlockChain) IsUTXOMature(txID *chainhash.Hash, index uint32) bool {
	return true
}

// RemoveUTXO 从UTXO集中删除指定UTXO（被花费时）
func (bc *BlockChain) RemoveUTXO(txID *chainhash.Hash, index uint32) error {
	return nil
}

// AddUTXO 向UTXO集添加新的UTXO（新交易确认时）
func (bc *BlockChain) AddUTXO(utxo *core.TxOut) error {
	return nil
}

// -------------- 区块定位接口 --------------

// BuildBlockLocator 构建指定区块的定位路标
func (bc *BlockChain) BuildBlockLocator(tip *chainhash.Hash) BlockLocator {
	return BlockLocator{}
}

// BestSnapshot 获取当前主链最佳状态的只读快照
func (b *BlockChain) BestSnapshot() *BestState {
	b.stateLock.RLock()
	snapshot := b.stateSnapshot
	b.stateLock.RUnlock()
	return snapshot
}

type ChainCtx interface {
	// ChainParams returns the chain's configured chaincfg.Params.
	ChainParams() *core.Params

	// BlocksPerRetarget returns the number of blocks before retargeting
	// occurs.
	BlocksPerRetarget() int32

	// MinRetargetTimespan returns the minimum amount of time to use in the
	// difficulty calculation.
	MinRetargetTimespan() int64

	// MaxRetargetTimespan returns the maximum amount of time to use in the
	// difficulty calculation.
	MaxRetargetTimespan() int64

	// 新增：根据高度获取主链区块（核心依赖）
	GetMainBlockByHeight(height int32) (*core.Block, error)
}

package blockchain

import (
	"bitcoin/chaincfg"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/event"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"math"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	db "bitcoin/db"
)

const (
	// OutPointIndexSize 交易输出索引的字节长度（uint32对应4字节）
	OutPointIndexSize = 4
)

const (
	// maxNonce is the maximum value a nonce can be in a block header.
	MaxNonce = ^uint32(0) // 2^32 - 1

	// maxExtraNonce is the maximum value an extra nonce used in a coinbase
	// transaction can be.
	MaxExtraNonce = ^uint64(0) // 2^64 - 1

	// hpsUpdateSecs is the number of seconds to wait in between each
	// update to the hashes per second monitor.
	HpsUpdateSecs = 10

	// hashUpdateSec is the number of seconds each worker waits in between
	// notifying the speed monitor with how many hashes have been completed
	// while they are actively searching for a solution.  This is done to
	// reduce the amount of syncs between the workers that must be done to
	// keep track of the hashes per second.
	HashUpdateSecs = 15
)

var (
	zeroHash chainhash.Hash
)

// 全局单例，原子读写
var (
	currentBest atomic.Pointer[BestState]
)

func init() {
	//检查是否有创世区块
	//如果没有则创建
}

// InitBestState 启动时调用一次即可
func InitBestState(height int32, hash chainhash.Hash) {
	best := &BestState{
		Hash:        hash,
		Height:      height,
		Bits:        0x1d00ffff, // 示例难度
		BlockSize:   0,          // 可填 0
		BlockWeight: 0,
		NumTxns:     0,
		TotalTxns:   0,
		MedianTime:  time.Now(),
	}
	currentBest.Store(best)
}

type Config struct {
	Bus *event.Bus
	// DB defines the database which houses the blocks and will be used to
	// store all metadata created by this package such as the utxo set.
	//
	// This field is required.
	ChainDB db.KeyValueStore

	// The maximum size in bytes of the UTXO cache.
	//
	// This field is required.
	UtxoCacheMaxSize uint64

	// Interrupt specifies a channel the caller can close to signal that
	// long running operations, such as catching up indexes or performing
	// database migrations, should be interrupted.
	//
	// This field can be nil if the caller does not desire the behavior.
	Interrupt <-chan struct{}

	// ChainParams identifies which chain parameters the chain is associated
	// with.
	//
	// This field is required.
	ChainParams *core.Params

	Checkpoints []core.Checkpoint

	// TimeSource defines the median time source to use for things such as
	// block processing and determining whether or not the chain is current.
	//
	// The caller is expected to keep a reference to the time source as well
	// and add time samples from other peers on the network so the local
	// time is adjusted to be in agreement with other peers.
	TimeSource MedianTimeSource

	// SigCache defines a signature cache to use when when validating
	// signatures.  This is typically most useful when individual
	// transactions are already being validated prior to their inclusion in
	// a block such as what is usually done via a transaction memory pool.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
	SigCache *txscript.SigCache

	// HashCache defines a transaction hash mid-state cache to use when
	// validating transactions. This cache has the potential to greatly
	// speed up transaction validation as re-using the pre-calculated
	// mid-state eliminates the O(N^2) validation complexity due to the
	// SigHashAll flag.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
	HashCache *txscript.HashCache

	// Prune specifies the target database usage (in bytes) the database
	// will target for with block files.  Prune at 0 specifies that no
	// blocks will be deleted.
	Prune uint64

	IndexManager IndexManager
}

// BlockChain 区块链服务
type BlockChain struct {
	checkpoints         []core.Checkpoint
	checkpointsByHeight map[int32]*core.Checkpoint
	db                  db.KeyValueStore
	bus                 event.Bus

	stateLock sync.RWMutex

	stateSnapshot *BestState

	chainLock    sync.RWMutex
	databaseLock sync.RWMutex

	utxoCache    *utxoCache
	chainParams  *core.Params
	timeSource   MedianTimeSource
	bestChain    *core.Block
	sigCache     *txscript.SigCache
	hashCache    *txscript.HashCache
	orphanLock   sync.RWMutex
	orphans      map[chainhash.Hash]*orphanBlock
	prevOrphans  map[chainhash.Hash][]*orphanBlock
	oldestOrphan *orphanBlock

	notificationsLock sync.RWMutex
	notifications     []NotificationCallback

	minRetargetTimespan int64 // 每个 “难度调整周期” 包含的区块数量。
	maxRetargetTimespan int64 // 难度调整周期的 “最小允许时间跨度”（以秒为单位）。
	blocksPerRetarget   int32 // 难度调整周期的 “最大允许时间跨度”（以秒为单位）。

	deploymentCaches []thresholdStateCache
	warningCaches    []thresholdStateCache

	unknownRulesWarned bool

	IndexManager IndexManager
}

// BestState 是一个只读快照，把“当前主链最佳区块”的所有关键信息一次性打包，方便并发代码在不加锁的情况下随时拿到链的最新状态。
// 详细解释：
// 数据来源
// 每当主链产生新的最佳区块，节点内部会新建一个 BestState 实例，把新区块的哈希、高度、难度、大小、交易数等信息填进去。
// 使用方式
// 外部代码通过 BestSnapshot() 方法拿到这份快照的指针。
// 并发安全：内部保证不会被回滚或修改，读的时候不用加锁。
// 只读共享：返回的是同一份共享内存，所有人拿到的都是同一个对象，所以不要改里面的字段。
type BestState struct {
	Hash        chainhash.Hash // 最佳区块的哈希
	Height      int32          // 最佳区块的高度
	Bits        uint32         // 该区块的难度 bits（压缩目标值）
	ChainWork   big.Int        //累计工作总量
	BlockSize   uint64         // 该区块原始字节大小
	BlockWeight uint64         // 该区块的权重（BIP-141 用于手续费计算）
	NumTxns     uint64         // 该区块包含的交易数量
	TotalTxns   uint64         // 从创世块到该区块为止链上累计交易数量
	MedianTime  time.Time      // 根据过去 11 个区块时间计算出的“中位时间”，用于验证时间锁
}

// GetBlockChain 供外部拿到当前链快照
func GetBlockChain() *BestState {
	return currentBest.Load()
}

// UpdateBestState 当链增长后更新
func UpdateBestState(height int32, hash chainhash.Hash, now time.Time) {
	best := &BestState{
		Hash:        hash,
		Height:      height,
		Bits:        0x1d00ffff,
		BlockSize:   0,
		BlockWeight: 0,
		NumTxns:     0,
		TotalTxns:   0,
		MedianTime:  now,
	}
	currentBest.Store(best)
}

// BlockLocator 就是“定位链上某个区块坐标的精简哈希列表”，
// BlockLocator 是 Bitcoin 协议里的“高效路标”，用极小的数据量即可让节点在巨大区块链里迅速对齐分叉点，避免无谓的全量同步。
// 用来在 节点间同步 时快速找出双方共同的最近分叉点，然后只下载差异部分，而不是把整条链重新传一遍。
// 为什么需要它
// 两个节点连接后，各自保存的链可能长度不同、甚至有分叉。直接把所有区块哈希广播一遍太浪费。
// BlockLocator 给出一种 指数级稀疏采样 的哈希序列，让对方能在 O(log n) 次往返 内找到共同祖先。
// 链：genesis→1→…→15→16→17→18
// 分叉：15→16a→17a
// 定位 17a 的 BlockLocator：
// [17a, 16a, 15, 14, …, 6, 4, genesis]
// 对方拿到后，从前往后比对自己的索引，第一个 双方都有的哈希 就是最近共同祖先（这里是 15），之后只要从 16a/17a 开始请求缺失区块即可。
// 跳步规则（指数回退）
// 从 tip 开始，先走 1 步，再走 2 步，再走 4 步，再走 8 步……
type BlockLocator []*chainhash.Hash

// 最多缓存100个孤儿块
const maxOrphanBlocks = 100

type orphanBlock struct {
	block      *core.Block
	expiration time.Time
}

func New(config *Config) (*BlockChain, error) {
	if config.ChainDB == nil {
		return nil, AssertError("blockchain.New database is nil")
	}
	if config.ChainParams == nil {
		return nil, AssertError("blockchain.New chain parameters nil")
	}
	if config.TimeSource == nil {
		return nil, AssertError("blockchain.New timesource is nil")
	}

	var checkpointsByHeight map[int32]*core.Checkpoint
	var prevCheckpointHeight int32
	if len(config.Checkpoints) > 0 {
		checkpointsByHeight = make(map[int32]*core.Checkpoint)
		for i := range config.Checkpoints {
			checkpoint := &config.Checkpoints[i]
			if checkpoint.Height <= prevCheckpointHeight {
				return nil, AssertError("blockchain.New " +
					"checkpoints are not sorted by height")
			}
			checkpointsByHeight[checkpoint.Height] = checkpoint
			prevCheckpointHeight = checkpoint.Height
		}
	}
	params := config.ChainParams
	targetTimespan := int64(params.TargetTimespan / time.Second)
	targetTimePerBlock := int64(params.TargetTimePerBlock / time.Second)
	adjustmentFactor := params.RetargetAdjustmentFactor
	b := BlockChain{
		checkpoints:         config.Checkpoints,
		checkpointsByHeight: checkpointsByHeight,

		db: config.ChainDB,

		chainParams:         params,
		timeSource:          config.TimeSource,
		sigCache:            config.SigCache,
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),

		hashCache:   config.HashCache,
		orphans:     make(map[chainhash.Hash]*orphanBlock),
		prevOrphans: make(map[chainhash.Hash][]*orphanBlock),

		utxoCache:        newUtxoCache(config.ChainDB, config.UtxoCacheMaxSize),
		warningCaches:    newThresholdCaches(vbNumBits),
		deploymentCaches: newThresholdCaches(core.DefinedDeployments),

		IndexManager: config.IndexManager,
	}

	// 初始化顶端
	// 如果高度为零的区块不存在，保存创世区块
	genesisHash, err := b.MainChainGetHashByHeightInit32(0)
	if err != nil {
		// 若获取失败，说明创世区块不存在，需要创建并保存
		log.Infof("创世区块不存在，开始初始化创世区块...")

		// 从链参数中获取预定义的创世区块
		genesisBlock := b.chainParams.GenesisBlock
		if genesisBlock == nil {
			return nil, AssertError("创世区块未在链参数中定义")
		}

		block := core.NewBlock(genesisBlock)
		calcMerkleRoot := CalcMerkleRoot(block.Transactions(), false)
		log.Infof("默克尔Root : %s", calcMerkleRoot)
		block.SetMerkleRoot(calcMerkleRoot)
		block.BlockHeight = 0

		//挖矿 找到符合条件的Nonce
		/*		header := block.MsgBlock().Header
				targetDifficulty := CompactToBig(header.Bits)
				log.Infof("创世区块挖矿开始 | 难度目标: %x | 初始Nonce: %d", targetDifficulty.Bytes(), header.Nonce)

				var foundNonce bool // 标记是否找到有效Nonce
				for nonce := uint32(0); nonce <= MaxNonce; nonce++ {
					// 1. 更新区块头的Nonce（当前尝试的随机数）
					header.Nonce = nonce
					// 2. 计算区块头哈希（比特币标准：双重SHA256）
					currentHash := header.BlockHash()
					// 3. 验证哈希是否满足目标难度（hash ≤ targetDifficulty）
					// 利用已有工具函数判断，传入哈希字节切片和目标难度值
					if DifficultyCheck(currentHash[:], targetDifficulty) {
						// 4. 找到有效Nonce，更新区块头并退出循环
						header.Nonce = nonce
						foundNonce = true
						log.Infof("创世区块挖矿成功 | 找到有效Nonce: %d | 区块哈希: %s", nonce, currentHash.String())
						break
					}
					// 可选：每计算100万次哈希打印进度（避免日志刷屏，按需开启）
					if nonce%1000000 == 0 && nonce != 0 {
						log.Tracef("挖矿中 | 已尝试Nonce: %d | 当前哈希: %s", nonce, currentHash.String())
					}
				}
				// 5. 处理挖矿结果（创世区块必须找到有效Nonce，否则难度配置异常）
				if !foundNonce {
					return nil, fmt.Errorf("创世区块挖矿失败：遍历所有Nonce(%d)仍未找到满足难度的解，请检查难度配置(Bits: %x)",
						MaxNonce, header.Bits)
				}*/

		// 处理创世区块，flags设为0表示正常处理

		// 设置区块链顶端为创世区块
		genesisHash = block.Hash()
		b.bestChain = block // 假设BlockChain结构体有tipHash字段
		//初始化状态快照

		log.Infof("创世区块初始化成功，哈希: %v，高度: 0", genesisHash)
		work := CalculateBlockWork(block.BlockHeader().Bits)
		block.SetChainWork(work)

		log.Infof("当前区块工作量%d", work)

		// 1. 计算创世区块的关键属性（用于构建快照）
		genesisHash = block.Hash()
		blockHeader := block.BlockHeader()
		blockSize := block.Size()                    // 假设core.Block有Size()方法，返回区块原始字节大小
		blockWeight := block.Weight()                // 假设core.Block有Weight()方法，实现BIP-141权重计算
		numTxns := uint64(len(block.Transactions())) // 创世区块交易数（通常为1笔CoinBase交易）
		totalTxns := numTxns                         // 累计交易数=创世区块交易数
		//medianTime := time.Unix(b.CalcPastMedianTime(blockHeader), 0) // 计算中位时间
		chainWork := CalculateBlockWork(blockHeader.Bits) // 计算区块工作量

		// 2. 构建创世区块的BestState快照（修正笔误：ChinaWork → ChainWork）
		genesisBestState := &BestState{
			Hash:        *genesisHash,
			Height:      0,
			Bits:        blockHeader.Bits,
			ChainWork:   *chainWork, // 累计工作量（创世区块工作量=自身工作量）
			BlockSize:   blockSize,
			BlockWeight: blockWeight,
			NumTxns:     numTxns,
			TotalTxns:   totalTxns,
			//MedianTime:  medianTime,
		}
		// 3. 更新stateSnapshot（写操作加互斥锁）
		b.stateSnapshot = genesisBestState
		b.bestChain = block // 同步更新最佳主链引用
		block.SetHeight(0)

		log.Infof("创世区块初始化成功，哈希: %v，高度: 0", genesisHash)
		log.Infof("当前区块工作量: %v", chainWork)

		err := b.SaveBlock(block)
		if err != nil {
			log.Infof("保存创世区块失败")
			return nil, err
		}
		//更新主链
		if err := b.UpdateMainChain(genesisHash, chainWork, 0); err != nil {
			log.Infof("更新主链失败")
			return nil, err
		}
		//将区块应用到主链
		err1 := b.ApplyToMainChain(block)
		if err1 != nil {
			log.Infof("更新主链失败")
			return nil, err
		}
		b.ChainParams().GenesisHash = genesisHash
	} else {
		// 创世区块已存在，加载当前顶端信息
		log.Infof("创世区块已存在，哈希: %v", genesisHash)
		//当前主链最新区块
		mainLatestHash, err := b.GetMainLatestHash() // 主链最新区块哈希
		if err != nil {
			return nil, fmt.Errorf("获取主链最新哈希失败: %w", err)
		}
		mainChainWork, err := b.GetMainChainWork() // 主链当前累计工作量
		if err != nil {
			return nil, fmt.Errorf("查询主链累计工作量出错: %w", err)
		}
		height, err := b.GetMainLatestHeight()
		if err != nil {
			return nil, fmt.Errorf("查询主链最新高度失败: %w", err)
		}
		hash, err := b.GetMainLatestHash()
		if err != nil {
			return nil, fmt.Errorf("查询主链最新Hash失败: %w", err)
		}
		//根据Hash查询区块头
		header, err := b.GetBlockHeader(hash[:])
		if err != nil {
			return nil, fmt.Errorf("根据Hash查询区块头失败: %w", err)
		}
		byHash, err := b.GetBlockBodyByHash(&hash)
		if err != nil {
			return nil, fmt.Errorf("根据Hash查询区块体失败: %w", err)
		}
		workByHash, err := b.GetBlockChainWorkByHash(hash)
		if err != nil {
			return nil, fmt.Errorf("根据Hash查询区块工作量缓存失败: %w", err)
		}

		log.Infof("当前数据: \n"+
			"主链最新区块哈希: %s\n"+
			"主链当前累计工作量: %v\n"+
			"主链最新高度: %d\n"+
			"区块头信息: %+v\n"+
			"区块体信息: %+v\n"+
			"区块工作量缓存: %v",
			mainLatestHash, // 哈希值通常用%x以十六进制展示
			mainChainWork,
			height,
			header, // 结构体用%+v展示字段名和值
			byHash,
			workByHash)

		genesisBestState := &BestState{
			Hash:      hash,
			Height:    height,
			Bits:      header.Bits,
			ChainWork: *mainChainWork, // 累计工作量（创世区块工作量=自身工作量）
		}
		b.stateSnapshot = genesisBestState
		blcok, _ := b.GetMainBlockByHeight(height)
		b.bestChain = blcok

		b.ChainParams().GenesisHash = genesisHash
	}
	log.Infof("初始化区块链")
	if b.db == nil {
		log.Info("区块链数据库是空的")
	}
	return &b, nil
}

func (b *BlockChain) GetUtxoCache() *utxoCache {
	return b.utxoCache
}

func (b *BlockChain) UpdateMainChainBestState(block *core.Block, header core.BlockHeader, hash *chainhash.Hash, work *big.Int, height int32) interface{} {
	genesisBestState := &BestState{
		Hash:      *hash,
		Height:    height,
		Bits:      header.Bits,
		ChainWork: *work, // 累计工作量（创世区块工作量=自身工作量）
	}
	b.stateSnapshot = genesisBestState
	b.bestChain = block
	return nil
}

// 计算区块奖励
func CalcBlockSubsidy(height int32, chainParams *core.Params) int64 {
	if chainParams.SubsidyReductionInterval == 0 {
		return chaincfg.BaseSubsidy
	}
	return chaincfg.BaseSubsidy >> uint(height/chainParams.SubsidyReductionInterval)
}

func IsCoinBase(tx *core.Tx) bool {
	return IsCoinBaseTx(tx.MsgTx())
}

func IsCoinBaseTx(msgTx *core.MsgTx) bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) != 1 {
		return false
	}
	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if prevOut.Index != math.MaxUint32 || prevOut.Hash != zeroHash {
		return false
	}
	return true
}

func CountSigOps(tx *core.Tx) int {
	msgTx := tx.MsgTx()
	// Accumulate the number of signature operations in all transaction
	// inputs.
	totalSigOps := 0
	for _, txIn := range msgTx.TxIn {
		numSigOps := txscript.GetSigOpCount(txIn.SignatureScript)
		totalSigOps += numSigOps
	}
	// Accumulate the number of signature operations in all transaction
	// outputs.
	for _, txOut := range msgTx.TxOut {
		numSigOps := txscript.GetSigOpCount(txOut.PkScript)
		totalSigOps += numSigOps
	}
	return totalSigOps
}

// IsFinalizedTransaction 这段代码的逻辑是判断一笔交易（tx）在给定的区块高度（blockHeight）和时间（blockTime）下，是否已经被“最终确认”（finalized）。
func IsFinalizedTransaction(tx *core.Tx, blockHeight int32, blockTime time.Time) bool {
	msgTx := tx.MsgTx()
	lockTime := msgTx.LockTime
	if lockTime == 0 {
		return true
	}
	blockTimeOrHeight := int64(0)
	if lockTime < txscript.LockTimeThreshold {
		blockTimeOrHeight = int64(blockHeight)
	} else {
		blockTimeOrHeight = blockTime.Unix()
	}
	if int64(lockTime) < blockTimeOrHeight {
		return true
	}
	// At this point, the transaction's lock time hasn't occurred yet, but
	// the transaction might still be finalized if the sequence number
	// for all transaction inputs is maxed out.
	for _, txIn := range msgTx.TxIn {
		if txIn.Sequence != math.MaxUint32 {
			return false
		}
	}
	return true
}

type SequenceLock struct {
	Seconds     int64
	BlockHeight int32
}

func CountP2SHSigOps(tx *core.Tx, isCoinBaseTx bool, utxoView *UtxoViewpoint) (int, error) {
	if isCoinBaseTx {
		return 0, nil
	}
	msgTx := tx.MsgTx()
	totalSigOps := 0
	for txInIndex, txIn := range msgTx.TxIn {
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return 0, ruleError(ErrMissingTxOut, str)
		}
		pkScript := utxo.PkScript()
		if !txscript.IsPayToScriptHash(pkScript) {
			continue
		}
		sigScript := txIn.SignatureScript
		numSigOps := txscript.GetPreciseSigOpCount(sigScript, pkScript, true)
		lastSigOps := totalSigOps
		totalSigOps += numSigOps
		if totalSigOps < lastSigOps {
			str := fmt.Sprintf("the public key script from output "+
				"%v contains too many signature operations - "+
				"overflow", txIn.PreviousOutPoint)
			return 0, ruleError(ErrTooManySigOps, str)
		}
	}

	return totalSigOps, nil
}

func CheckTransactionInputs(tx *core.Tx, txHeight int32, utxoView *UtxoViewpoint, chainParams *core.Params) (int64, error) {
	if IsCoinBase(tx) {
		return 0, nil
	}
	var totalSatoshiIn int64
	for txInIndex, txIn := range tx.MsgTx().TxIn {
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil {
			log.Infof("UTXO为空")
		}
		log.Infof("打印这个UTXO%s", utxo)
		if utxo == nil || utxo.IsSpent() {
			log.Infof("UTXO已经花费")
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return 0, ruleError(ErrMissingTxOut, str)
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		if utxo.IsCoinBase() {
			originHeight := utxo.BlockHeight()
			blocksSincePrev := txHeight - originHeight
			coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
			if blocksSincePrev < coinbaseMaturity {
				str := fmt.Sprintf("tried to spend coinbase "+
					"transaction output %v from height %v "+
					"at height %v before required maturity "+
					"of %v blocks", txIn.PreviousOutPoint,
					originHeight, txHeight,
					coinbaseMaturity)
				return 0, ruleError(ErrImmatureSpend, str)
			}
		}
		originTxSatoshi := utxo.Amount()
		if originTxSatoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", utils.Amount(originTxSatoshi))
			return 0, ruleError(ErrBadTxOutValue, str)
		}
		if originTxSatoshi > chaincfg.MaxSatoshi {
			str := fmt.Sprintf("transaction output value is "+
				"higher than max allowed value: %v > %v ",
				utils.Amount(originTxSatoshi),
				chaincfg.MaxSatoshi)
			return 0, ruleError(ErrBadTxOutValue, str)
		}

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		lastSatoshiIn := totalSatoshiIn
		totalSatoshiIn += originTxSatoshi
		if totalSatoshiIn < lastSatoshiIn ||
			totalSatoshiIn > chaincfg.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"inputs is %v which is higher than max "+
				"allowed value of %v", totalSatoshiIn,
				chaincfg.MaxSatoshi)
			return 0, ruleError(ErrBadTxOutValue, str)
		}
	}

	// Calculate the total output amount for this transaction.  It is safe
	// to ignore overflow and out of range errors here because those error
	// conditions would have already been caught by checkTransactionSanity.
	var totalSatoshiOut int64
	for _, txOut := range tx.MsgTx().TxOut {
		totalSatoshiOut += txOut.Value
	}

	// Ensure the transaction does not spend more than its inputs.
	if totalSatoshiIn < totalSatoshiOut {
		str := fmt.Sprintf("total value of all transaction inputs for "+
			"transaction %v is %v which is less than the amount "+
			"spent of %v", tx.Hash(), totalSatoshiIn, totalSatoshiOut)
		return 0, ruleError(ErrSpendTooHigh, str)
	}

	// NOTE: bitcoind checks if the transaction fees are < 0 here, but that
	// is an impossible condition because of the check above that ensures
	// the inputs are >= the outputs.
	txFeeInSatoshi := totalSatoshiIn - totalSatoshiOut
	return txFeeInSatoshi, nil
}

func ValidateTransactionScripts(tx *core.Tx, utxoView *UtxoViewpoint, flags txscript.ScriptFlags, sigCache *txscript.SigCache, hashCache *txscript.HashCache) error {

	segwitActive := flags&txscript.ScriptVerifyWitness == txscript.ScriptVerifyWitness

	if segwitActive && tx.MsgTx().HasWitness() &&
		!hashCache.ContainsHashes(tx.Hash()) {
		hashCache.AddSigHashes(tx.MsgTx(), utxoView)
	}

	var cachedHashes *txscript.TxSigHashes
	if segwitActive && tx.MsgTx().HasWitness() {
		cachedHashes, _ = hashCache.GetSigHashes(tx.Hash())
	}

	txIns := tx.MsgTx().TxIn
	txValItems := make([]*txValidateItem, 0, len(txIns))
	for txInIdx, txIn := range txIns {
		// Skip coinbases.
		if txIn.PreviousOutPoint.Index == math.MaxUint32 {
			continue
		}

		txVI := &txValidateItem{
			txInIndex: txInIdx,
			txIn:      txIn,
			tx:        tx,
			sigHashes: cachedHashes,
		}
		txValItems = append(txValItems, txVI)
	}

	validator := newTxValidator(utxoView, flags, sigCache, hashCache)
	return validator.Validate(txValItems)
}

func (b *BlockChain) CalcPastMedianTime(node *core.BlockHeader) int64 {
	timestamps := make([]int64, medianTimeBlocks)
	numNodes := 0
	iterNode := node
	for i := 0; i < medianTimeBlocks && iterNode != nil; i++ {
		timestamps[i] = iterNode.Timestamp
		numNodes++
		prevHash := iterNode.ParentHash()
		header, err := b.GetBlockHeader(prevHash[:])
		if err != nil {
			log.Infof("错误,%s", err)
			continue
		}
		iterNode = header // 修复：直接赋值指针，不需要取地址
	}
	timestamps = timestamps[:numNodes]
	sort.Sort(timeSorter(timestamps))
	medianTimestamp := timestamps[numNodes/2]
	return medianTimestamp
}

func countSpentOutputs(block *core.Block) int {
	// Exclude the coinbase transaction since it can't spend anything.
	var numSpent int
	for _, tx := range block.Transactions()[1:] {
		numSpent += len(tx.MsgTx().TxIn)
	}
	return numSpent
}

func (b *BlockChain) removeOrphanBlock(orphan *orphanBlock) {
	// Protect concurrent access.
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// Remove the orphan block from the orphan pool.
	orphanHash := orphan.block.Hash()
	delete(b.orphans, *orphanHash)

	// Remove the reference from the previous orphan index too.  An indexing
	// for loop is intentionally used over a range here as range does not
	// reevaluate the slice on each iteration nor does it adjust the index
	// for the modified slice.
	prevHash := &orphan.block.MsgBlock().Header.PrevBlock
	orphans := b.prevOrphans[*prevHash]
	for i := 0; i < len(orphans); i++ {
		hash := orphans[i].block.Hash()
		if hash.IsEqual(orphanHash) {
			copy(orphans[i:], orphans[i+1:])
			orphans[len(orphans)-1] = nil
			orphans = orphans[:len(orphans)-1]
			i--
		}
	}
	b.prevOrphans[*prevHash] = orphans

	// Remove the map entry altogether if there are no longer any orphans
	// which depend on the parent hash.
	if len(b.prevOrphans[*prevHash]) == 0 {
		delete(b.prevOrphans, *prevHash)
	}
}

func (b *BlockChain) addOrphanBlock(block *core.Block) {
	// Remove expired orphan blocks.
	for _, oBlock := range b.orphans {
		if time.Now().After(oBlock.expiration) {
			b.removeOrphanBlock(oBlock)
			continue
		}

		// Update the oldest orphan block pointer so it can be discarded
		// in case the orphan pool fills up.
		if b.oldestOrphan == nil || oBlock.expiration.Before(b.oldestOrphan.expiration) {
			b.oldestOrphan = oBlock
		}
	}

	// Limit orphan blocks to prevent memory exhaustion.
	if len(b.orphans)+1 > maxOrphanBlocks {
		// Remove the oldest orphan to make room for the new one.
		b.removeOrphanBlock(b.oldestOrphan)
		b.oldestOrphan = nil
	}

	// Protect concurrent access.  This is intentionally done here instead
	// of near the top since removeOrphanBlock does its own locking and
	// the range iterator is not invalidated by removing map entries.
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// Insert the block into the orphan map with an expiration time
	// 1 hour from now.
	expiration := time.Now().Add(time.Hour)
	oBlock := &orphanBlock{
		block:      block,
		expiration: expiration,
	}
	b.orphans[*block.Hash()] = oBlock

	// Add to previous hash lookup index for faster dependency lookups.
	prevHash := &block.MsgBlock().Header.PrevBlock
	b.prevOrphans[*prevHash] = append(b.prevOrphans[*prevHash], oBlock)
}

// CachedStateSize returns the total size of the cached state of the blockchain
// in bytes.
func (b *BlockChain) CachedStateSize() uint64 {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()
	return b.utxoCache.totalMemoryUsage()
}

// 区块头基础验证
func (b *BlockChain) checkBlockContext(block *core.Block, flags BehaviorFlags) error {
	log.Infof("检查区块")
	header := &block.MsgBlock().Header
	err := b.CheckBlockHeaderContext(block, flags, b, false)
	if err != nil {
		return err
	}
	fastAdd := flags&BFFastAdd == BFFastAdd
	if !fastAdd {
		blockHeight := block.BlockHeight
		blockTime := header.Timestamp
		for _, tx := range block.Transactions() {
			if !IsFinalizedTransaction(tx, blockHeight,
				time.Unix(blockTime, 0)) {

				str := fmt.Sprintf("block contains unfinalized "+
					"transaction %v", tx.Hash())
				return ruleError(ErrUnfinalizedTx, str)
			}
		}
		if ShouldHaveSerializedBlockHeight(header) &&
			blockHeight >= b.chainParams.BIP0034Height {
			coinbaseTx := block.Transactions()[0]
			err := CheckSerializedHeight(coinbaseTx, blockHeight)
			if err != nil {
				return err
			}
		}
		if err := ValidateWitnessCommitment(block); err != nil {
			return err
		}
		blockWeight := GetBlockWeight(block)
		if blockWeight > MaxBlockWeight {
			str := fmt.Sprintf("block's weight metric is "+
				"too high - got %v, max %v",
				blockWeight, MaxBlockWeight)
			return ruleError(ErrBlockWeightTooHigh, str)
		}
	}
	log.Infof("区块检查完成")
	return nil
}

func ShouldHaveSerializedBlockHeight(header *core.BlockHeader) bool {
	return header.Version >= serializedHeightVersion
}

func CheckSerializedHeight(coinbaseTx *core.Tx, wantHeight int32) error {
	serializedHeight, err := ExtractCoinbaseHeight(coinbaseTx)
	if err != nil {
		return err
	}

	if serializedHeight != wantHeight {
		str := fmt.Sprintf("the coinbase signature script serialized "+
			"block height is %d when %d was expected",
			serializedHeight, wantHeight)
		return ruleError(ErrBadCoinbaseHeight, str)
	}
	return nil
}

// ExtractCoinbaseHeight attempts to extract the height of the block from the
// scriptSig of a coinbase transaction.  Coinbase heights are only present in
// blocks of version 2 or later.  This was added as part of BIP0034.
func ExtractCoinbaseHeight(coinbaseTx *core.Tx) (int32, error) {
	sigScript := coinbaseTx.MsgTx().TxIn[0].SignatureScript
	if len(sigScript) < 1 {
		str := "the coinbase signature script for blocks of " +
			"version %d or greater must start with the " +
			"length of the serialized block height"
		str = fmt.Sprintf(str, serializedHeightVersion)
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	// Detect the case when the block height is a small integer encoded with
	// as single byte.
	opcode := int(sigScript[0])
	if opcode == txscript.OP_0 {
		return 0, nil
	}
	if opcode >= txscript.OP_1 && opcode <= txscript.OP_16 {
		return int32(opcode - (txscript.OP_1 - 1)), nil
	}

	// Otherwise, the opcode is the length of the following bytes which
	// encode in the block height.
	serializedLen := int(sigScript[0])
	if len(sigScript[1:]) < serializedLen {
		str := "the coinbase signature script for blocks of " +
			"version %d or greater must start with the " +
			"serialized block height"
		str = fmt.Sprintf(str, serializedLen)
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	// We use 4 bytes here since it saves us allocations. We use a stack
	// allocation rather than a heap allocation here.
	var serializedHeightBytes [4]byte
	copy(serializedHeightBytes[:], sigScript[1:serializedLen+1])

	serializedHeight := int32(
		binary.LittleEndian.Uint32(serializedHeightBytes[:]),
	)

	if err := compareScript(serializedHeight, sigScript); err != nil {
		return 0, err
	}

	return serializedHeight, nil
}

func compareScript(height int32, script []byte) error {
	scriptBuilder := txscript.NewScriptBuilder(
		txscript.WithScriptAllocSize(coinbaseHeightAllocSize),
	)
	scriptHeight, err := scriptBuilder.AddInt64(
		int64(height),
	).Script()
	if err != nil {
		return err
	}

	if !bytes.HasPrefix(script, scriptHeight) {
		str := fmt.Sprintf("the coinbase signature script does not "+
			"minimally encode the height %d", height)
		return ruleError(ErrBadCoinbaseHeight, str)
	}

	return nil
}

// 检查高度连续 hash连续 检查Hash是否符合难度要求
// 验证前序区块有效性
// 计算并设置当前区块高度
// 验证区块上下文规则
// 若前序区块不存在，返回 “前序区块未知” 错误；
// 若前序区块已知无效，返回 “祖先区块无效” 错误。
func (b *BlockChain) CheckBlockHeaderContext(block *core.Block, flags BehaviorFlags, c ChainCtx, skipCheckpoint bool) error {
	// 判断是否为创世区块（通常高度为0）
	isGenesisBlock := block.Height() == 0
	log.Infof("是否创世区块:%v", isGenesisBlock)
	if isGenesisBlock {
		return nil
	}
	//检查

	return nil
}

// GetMainChainWork 获取当前主链最新区块的工作总量
// 返回值：最新区块的工作总量（big.Int）、可能的错误信息
func (b *BlockChain) GetMainChainWork() (*big.Int, error) {
	// 1. 获取当前主链最新区块的哈希
	hash, err := b.GetMainLatestHash()
	if err != nil {
		// 包装错误信息，明确错误发生环节
		return nil, fmt.Errorf("获取主链最新区块哈希失败: %w", err)
	}

	// 2. 根据最新区块哈希获取对应的工作总量
	chainWork, err2 := b.GetBlockChainWorkByHash(hash)
	if err2 != nil {
		// 包装错误信息，包含具体区块哈希便于排查
		return nil, fmt.Errorf("获取区块 %s 的工作总量失败: %w", hash.String(), err2)
	}

	// 3. 额外检查工作总量是否为nil（防止极端情况下的空值）
	if chainWork == nil {
		return nil, fmt.Errorf("区块 %s 的工作总量为空", hash.String())
	}
	return chainWork, nil
}

/*
新主链 ，核心是处理 “更长工作量分叉链替代当前主链” 的全流程，确保状态一致性、原子性和数据正确性。
链重组的本质是回滚旧主链（至共同祖先）→ 验证分叉链 → 应用新主链的三步操作，
需严格保证每一步的原子性和可追溯性。
*/
func (b *BlockChain) reorganizeChain(newTipBlock *core.Block) error {
	newChainWork := newTipBlock.GetChainWork()
	currentChainWork := b.bestChain.GetChainWork()
	if newChainWork.Cmp(currentChainWork) <= 0 {
		return fmt.Errorf("新链工作量不大于当前主链，无需重组")
	}
	// 2. 找到新链与当前主链的共同祖先
	commonAncestor := b.findCommonAncestor(newTipBlock)
	if commonAncestor == nil {
		return fmt.Errorf("未找到共同祖先，无法重组链")
	}
	ancestorHeight := commonAncestor.Height()
	ancestorHash := commonAncestor.Hash()
	log.Infof("链重组 - 共同祖先区块: %s (高度: %d)", ancestorHash, ancestorHeight)
	// 3. 收集需要回滚的旧主链区块（从当前高度到共同祖先）
	var blocksToUndo []*core.Block
	currentTip := b.bestChain
	for currentTip != nil && currentTip.Height() > ancestorHeight {
		blocksToUndo = append(blocksToUndo, currentTip)
		// 获取前一个区块
		prevHash := currentTip.MsgBlock().Header.PrevBlock
		prevBlock, err := b.GetBlockByHash(&prevHash)
		if err != nil {
			return fmt.Errorf("获取前序区块失败: %w", err)
		}
		currentTip = prevBlock
	}
	// 4. 收集需要应用的新链区块（从共同祖先到新尖端）
	var blocksToApply []*core.Block
	tempBlock := newTipBlock
	for tempBlock != nil && tempBlock.Height() > ancestorHeight {
		blocksToApply = append(blocksToApply, tempBlock)
		// 获取前一个区块
		prevHash := tempBlock.MsgBlock().Header.PrevBlock
		prevBlock, err := b.GetBlockByHash(&prevHash)
		if err != nil {
			return fmt.Errorf("获取新链前序区块失败: %w", err)
		}
		tempBlock = prevBlock
	}
	// 反转新链区块顺序，使其从共同祖先之后的第一个区块开始
	for i, j := 0, len(blocksToApply)-1; i < j; i, j = i+1, j-1 {
		blocksToApply[i], blocksToApply[j] = blocksToApply[j], blocksToApply[i]
	}
	log.Infof("链重组 - 准备回滚 %d 个区块，应用 %d 个新区块", len(blocksToUndo), len(blocksToApply))
	// 5. 验证新链区块的连续性和有效性
	if err := b.verifyNewChain(commonAncestor, blocksToApply); err != nil {
		return fmt.Errorf("新链验证失败: %w", err)
	}
	// 6. 准备回滚信息（记录所有将被回滚的UTXO变更）
	var undoData []struct {
		block       *core.Block
		spentTxOuts []SpentTxOut
	}
	for _, block := range blocksToUndo {
		spentTxOuts, err := b.FetchSpentTxOuts(block)
		if err != nil {
			return fmt.Errorf("获取区块 %s 的花费信息失败: %w", block.Hash(), err)
		}
		undoData = append(undoData, struct {
			block       *core.Block
			spentTxOuts []SpentTxOut
		}{block, spentTxOuts})
	}
	log.Infof("获取Undo")
	// 7. 执行链重组（使用数据库事务确保原子性）
	err := b.db.Update(func(batch db.IndexedBatch) error {
		log.Infof("准备重组")

		// 7.1 回滚旧链区块
		for i, undo := range undoData {
			log.Infof("回滚区块 %d/%d: %s (高度: %d)",
				i+1, len(undoData), undo.block.Hash(), undo.block.Height())

			// 从UTXO集中移除新区块创建的UTXO，恢复被花费的UTXO
			if err := b.disconnectBlock(undo.block, undo.spentTxOuts, batch); err != nil {
				return fmt.Errorf("回滚区块 %s 失败: %w", undo.block.Hash(), err)
			}

			// 更新索引
			if err := b.IndexManager.DisconnectBlock(undo.block, undo.spentTxOuts); err != nil {
				return fmt.Errorf("断开区块索引 %s 失败: %w", undo.block.Hash(), err)
			}
			//移除区块对UTXO集的影响

			b.sendNotification(NTBlockDisconnected, undo)
		}

		// 7.2 应用新链区块
		for i, block := range blocksToApply {
			log.Infof("应用新区块 %d/%d: %s (高度: %d)",
				i+1, len(blocksToApply), block.Hash(), block.Height())

			// 验证区块上下文（确保与前序区块正确连接）
			if err := b.checkBlockContext(block, 0); err != nil {
				return fmt.Errorf("区块 %s 上下文验证失败: %w", block.Hash(), err)
			}

			// 获取区块中所有被花费的UTXO信息
			spentTxOuts, err := b.FetchSpentTxOuts(block)
			if err != nil {
				return fmt.Errorf("获取区块 %s 花费信息失败: %w", block.Hash(), err)
			}

			// 将区块应用到UTXO集
			if err := b.applyBlock(block, spentTxOuts, batch); err != nil {
				return fmt.Errorf("应用区块 %s 失败: %w", block.Hash(), err)
			}

			// 更新索引
			if err := b.IndexManager.ConnectBlock(block, spentTxOuts); err != nil {
				return fmt.Errorf("连接区块索引 %s 失败: %w", block.Hash(), err)
			}
			b.sendNotification(NTBlockConnected, block)
		}

		// 7.3 更新主链元数据（最新区块哈希、高度、工作量等）
		if err := b.updateMainChainMetadata(newTipBlock, batch); err != nil {
			return fmt.Errorf("更新主链元数据失败: %w", err)
		}

		return nil
	})
	if err != nil {
		log.Errorf("链重组事务失败: %v", err)
		return err
	}
	// 8. 更新内存中的最佳链引用
	b.bestChain = newTipBlock

	// 9. 更新最佳状态快照
	newBestState := &BestState{
		Hash:        *newTipBlock.Hash(),
		Height:      newTipBlock.Height(),
		Bits:        newTipBlock.BlockHeader().Bits,
		ChainWork:   *newChainWork,
		BlockSize:   newTipBlock.Size(),
		BlockWeight: newTipBlock.Weight(),
		NumTxns:     uint64(len(newTipBlock.Transactions())),
		TotalTxns:   b.stateSnapshot.TotalTxns + uint64(len(blocksToApply)) - uint64(len(blocksToUndo)),
		MedianTime:  time.Unix(b.CalcPastMedianTime(newTipBlock.BlockHeader()), 0),
	}
	b.stateSnapshot = newBestState
	currentBest.Store(newBestState)

	log.Infof("链重组完成 - 新主链尖端: %s (高度: %d, 工作量: %v)",
		newTipBlock.Hash(), newTipBlock.Height(), newChainWork)

	return nil
}

/*
找到共同祖先
*/
func (b *BlockChain) findCommonAncestor(newTipBlock *core.Block) *core.Block {
	// 如果新尖端区块就是主链区块，直接返回自身
	if b.isMainChainBlock(newTipBlock.Hash()) {
		return newTipBlock
	}
	// 创建当前主链区块哈希的映射，用于快速查找
	mainChainHashes := make(map[chainhash.Hash]bool)
	currentBlock := b.bestChain
	for currentBlock != nil {
		hash := currentBlock.Hash()
		mainChainHashes[*hash] = true
		// 到达创世区块时停止
		if currentBlock.Height() == 0 {
			break
		}
		// 获取前一个区块
		prevHash := currentBlock.MsgBlock().Header.PrevBlock
		prevBlock, err := b.GetBlockByHash(&prevHash)
		if err != nil {
			log.Errorf("获取主链区块失败: %v", err)
			break
		}
		currentBlock = prevBlock
	}
	// 从新链尖端向上查找，找到第一个在主链中的区块
	currentNewBlock := newTipBlock
	for currentNewBlock != nil {
		hash := currentNewBlock.Hash()
		if mainChainHashes[*hash] {
			return currentNewBlock
		}
		// 到达创世区块时停止
		if currentNewBlock.Height() == 0 {
			break
		}
		// 获取前一个区块
		prevHash := currentNewBlock.MsgBlock().Header.PrevBlock
		prevBlock, err := b.GetBlockByHash(&prevHash)
		if err != nil {
			log.Errorf("获取新链区块失败: %v", err)
			break
		}
		currentNewBlock = prevBlock
	}
	// 如果没有找到共同祖先，返回创世区块
	genesisHash, err := b.MainChainGetHashByHeightInit32(0)
	if err != nil {
		log.Errorf("获取创世区块失败: %v", err)
		return nil
	}
	genesisBlock, err := b.GetBlockByHash(genesisHash)
	if err != nil {
		log.Errorf("获取创世区块失败: %v", err)
		return nil
	}
	return genesisBlock
}

// 使用二分查找优化的共同祖先查找方法
func (b *BlockChain) findCommonAncestorBack(newTipBlock *core.Block) *core.Block {
	// 如果新尖端区块就是主链区块，直接返回自身
	if b.isMainChainBlock(newTipBlock.Hash()) {
		return newTipBlock
	}

	// 获取主链和新链的高度
	mainChainHeight := b.bestChain.Height()
	newChainHeight := newTipBlock.Height()

	// 找到两条链中较低的高度作为起始点
	startHeight := mainChainHeight
	if newChainHeight < startHeight {
		startHeight = newChainHeight
	}

	// 二分查找共同祖先
	low := int32(0)
	high := startHeight
	var commonAncestor *core.Block

	for low <= high {
		mid := (low + high) / 2

		// 获取主链在mid高度的区块哈希
		mainChainHash, err := b.GetMainBlockHashByHeight(mid)
		if err != nil {
			log.Errorf("获取主链高度%d的哈希失败: %v", mid, err)
			high = mid - 1
			continue
		}

		// 检查新链在mid高度是否存在该哈希的区块
		newChainBlock, err := b.GetBlockByHash(&mainChainHash)
		if err != nil {
			// 新链中不存在该区块，需要在更低的高度查找
			high = mid - 1
			continue
		}

		// 验证该区块是否在新链上
		if b.isBlockInChain(newChainBlock, newTipBlock) {
			// 找到一个共同区块，尝试在更高的高度查找
			commonAncestor = newChainBlock
			low = mid + 1
		} else {
			// 不在新链上，需要在更低的高度查找
			high = mid - 1
		}
	}

	// 如果没有找到共同祖先，返回创世区块
	if commonAncestor == nil {
		genesisHash, err := b.MainChainGetHashByHeightInit32(0)
		if err != nil {
			log.Errorf("获取创世区块失败: %v", err)
			return nil
		}
		genesisBlock, err := b.GetBlockByHash(genesisHash)
		if err != nil {
			log.Errorf("获取创世区块失败: %v", err)
			return nil
		}
		return genesisBlock
	}
	return commonAncestor
}

// 辅助函数：检查区块是否在指定链上
func (b *BlockChain) isBlockInChain(targetBlock, chainTip *core.Block) bool {
	// 如果目标区块高度大于链尖端高度，不可能在链上
	if targetBlock.Height() > chainTip.Height() {
		return false
	}

	// 如果目标区块就是链尖端，直接返回true
	if targetBlock.Hash().IsEqual(chainTip.Hash()) {
		return true
	}

	// 从链尖端向上查找，直到找到目标区块或超过目标区块高度
	currentBlock := chainTip
	for currentBlock.Height() > targetBlock.Height() {
		prevHash := currentBlock.MsgBlock().Header.PrevBlock
		prevBlock, err := b.GetBlockByHash(&prevHash)
		if err != nil {
			log.Errorf("获取区块失败: %v", err)
			return false
		}
		currentBlock = prevBlock

		// 检查是否找到目标区块
		if currentBlock.Hash().IsEqual(targetBlock.Hash()) {
			return true
		}
	}

	// 到达目标区块高度但未找到
	return currentBlock.Hash().IsEqual(targetBlock.Hash())
}

// 验证新链的连续性和有效性
func (b *BlockChain) verifyNewChain(commonAncestor *core.Block, newBlocks []*core.Block) error {
	if len(newBlocks) == 0 {
		return nil
	}

	// 验证第一个新块是否连接到共同祖先
	firstNewBlock := newBlocks[0]
	prevHash := firstNewBlock.MsgBlock().Header.PrevBlock
	if !prevHash.IsEqual(commonAncestor.Hash()) {
		return fmt.Errorf("新链第一个区块未连接到共同祖先: %s -> %s",
			prevHash.String(), commonAncestor.Hash().String())
	}

	// 验证新块之间的连续性
	for i := 1; i < len(newBlocks); i++ {
		currentBlock := newBlocks[i]
		prevBlock := newBlocks[i-1]
		currentPrevHash := currentBlock.MsgBlock().Header.PrevBlock
		if !currentPrevHash.IsEqual(prevBlock.Hash()) {
			return fmt.Errorf("新链区块不连续: %s -> %s",
				currentPrevHash.String(), prevBlock.Hash().String())
		}
	}

	// 验证每个新块的工作量是否正确累积
	expectedWork := new(big.Int).Set(commonAncestor.GetChainWork())
	for _, block := range newBlocks {
		blockWork := CalculateBlockWork(block.BlockHeader().Bits)
		expectedWork.Add(expectedWork, blockWork)

		if block.GetChainWork().Cmp(expectedWork) != 0 {
			return fmt.Errorf("区块 %s 工作量计算错误: 预期 %v, 实际 %v",
				block.Hash(), expectedWork, block.GetChainWork())
		}
	}
	log.Infof("新链验证完成")
	return nil
}

// disconnectBlock 从主链断开区块，恢复UTXO状态
func (b *BlockChain) disconnectBlock(block *core.Block, spentTxOuts []SpentTxOut, batch db.IndexedBatch) error {
	// 1. 准备UTXO视图
	utxoView := NewUtxoViewpoint()

	// 2. 恢复被该区块花费的UTXO
	txns := block.Transactions()
	outPointIndex := 0

	for _, tx := range txns {
		// 跳过coinbase交易，它没有输入
		if IsCoinBase(tx) {
			continue
		}

		msgTx := tx.MsgTx()
		for _, txIn := range msgTx.TxIn {
			if outPointIndex >= len(spentTxOuts) {
				return fmt.Errorf("区块 %s 花费信息不完整", block.Hash())
			}

			spentTxOut := spentTxOuts[outPointIndex]
			outPoint := txIn.PreviousOutPoint

			// 初始化标志位
			var flags txoFlags

			// 设置coinbase标志
			if spentTxOut.IsCoinBase {
				flags |= tfCoinBase
			}

			// 标记为已修改
			flags |= tfModified

			// 创建未花费的UTXO条目（不设置tfSpent标志）
			entry := &UtxoEntry{
				amount:      spentTxOut.Amount,
				pkScript:    spentTxOut.PkScript,
				blockHeight: spentTxOut.Height,
				packedFlags: flags,
			}

			// 直接操作entries map添加条目（替代不存在的AddEntry方法）
			utxoView.Entries()[outPoint] = entry
			outPointIndex++
		}
	}

	// 3. 移除该区块创建的UTXO
	for _, tx := range txns {
		msgTx := tx.MsgTx()
		txHash := *tx.Hash()

		for txOutIdx, txOut := range msgTx.TxOut {
			outPoint := core.OutPoint{Hash: txHash, Index: uint32(txOutIdx)}
			utxoKey := b.UTXOKey(txHash, uint32(txOutIdx))

			// 从数据库中删除该UTXO
			if err := batch.Delete(utxoKey); err != nil {
				return fmt.Errorf("删除UTXO失败: %w", err)
			}

			// 初始化标志位
			var flags txoFlags

			// 标记为已花费
			flags |= tfSpent

			// 标记为已修改
			flags |= tfModified

			// 设置coinbase标志（如果是coinbase交易）
			if IsCoinBase(tx) {
				flags |= tfCoinBase
			}

			// 创建标记为已花费的UTXO条目
			entry := &UtxoEntry{
				amount:      txOut.Value,
				pkScript:    txOut.PkScript,
				blockHeight: block.Height(),
				packedFlags: flags,
			}

			// 直接操作entries map添加条目（替代不存在的AddEntry方法）
			utxoView.Entries()[outPoint] = entry
		}
	}

	// 4. 提交UTXO视图变更
	utxoView.commit()
	return nil
}

// 将区块应用到主链，更新UTXO状态
func (b *BlockChain) applyBlock(block *core.Block, spentTxOuts []SpentTxOut, batch db.IndexedBatch) error {
	// 1. 准备UTXO视图
	utxoView := NewUtxoViewpoint()
	if err := utxoView.fetchInputUtxos(b.utxoCache, block); err != nil {
		return fmt.Errorf("加载UTXO失败：%w", err)
	}

	blockHeight := block.Height()
	transactions := block.Transactions()

	// 2. 处理交易输入（消耗UTXO）
	outPointIndex := 0
	for _, tx := range transactions {
		msgTx := tx.MsgTx()
		isCoinBase := IsCoinBase(tx)

		if !isCoinBase {
			for _, txIn := range msgTx.TxIn {
				if outPointIndex >= len(spentTxOuts) {
					return fmt.Errorf("区块 %s 花费信息不完整", block.Hash())
				}

				outPoint := txIn.PreviousOutPoint
				utxoEntry := utxoView.LookupEntry(outPoint)
				if utxoEntry == nil || utxoEntry.IsSpent() {
					return fmt.Errorf("交易 %s 引用的UTXO不存在或已花费", tx.Hash().String())
				}

				utxoEntry.Spend()
				outPointIndex++
			}
		}

		// 3. 处理交易输出（创建新UTXO）
		utxoView.AddTxOuts(tx, blockHeight)
	}

	// 4. 持久化UTXO变更
	for outPoint, entry := range utxoView.Entries() {
		if !entry.isModified() {
			continue
		}

		utxoKey := b.UTXOKey(outPoint.Hash, outPoint.Index)
		if entry.IsSpent() {
			// 删除已花费的UTXO
			if err := batch.Delete(utxoKey); err != nil {
				return fmt.Errorf("删除UTXO失败: %w", err)
			}
		} else {
			// 保存新创建的UTXO
			protoUtxo, err := entry.ToProto()
			if err != nil {
				return err
			}

			utxoBytes, err := proto.Marshal(protoUtxo)
			if err != nil {
				return fmt.Errorf("序列化UTXO失败: %w", err)
			}

			if err := batch.Put(utxoKey, utxoBytes); err != nil {
				return fmt.Errorf("保存UTXO失败: %w", err)
			}
		}
	}

	// 5. 提交UTXO视图
	utxoView.commit()
	return nil
}

// 是否主链区块 通过区块高度查询该高度主链对应的hash 如果一致就是主链区块 如果不一致就不是主链区块
// isMainChainBlock 判断给定哈希的区块是否为当前主链区块
// 逻辑：查询该区块高度对应的主链哈希，与输入哈希一致则为核心区块
func (b *BlockChain) isMainChainBlock(hash *chainhash.Hash) bool {
	// 1. 先从区块哈希查询其高度（需实现从哈希查高度的数据库方法）
	blockHeight, err := b.GetBlockHeightByHash(hash)
	if err != nil {
		log.Errorf("查询区块高度失败 (hash: %s): %v", hash, err)
		return false
	}

	// 2. 查询该高度对应的主链区块哈希
	mainChainHash, err := b.GetMainBlockHashByHeight(blockHeight)
	if err != nil {
		log.Errorf("查询主链高度%d的哈希失败: %v", blockHeight, err)
		return false
	}
	// 3. 对比两个哈希是否一致
	return mainChainHash.IsEqual(hash)
}

// updateMainChainMetadata 更新主链元数据（最新区块哈希、高度、工作量等）
func (b *BlockChain) updateMainChainMetadata(newTip *core.Block, batch db.IndexedBatch) error {
	// 保存最新区块哈希
	if err := batch.Put(db.MainStatus.Key([]byte(db.MainLatestHash)), newTip.Hash()[:]); err != nil {
		return fmt.Errorf("保存主链尖端哈希失败: %w", err)
	}

	// 保存最新区块高度
	heightBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(heightBytes, uint32(newTip.Height()))
	if err := batch.Put(db.MainStatus.Key([]byte(db.MainLatestHeight)), heightBytes); err != nil {
		return fmt.Errorf("保存主链尖端高度失败: %w", err)
	}

	// 保存最新链工作量
	workBytes := newTip.GetChainWork().Bytes()
	if err := batch.Put(db.MainStatus.Key([]byte(db.MainLatestWork)), workBytes); err != nil {
		return fmt.Errorf("保存主链工作量失败: %w", err)
	}

	// 更新高度到哈希的映射
	hashHeightKey := db.HeightToBlockBucket.Int32Key(newTip.Height())
	if err := batch.Put(hashHeightKey, newTip.Hash()[:]); err != nil {
		return fmt.Errorf("更新高度-哈希映射失败: %w", err)
	}
	return nil
}

// UTXO 集更新：消耗旧 UTXO，创建新 UTXO
// 消耗旧 UTXO：区块中所有交易的输入引用的 UTXO 会被标记为 “已花费”（从 UTXO 集中移除）。
// 例如：交易 A 的输入引用了区块 N-1 中交易 B 的第 0 个输出（某 UTXO），则该 UTXO 会被从 UTXO 集中删除，不再可用。
// 创建新 UTXO：区块中所有交易的输出（TxOut）会被作为新的 UTXO 添加到 UTXO 集中。
// 这些新 UTXO 包含金额和锁定脚本（通常是接收地址的公钥哈希），未来的交易可通过引用它们作为输入来花费。
// 发起一笔成功的交易
//
// 1、未被打包前
// 引用的UTXO 被标记已经花费
// 新增的UTXO被标记为未确认
//
// 2、打包到区块后
// 引用的UTXO 被标记已经花费 并从数据库删除
// 新增的UTXO被标记为已经确认 并新增到数据库
// ApplyToMainChain 将区块应用到主链，仅处理UTXO核心逻辑，索引操作完全委托给IndexManager
func (b *BlockChain) ApplyToMainChain(block *core.Block) error {
	log.Infof("应用区块到主链 (哈希: %s, 高度: %d)", block.Hash(), block.Height())
	hash := block.Hash()
	work := block.GetChainWork()
	blockHeight := block.Height()
	// 1. 参数合法性校验（避免无效输入导致的后续存储错误）
	if hash == nil {
		return fmt.Errorf("invalid parameter: hash is nil")
	}
	if work == nil {
		return fmt.Errorf("invalid parameter: work is nil")
	}
	// 高度通常非负（创世区块高度为0），可根据业务需求补充校验
	if blockHeight < 0 {
		return fmt.Errorf("invalid parameter: height is negative (%d)", blockHeight)
	}

	// 准备UTXO视图，加载区块中所有交易输入引用的UTXO
	utxoView := NewUtxoViewpoint()
	utxoView.SetBestHash(b.bestChain.BlockHash)
	if err := utxoView.fetchInputUtxos(b.utxoCache, block); err != nil {
		return fmt.Errorf("加载UTXO失败: %w", err)
	}

	var spentTxOuts []SpentTxOut // 记录被花费的UTXO信息（用于回滚和索引）
	// 处理区块中所有交易，更新UTXO状态
	transactions := block.Transactions()
	for _, tx := range transactions {
		msgTx := tx.MsgTx()
		isCoinBase := IsCoinBase(tx)
		// 处理非coinbase交易的输入（消耗UTXO）
		if !isCoinBase {
			for _, txIn := range msgTx.TxIn {
				outPoint := txIn.PreviousOutPoint
				utxoEntry := utxoView.LookupEntry(outPoint)
				// 验证UTXO存在且未被花费
				if utxoEntry == nil || utxoEntry.IsSpent() {
					return fmt.Errorf("交易 %s 引用无效UTXO: %v", tx.Hash(), outPoint)
				}
				// 记录被花费的UTXO信息（供索引管理器使用）
				spentTxOuts = append(spentTxOuts, SpentTxOut{
					Amount:     utxoEntry.Amount(),
					PkScript:   utxoEntry.PkScript(),
					Height:     utxoEntry.BlockHeight(),
					IsCoinBase: utxoEntry.IsCoinBase(),
				})
				// 标记UTXO为已花费
				//utxoEntry.Spend()
			}
		}
		// 处理所有交易的输出（创建新UTXO）
		utxoView.AddTxOuts(tx, blockHeight)
	}

	if blockHeight != 0 {
		if err := b.checkConnectBlock(block, utxoView, &spentTxOuts); err != nil {
			log.Infof("检查连接的区块失败")
			return fmt.Errorf("检查连接的区块失败: %w", err)
		}
	}

	// 原子化执行UTXO更新和索引操作
	return b.db.Update(func(batch db.IndexedBatch) error {
		// 1. 处理UTXO核心数据变更（仅维护UTXO集本身）
		for outPoint, entry := range utxoView.Entries() {
			if !entry.isModified() {
				continue // 跳过未变更的UTXO
			}
			utxoKey := b.UTXOKey(outPoint.Hash, outPoint.Index)
			if entry.IsSpent() {
				// 删除已花费的UTXO
				if err := batch.Delete(utxoKey); err != nil {
					return fmt.Errorf("删除UTXO失败 (outpoint: %v): %w", outPoint, err)
				}
				//utxoCache缓存变更为已经花费
				// 更新缓存：标记为已花费
				if err := b.utxoCache.MarkAsSpent(outPoint); err != nil {
					log.Warnf("缓存中标记UTXO为已花费失败: %v, 错误: %v", outPoint, err)
					// 这里选择警告而非返回错误，因为数据库操作已成功，缓存可后续同步
				}
			} else {
				// 保存新创建的UTXO
				protoUtxo, err := entry.ToProto()
				if err != nil {
					return fmt.Errorf("UTXO序列化失败: %w", err)
				}
				utxoBytes, err := proto.Marshal(protoUtxo)
				if err != nil {
					return fmt.Errorf("UTXO proto序列化失败: %w", err)
				}
				if err := batch.Put(utxoKey, utxoBytes); err != nil {
					return fmt.Errorf("保存UTXO失败 (outpoint: %v): %w", outPoint, err)
				}
				//utxoCache缓存变更 新增UTXO到缓存
				// 更新缓存：新增UTXO
				txOut := &core.TxOut{
					Value:    entry.amount,
					PkScript: entry.pkScript,
				}
				if err := b.utxoCache.AddUTXO(outPoint, txOut, entry.IsCoinBase(), blockHeight); err != nil {
					log.Warnf("缓存中添加UTXO失败: %v, 错误: %v", outPoint, err)
					// 同样选择警告而非返回错误
				}

			}
		}
		// 2. 完全委托索引管理器处理所有索引操作
		if err := b.IndexManager.ConnectBlock(block, spentTxOuts); err != nil {
			return fmt.Errorf("索引管理器处理失败: %w", err)
		}

		utxoView.commit()
		return nil
	})
}

func ValidateWitnessCommitment(blk *core.Block) error {
	// If the block doesn't have any transactions at all, then we won't be
	// able to extract a commitment from the non-existent coinbase
	// transaction. So we exit early here.
	if len(blk.Transactions()) == 0 {
		str := "cannot validate witness commitment of block without " +
			"transactions"
		return ruleError(ErrNoTransactions, str)
	}

	coinbaseTx := blk.Transactions()[0]
	if len(coinbaseTx.MsgTx().TxIn) == 0 {
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	witnessCommitment, witnessFound := ExtractWitnessCommitment(coinbaseTx)

	// If we can't find a witness commitment in any of the coinbase's
	// outputs, then the block MUST NOT contain any transactions with
	// witness data.
	if !witnessFound {
		for _, tx := range blk.Transactions() {
			msgTx := tx.MsgTx()
			if msgTx.HasWitness() {
				str := fmt.Sprintf("block contains transaction with witness" +
					" data, yet no witness commitment present")
				return ruleError(ErrUnexpectedWitness, str)
			}
		}
		return nil
	}

	// At this point the block contains a witness commitment, so the
	// coinbase transaction MUST have exactly one witness element within
	// its witness data and that element must be exactly
	// CoinbaseWitnessDataLen bytes.
	coinbaseWitness := coinbaseTx.MsgTx().TxIn[0].Witness
	if len(coinbaseWitness) != 1 {
		str := fmt.Sprintf("the coinbase transaction has %d items in "+
			"its witness stack when only one is allowed",
			len(coinbaseWitness))
		return ruleError(ErrInvalidWitnessCommitment, str)
	}
	witnessNonce := coinbaseWitness[0]
	if len(witnessNonce) != CoinbaseWitnessDataLen {
		str := fmt.Sprintf("the coinbase transaction witness nonce "+
			"has %d bytes when it must be %d bytes",
			len(witnessNonce), CoinbaseWitnessDataLen)
		return ruleError(ErrInvalidWitnessCommitment, str)
	}

	// Finally, with the preliminary checks out of the way, we can check if
	// the extracted witnessCommitment is equal to:
	// SHA256(witnessMerkleRoot || witnessNonce). Where witnessNonce is the
	// coinbase transaction's only witness item.
	witnessMerkleRoot := CalcMerkleRoot(blk.Transactions(), true)

	var witnessPreimage [chainhash.HashSize * 2]byte
	copy(witnessPreimage[:], witnessMerkleRoot[:])
	copy(witnessPreimage[chainhash.HashSize:], witnessNonce)

	computedCommitment := chainhash.DoubleHashB(witnessPreimage[:])
	if !bytes.Equal(computedCommitment, witnessCommitment) {
		str := fmt.Sprintf("witness commitment does not match: "+
			"computed %v, coinbase includes %v", computedCommitment,
			witnessCommitment)
		return ruleError(ErrWitnessCommitmentMismatch, str)
	}

	return nil
}

func ExtractWitnessCommitment(tx *core.Tx) ([]byte, bool) {
	// The witness commitment *must* be located within one of the coinbase
	// transaction's outputs.
	if !IsCoinBase(tx) {
		return nil, false
	}

	msgTx := tx.MsgTx()
	for i := len(msgTx.TxOut) - 1; i >= 0; i-- {
		// The public key script that contains the witness commitment
		// must shared a prefix with the WitnessMagicBytes, and be at
		// least 38 bytes.
		pkScript := msgTx.TxOut[i].PkScript
		if len(pkScript) >= CoinbaseWitnessPkScriptLength &&
			bytes.HasPrefix(pkScript, WitnessMagicBytes) {

			// The witness commitment itself is a 32-byte hash
			// directly after the WitnessMagicBytes. The remaining
			// bytes beyond the 38th byte currently have no consensus
			// meaning.
			start := len(WitnessMagicBytes)
			end := CoinbaseWitnessPkScriptLength
			return msgTx.TxOut[i].PkScript[start:end], true
		}
	}

	return nil, false
}

// UTXOKey 构造UTXO的数据库存储键
// 键结构：[UTXOBucket(1字节)] + [交易哈希(32字节)] + [输出索引(4字节，小端序)]
// 参数：
//   - txHash: 交易哈希（UTXO所属的交易）
//   - index: 交易输出索引（UTXO在交易中的位置）
//
// 返回值：
//
//	完整的UTXO数据库键（字节切片）
func (b *BlockChain) UTXOKey(txHash chainhash.Hash, index uint32) []byte {
	outPointBytes := make([]byte, chainhash.HashSize+4)
	copy(outPointBytes[:chainhash.HashSize], txHash[:])
	binary.LittleEndian.PutUint32(outPointBytes[chainhash.HashSize:], index)
	utxoKey := db.UTXOBucket.Key(outPointBytes)
	return utxoKey
}

func (b *BlockChain) CalcSequenceLock(tx *core.Tx, utxoView *UtxoViewpoint, mempool bool) (*SequenceLock, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	return b.calcSequenceLock(b.bestChain, tx, utxoView, mempool)
}

func (b *BlockChain) calcSequenceLock(node *core.Block, tx *core.Tx, utxoView *UtxoViewpoint, mempool bool) (*SequenceLock, error) {
	sequenceLock := &SequenceLock{Seconds: -1, BlockHeight: -1}

	return sequenceLock, nil
}

func (b *BlockChain) GetBestChain() *core.Block {
	return b.bestChain
}

func serializeAmount(amount int64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, uint64(amount)) // 金额非负，转uint64安全
	return buf
}

// 反序列化8字节为int64金额
func deserializeAmount(buf []byte) (int64, error) {
	if len(buf) != 8 {
		return 0, fmt.Errorf("invalid amount bytes length: %d", len(buf))
	}
	return int64(binary.LittleEndian.Uint64(buf)), nil
}

// isCurrent 判断当前区块链是否已同步到最新状态
// 当本地最新区块的中位时间与节点调整后时间的差值在合理阈值内时，认为是同步完成的
func (b *BlockChain) isCurrent() bool {
	// 加读锁保护状态快照的并发访问
	b.stateLock.RLock()
	defer b.stateLock.RUnlock()

	// 若没有状态快照，说明链未初始化，肯定不是当前状态
	if b.stateSnapshot == nil {
		return false
	}

	// 获取最新区块的中位时间（来自最佳状态快照）
	latestBlockTime := b.stateSnapshot.MedianTime

	// 获取节点调整后的当前时间（使用链的时间源，避免本地时间偏差）
	currentTime := b.timeSource.AdjustedTime()

	// 计算时间差（当前时间 - 最新区块时间）
	timeDifference := currentTime.Sub(latestBlockTime)

	// 定义同步阈值：超过24小时则认为未同步（可根据链参数调整）
	// 对于快速确认的链可缩短，对于慢链可延长
	maxAllowedDiff := 24 * time.Hour

	// 若时间差在阈值内，认为区块链处于当前状态
	return timeDifference <= maxAllowedDiff
}

//	提取区块中所有被花费的交易输出信息
//
// 这些信息来自于区块中所有非coinbase交易的输入所引用的前置UTXO
// FetchSpentTxOuts 提取区块中所有被花费的交易输出信息
// 这些信息来自于区块中所有非coinbase交易的输入所引用的前置UTXO
func (b *BlockChain) FetchSpentTxOuts(block *core.Block) ([]SpentTxOut, error) {
	var spentTxOuts []SpentTxOut
	transactions := block.Transactions()
	if len(transactions) == 0 {
		return spentTxOuts, nil // 空区块无花费输出
	}

	// 收集所有需要查询的前置输出点
	var neededOutPoints []core.OutPoint
	for i, tx := range transactions {
		// 跳过coinbase交易（无输入）
		if i == 0 && IsCoinBase(tx) {
			continue
		}

		// 收集非coinbase交易的所有输入引用
		for _, txIn := range tx.MsgTx().TxIn {
			neededOutPoints = append(neededOutPoints, txIn.PreviousOutPoint)
		}
	}

	// 批量查询UTXO缓存获取所有前置输出信息
	entries, err := b.utxoCache.fetchEntries(neededOutPoints)
	if err != nil {
		return nil, fmt.Errorf("获取UTXO条目失败: %w", err)
	}

	// 验证并收集所有被花费的UTXO信息
	for i, outPoint := range neededOutPoints {
		entry := entries[i]
		if entry == nil || entry.IsSpent() {
			return nil, fmt.Errorf("引用了不存在或已花费的UTXO: %v", outPoint)
		}

		// 构造被花费的UTXO信息
		spentTxOuts = append(spentTxOuts, SpentTxOut{
			Amount:     entry.Amount(),
			PkScript:   entry.PkScript(),
			Height:     entry.BlockHeight(),
			IsCoinBase: entry.IsCoinBase(),
		})
	}

	return spentTxOuts, nil
}

func (b *BlockChain) GetAddressAllUTXOByCache(address string) ([]*UtxoEntry, error) {
	// 1. 解析地址
	addr, err := b.parseAddress(address)
	if err != nil {
		return nil, fmt.Errorf("解析地址失败: %w", err)
	}
	// 2. 获取地址对应的键
	addrKey, err := b.utxoKeyFromAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("无法转换地址为索引键: %w", err)
	}
	// 3. 构建地址前缀，用于范围查询
	prefix := db.AddrToUtxo.Key(addrKey[:])

	// 4. 创建数据库迭代器
	iter, err := b.db.NewIterator(prefix, true)
	if err != nil {
		return nil, fmt.Errorf("创建迭代器失败: %w", err)
	}
	defer iter.Close()
	var outPoints []core.OutPoint
	// 5. 收集所有UTXO信息
	var utxoEntries []*UtxoEntry
	// 6. 加锁保护UTXO缓存/数据库读取
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	// 7. 遍历所有匹配前缀的键值对
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		// 验证当前键是否仍然匹配前缀
		if !bytes.HasPrefix(key, prefix) {
			break
		}
		// 从键中解析出交易哈希和输出索引
		data := key[len(prefix):]
		if len(data) < chainhash.HashSize+4 {
			continue
		}
		var txHash chainhash.Hash
		copy(txHash[:], data[:chainhash.HashSize])
		outIndex := binary.BigEndian.Uint32(data[chainhash.HashSize : chainhash.HashSize+4])

		// 根据交易哈希和输出索引获取完整的UTXO信息
		utxo, err := b.getUTXOByOutPoint(&txHash, outIndex)
		if err != nil {
			// 如果UTXO已被花费，跳过
			if errors.Is(err, db.ErrKeyNotFound) {
				continue
			}
			log.Infof("UTXO已经被花费未找到")
			return nil, fmt.Errorf("获取UTXO信息失败: %w", err)
		}

		outPoint := core.OutPoint{
			Hash:  txHash,
			Index: outIndex,
		}
		outPoints = append(outPoints, outPoint)
		utxoEntries = append(utxoEntries, utxo)
	}

	return utxoEntries, nil
}

func (b *BlockChain) LatestCheckpoint() *core.Checkpoint {
	if !b.HasCheckpoints() {
		return nil
	}
	return &b.checkpoints[len(b.checkpoints)-1]
}

func (b *BlockChain) HasCheckpoints() bool {
	return len(b.checkpoints) > 0
}

type IndexManager interface {
	Init(*BlockChain, <-chan struct{}) error

	ConnectBlock(*core.Block, []SpentTxOut) error

	DisconnectBlock(*core.Block, []SpentTxOut) error
}

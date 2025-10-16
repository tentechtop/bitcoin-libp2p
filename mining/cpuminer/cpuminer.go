package cpuminer

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	wire2 "bitcoin/core"
	"bitcoin/mining"
	"bitcoin/utils"
	"bitcoin/wire"
	"math/big"

	"math/rand"
	"runtime"
	"sync"
	"time"
)

// 共享挖矿结果，所有 worker 只设置一次
type MiningResult struct {
	Found bool
	Nonce uint32
	Hash  chainhash.Hash
	Mu    sync.Mutex
}

type Config struct {
	ChainParams            *wire2.Params
	BlockTemplateGenerator *mining.BlkTmplGenerator
	MiningAddrs            []utils.Address
	ProcessBlock           func(*wire2.Block, blockchain.BehaviorFlags) (bool, error)
	ConnectedCount         func() int32
	IsCurrent              func() bool
}

var (
	defaultNumWorkers = uint32(runtime.NumCPU())
)

// speedMonitor：算力监控协程（归属于 wg 等待组）；
// miningWorkerController：挖矿控制器（归属于 wg 等待组）；
// miningTaskScheduler：任务调度器（归属于 workerWg 等待组）；
// solveBlock 内的 worker 协程（挖矿计算协程）和 资源清理 goroutine。
type CPUMiner struct {
	sync.Mutex
	g                 *mining.BlkTmplGenerator
	cfg               Config
	numWorkers        uint32
	started           bool
	discreteMining    bool
	submitBlockLock   sync.Mutex
	updateNumWorkers  chan struct{}
	queryHashesPerSec chan float64
	updateHashes      chan uint64

	wg               sync.WaitGroup
	workerWg         sync.WaitGroup
	speedMonitorQuit chan struct{}
	quit             chan struct{}
	CurrentTaskQuit  chan struct{} // 当前挖矿任务的终止信号（确保同一时间仅一个任务运行）
}

func New(cfg *Config) *CPUMiner {
	return &CPUMiner{
		g:                 cfg.BlockTemplateGenerator,
		cfg:               *cfg,
		numWorkers:        defaultNumWorkers,
		updateNumWorkers:  make(chan struct{}),
		queryHashesPerSec: make(chan float64),
		updateHashes:      make(chan uint64),
		started:           false,
	}
}

func (m *CPUMiner) speedMonitor() {
	log.Tracef("CPU miner speed monitor started")

	var hashesPerSec float64
	var totalHashes uint64
	ticker := time.NewTicker(time.Second * mining.HpsUpdateSecs)
	defer ticker.Stop()

out:
	for {
		select {
		// Periodic updates from the workers with how many hashes they
		// have performed.
		case numHashes := <-m.updateHashes:
			totalHashes += numHashes

		// Time to update the hashes per second.
		case <-ticker.C:
			curHashesPerSec := float64(totalHashes) / mining.HpsUpdateSecs
			if hashesPerSec == 0 {
				hashesPerSec = curHashesPerSec
			}
			hashesPerSec = (hashesPerSec + curHashesPerSec) / 2
			totalHashes = 0
			if hashesPerSec != 0 {
				log.Debugf("Hash speed: %6.0f kilohashes/s",
					hashesPerSec/1000)
			}

		// Request for the number of hashes per second.
		case m.queryHashesPerSec <- hashesPerSec:
			// Nothing to do.

		case <-m.speedMonitorQuit:
			break out
		}
	}

	m.wg.Done()
	log.Tracef("CPU miner speed monitor done")
}

func (m *CPUMiner) Start() {
	m.Lock()
	defer m.Unlock()

	if m.started || m.discreteMining {
		return
	}

	m.quit = make(chan struct{})
	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(1)

	go m.speedMonitor()
	m.miningWorkerController()

	m.started = true
	log.Infof("CPU miner started")
}

func (m *CPUMiner) miningWorkerController() {
	go m.miningTaskScheduler()
}

// miningTaskScheduler 单任务调度器：统一生成模板、启动/终止挖矿
func (m *CPUMiner) miningTaskScheduler() {
	defer m.workerWg.Done()
	log.Tracef("Mining task scheduler started")

	for {
		// 优先检查退出信号
		select {
		case <-m.quit:
			log.Tracef("Mining task scheduler stopped")
			return
		case <-m.CurrentTaskQuit:
			log.Tracef("Mining task scheduler stopped")
			return
		default:
		}

		// 1. 生成最新区块模板（加锁确保线程安全）
		m.submitBlockLock.Lock()
		bestSnap := m.g.BestSnapshot()
		curHeight := bestSnap.Height

		// 随机选择挖矿地址（仅一次/模板）
		rand.Seed(time.Now().UnixNano())
		payToAddr := m.cfg.MiningAddrs[rand.Intn(len(m.cfg.MiningAddrs))]

		// 基于最新快照和内存池创建模板（避免重复模板）
		template, err := m.g.NewBlockTemplate(payToAddr, curHeight)
		m.submitBlockLock.Unlock()

		if err != nil {
			log.Errorf("Failed to create block template: %v", err)
			time.Sleep(1 * time.Second) // 出错后重试
			continue
		}

		// 2. 初始化当前任务的终止信号（关闭上一个任务）
		m.Lock()
		if m.CurrentTaskQuit != nil {
			close(m.CurrentTaskQuit) // 终止旧任务
		}
		m.CurrentTaskQuit = make(chan struct{})
		//taskQuit := m.currentTaskQuit // 局部变量避免锁竞争

		m.Unlock()
		log.Infof("")
		log.Infof("正在挖矿 | Height: %d ", curHeight+1)

		combinedQuit := make(chan struct{})
		go func() {
			select {
			case <-m.quit:
				close(combinedQuit)
			case <-m.CurrentTaskQuit:
				close(combinedQuit)
			}
		}()

		// 3. 启动挖矿任务（阻塞至任务完成/终止）
		found := m.solveBlock(template.Block, curHeight+1, combinedQuit)

		// 4. 若找到有效区块，提交并短暂延迟（确保链更新）
		if found {
			block := wire2.NewBlock(template.Block)
			block.BlockHeight = curHeight + 1

			// 原有ChainWork计算逻辑（保留）
			bits := block.BlockHeader().Bits
			work := blockchain.CalculateBlockWork(bits)
			chainWork := blockchain.CalculateChainWork(bestSnap.ChainWork, bits)
			sum := new(big.Int).Add(work, chainWork)
			if err := block.SetChainWork(sum); err != nil {
				log.Errorf("Failed to set chain work: %v", err)
				continue
			}
			log.Infof("Current block work: %s", sum.String())

			m.submitBlock(block)
			time.Sleep(500 * time.Millisecond) // 等待链处理新块
		}
	}
}

func (m *CPUMiner) solveBlock(msgBlock *wire2.MsgBlock, blockHeight int32, taskQuit chan struct{}) bool {
	//   miningStartTime := time.Now()
	miningStartTimeUnix := time.Now().Unix()
	miningStartTime := time.Now()
	msgBlock.Header.Timestamp = miningStartTimeUnix

	// 定义超时阈值（根据你的链规则设置，如5分钟）
	timeoutThreshold := 10 * time.Minute

	enOffset, err := wire.RandomUint64()
	if err != nil {
		log.Errorf("Failed to generate extra nonce offset: %v", err)
		enOffset = 0
	}
	header := &msgBlock.Header
	currentBits := header.Bits                               // 确保这里是调整后的 6b00ffff
	targetDifficulty := blockchain.CompactToBig(currentBits) // 基于新 bits 计算目标

	lastGenerated := time.Now()
	lastTxUpdate := m.g.TxSource().LastUpdated()

	// 遍历ExtraNonce（仅单任务内循环，无多任务重复）
	for extraNonce := enOffset; extraNonce < mining.MaxExtraNonce; extraNonce++ {
		// 优先检查任务终止信号（区块过时/退出）
		select {
		case <-taskQuit:
			log.Tracef("SolveBlock terminated at extraNonce: %d", extraNonce)
			return false
		default:
		}

		// 更新区块的ExtraNonce（单任务内唯一更新）
		m.g.UpdateExtraNonce(msgBlock, blockHeight, extraNonce)

		// 内层worker数量（基于配置，合理利用多核）
		numWorkers := m.numWorkers
		if numWorkers == 0 {
			numWorkers = defaultNumWorkers
		}

		// 定义worker通信结构
		type workerResult struct {
			found bool
			nonce uint32
			hash  chainhash.Hash
		}
		resultChan := make(chan workerResult, numWorkers)
		workerStopChan := make(chan struct{}) // 控制当前ExtraNonce的worker
		hashCountChan := make(chan uint64, numWorkers)

		// 拆分Nonce范围（避免worker重复计算）
		step := mining.MaxNonce / numWorkers
		if step == 0 {
			step = 1
		}
		currentHeader := *header // 复制头，避免并发修改

		// 启动内层worker（并行计算Nonce，无重复）
		for workerIdx := uint32(0); workerIdx < numWorkers; workerIdx++ {
			startNonce := workerIdx * step
			endNonce := (workerIdx+1)*step - 1
			if workerIdx == numWorkers-1 {
				endNonce = mining.MaxNonce // 最后一个worker处理剩余范围
			}

			workerHeader := currentHeader
			go func(s, e uint32, hdr wire2.BlockHeader) {
				localHashes := uint64(0)
				defer func() {
					hashCountChan <- localHashes // 确保哈希计数发送
					// 延迟发送 resultChan，覆盖所有退出场景
					resultChan <- workerResult{false, 0, chainhash.Hash{}}
				}()

				for nonce := s; nonce <= e; nonce++ {
					// 检查终止信号（任务/worker）
					select {
					case <-taskQuit:
						return
					case <-workerStopChan:
						return
					default:
					}

					// 计算哈希并检查难度
					hdr.Nonce = nonce
					hash := hdr.BlockHash()
					localHashes++

					if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
						resultChan <- workerResult{true, nonce, hash}
						return
					}
				}
			}(startNonce, endNonce, workerHeader)
		}

		// 监听worker结果/定期检查
		ticker := time.NewTicker(time.Second * mining.HashUpdateSecs)
		defer ticker.Stop()

		workersCompleted := 0
		foundSolution := false
		var solvedNonce uint32
		var solvedHash chainhash.Hash
		hashesCompleted := uint64(0)

	loop:
		for {
			select {
			// 处理worker结果
			case res := <-resultChan:
				workersCompleted++
				if res.found {
					foundSolution = true
					solvedNonce = res.nonce
					solvedHash = res.hash
					close(workerStopChan) // 停止其他worker
					// 收集剩余worker的哈希计数（避免goroutine泄漏）
					go func() {
						for ; workersCompleted < int(numWorkers); workersCompleted++ {
							<-resultChan
							hashesCompleted += <-hashCountChan
						}
					}()
					break loop
				}

				// 所有worker完成，当前ExtraNonce无结果
				if workersCompleted == int(numWorkers) {
					for i := 0; i < int(numWorkers); i++ {
						hashesCompleted += <-hashCountChan
					}
					m.updateHashes <- hashesCompleted // 汇报算力
					hashesCompleted = 0
					break loop
				}

			// 定期检查（区块过时/交易更新）
			//// 定期检查（区块过时/交易更新/超时）
			case <-ticker.C:

				if time.Since(miningStartTime) > timeoutThreshold {
					log.Infof("挖矿超时（已耗时%v），终止当前任务", time.Since(miningStartTime))
					close(workerStopChan)
					go func() { // 清理资源
						for ; workersCompleted < int(numWorkers); workersCompleted++ {
							<-resultChan
							<-hashCountChan
						}
					}()
					return false // 返回false，上层会重新生成模板（更新时间戳）
				}

				// 汇总哈希计数
				select {
				case hc := <-hashCountChan:
					hashesCompleted += hc
				default:
				}
				m.updateHashes <- hashesCompleted
				hashesCompleted = 0

				// 检查区块是否过时（PrevBlock是否变化）
				m.submitBlockLock.Lock()
				isStale := !header.PrevBlock.IsEqual(&m.g.BestSnapshot().Hash)
				m.submitBlockLock.Unlock()

				if isStale {
					close(workerStopChan)
					go func() { // 清理资源
						for ; workersCompleted < int(numWorkers); workersCompleted++ {
							<-resultChan
							<-hashCountChan
						}
					}()
					return false
				}

				// 检查内存池更新（需重新生成模板）
				if lastTxUpdate != m.g.TxSource().LastUpdated() &&
					time.Now().After(lastGenerated.Add(time.Minute)) {
					close(workerStopChan)
					go func() {
						for ; workersCompleted < int(numWorkers); workersCompleted++ {
							<-resultChan
							<-hashCountChan
						}
					}()
					return false
				}

				// 【已删除】禁止更新时间戳：m.g.UpdateBlockTime(msgBlock, blockHeight)
				// 【已删除】禁止同步时间戳：currentHeader.Timestamp = header.Timestamp

			// 外部任务终止信号
			case <-taskQuit:
				close(workerStopChan)
				go func() {
					for ; workersCompleted < int(numWorkers); workersCompleted++ {
						<-resultChan
						<-hashCountChan
					}
				}()
				return false
			}
		}

		// 找到有效解，返回成功
		if foundSolution {

			// 锁定当前区块的Header，复制为不可变对象
			finalHeader := currentHeader
			finalHeader.Nonce = solvedNonce
			// 后续提交使用finalHeader，不再修改原msgBlock.Header
			msgBlock.Header = finalHeader

			ticker.Stop() // 立即停止定期检查，避免时间戳更新

			// 汇总剩余哈希计数
			for i := 0; i < int(numWorkers); i++ {
				select {
				case hc := <-hashCountChan:
					hashesCompleted += hc
				default:
				}
			}
			m.updateHashes <- hashesCompleted

			header.Nonce = solvedNonce
			log.Infof("Mined block | Height: %d | ExtraNonce: %d | Nonce: %d | Hash: %s",
				blockHeight, extraNonce, solvedNonce, solvedHash)
			return true
		}
	}

	log.Debugf("Exhausted all extra nonces (offset: %d)", enOffset)
	return false
}

func (m *CPUMiner) Stop() {
	m.Lock()
	defer m.Unlock()

	if !m.started || m.discreteMining {
		return
	}

	log.Infof("开始退出挖矿程序")

	if m.speedMonitorQuit != nil {
		close(m.speedMonitorQuit)
		m.speedMonitorQuit = nil
	}

	if m.CurrentTaskQuit != nil {
		close(m.CurrentTaskQuit)
		m.CurrentTaskQuit = nil
	}

	if m.quit != nil {
		close(m.quit)
		m.quit = nil
	}

	// 3. 等待 workerWg（调度器）退出，增加超时保护
	workerExit := make(chan struct{})
	go func() {
		m.workerWg.Wait()
		close(workerExit)
	}()
	select {
	case <-workerExit:
		log.Infof("调度器协程已退出")
	case <-time.After(10 * time.Second):
		log.Warnf("调度器协程退出超时，可能存在泄漏")
	}

	// 4. 等待 wg（监控器+控制器）退出
	wgExit := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(wgExit)
	}()
	select {
	case <-wgExit:
		log.Infof("监控器与控制器协程已退出")
	case <-time.After(10 * time.Second):
		log.Warnf("监控器协程退出超时，可能存在泄漏")
	}

	// 5. 重置状态
	m.started = false
	m.speedMonitorQuit = nil
	log.Infof("CPU miner stopped completely")
}

func (m *CPUMiner) IsMining() bool {
	m.Lock()
	defer m.Unlock()
	return m.started
}

func (m *CPUMiner) submitBlock(block *wire2.Block) bool {

	log.Info("Submitting mined block")
	m.submitBlockLock.Lock()
	defer m.submitBlockLock.Unlock()

	// 原有：检查区块是否过时
	msgBlock := block.MsgBlock()
	bestSnap := m.g.BestSnapshot()
	if !msgBlock.Header.PrevBlock.IsEqual(&bestSnap.Hash) {
		log.Debugf("Submitted block is stale (prev hash: %s)", msgBlock.Header.PrevBlock)
		return false
	}

	// 处理区块
	isOrphan, err := m.cfg.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		if _, ok := err.(blockchain.RuleError); !ok {
			log.Errorf("Unexpected error processing block: %v", err)
		} else {
			log.Debugf("Block rejected: %v", err)
		}
		return false
	}
	if isOrphan {
		log.Debugf("Submitted block is orphan")
		return false
	}

	// 新增：区块接受后，立即终止当前挖矿任务
	m.Lock()
	if m.CurrentTaskQuit != nil {
		close(m.CurrentTaskQuit)
		m.CurrentTaskQuit = nil
	}
	m.Unlock()

	// 原有日志
	coinbaseTx := msgBlock.Transactions[0].TxOut[0]
	log.Infof("Block accepted | Hash: %s | Reward: %v", block.Hash(), utils.Amount(coinbaseTx.Value))
	return true
}

// SetNumWorkers 动态调整挖矿Worker数量
func (m *CPUMiner) SetNumWorkers(num uint32) {
	m.Lock()
	defer m.Unlock()
	if num == 0 {
		num = defaultNumWorkers
	}
	m.numWorkers = num
	// 发送信号通知solveBlock调整Worker
	select {
	case m.updateNumWorkers <- struct{}{}:
	default:
		// 避免通道阻塞（若前一个信号未处理，忽略重复信号）
	}
}

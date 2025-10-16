package netsync

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/mempool"
	"bitcoin/network"
	"bitcoin/wire"
	"bytes"
	"container/list"
	"fmt"
	"google.golang.org/protobuf/proto"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// 消息类型定义：封装所有需要串行处理的事件
type (
	// blockMsg 表示区块处理消息
	blockMsg struct {
		id  string
		blk *core.MsgBlock
		// 用于同步返回处理结果
		reply chan error
	}

	// txMsg 表示交易处理消息

	txMsg struct {
		id    string
		tx    *core.MsgTx
		reply chan error
	}

	// handshakeMsg 表示握手处理消息
	handshakeMsg struct {
		id    string
		hs    *wire.ProtoHandshake
		reply chan error
	}

	// handshakeAckMsg 表示握手确认处理消息
	handshakeAckMsg struct {
		id    string
		ack   *wire.ProtoHandshakeAck
		reply chan error
	}
)

const (
	//含义：在 “headers-first 同步模式” 下，请求队列中至少应保持的区块数量。当队列中待处理的区块请求数低于这个值时，
	//节点会主动向对等节点请求更多区块。
	//背景：区块链同步通常采用 “先同步区块头（headers），再同步区块体（blocks）” 的策略（headers-first）。
	//这个参数确保队列始终有足够的区块请求 “在途”，避免同步过程因 “无数据可处理” 而中断，提高同步效率。
	minInFlightBlocks = 10

	//含义：内存中最多保存的 “被拒绝交易哈希” 数量（1000 个）。
	//作用：节点在处理交易时，会拒绝无效交易（如格式错误、签名无效等）。
	//保存最近被拒绝的交易哈希，可避免重复接收和处理同一笔无效交易（当其他节点再次广播时，直接跳过），
	//减少无效计算和网络开销。限制数量是为了防止内存占用过高。
	maxRejectedTxns = 1000

	//含义：内存中最多保存的 “已请求区块哈希” 数量，值等于协议定义的wire.MaxInvPerMsg（通常是 50000，
	//区块链协议中单次inv消息能包含的最大哈希数）。
	//作用：节点向对等节点请求区块时，会记录已发送请求的区块哈希，
	//避免重复请求同一区块（比如网络延迟导致的重试场景）。数量限制与协议保持一致，确保不超过单次消息的最大容量。
	maxRequestedBlocks = wire.MaxInvPerMsg

	//含义：内存中最多保存的 “已请求交易哈希” 数量，同样等于wire.MaxInvPerMsg。
	//作用：与maxRequestedBlocks类似，用于跟踪已向对等节点请求的交易哈希，防止重复请求同一笔交易，优化网络带宽和节点处理效率。
	maxRequestedTxns = wire.MaxInvPerMsg

	//含义：如果与当前同步节点的同步过程 “停滞”（没有新的区块 / 交易数据进展）超过 3 分钟，节点会主动断开与该节点的连接。
	//作用：避免节点长时间卡在 “无响应” 或 “同步缓慢” 的对等节点上。当一个节点同步停滞时，及时断开并切换到其他健康节点，保证整体同步进度。
	maxStallDuration = 3 * time.Minute

	//含义：检查同步是否 “停滞” 的时间间隔（每 30 秒检查一次）。
	//作用：定期采样同步进度（比如对比当前已同步的区块高度与上一次检查时的高度），
	//如果连续多次检查都没有进展，且累计时间超过maxStallDuration，则触发断开连接的逻辑。
	stallSampleInterval = 30 * time.Second
)

var zeroHash chainhash.Hash

type SyncManager struct {
	peerNotifier PeerNotifier
	// 原子操作标记，用于判断启动/关闭状态
	started  int32
	shutdown int32

	txMemPool *mempool.TxPool

	chain *blockchain.BlockChain

	chainParams     *core.Params
	progressLogger  *blockProgressLogger
	msgChan         chan interface{}
	wg              sync.WaitGroup
	quit            chan struct{}
	rejectedTxns    map[chainhash.Hash]struct{}
	requestedTxns   map[chainhash.Hash]struct{}
	requestedBlocks map[chainhash.Hash]struct{}

	lastProgressTime time.Time

	headersFirstMode bool
	headerList       *list.List
	startHeader      *list.Element
	nextCheckpoint   *core.Checkpoint

	feeEstimator *mempool.FeeEstimator

	Network network.NetworkLayer

	parentReqCount map[string]int

	syncLock sync.RWMutex

	isSyncing atomic.Bool

	processBlockLock sync.Mutex
}

// OnBlock 接收区块事件，发送到消息通道串行处理
func (sm *SyncManager) OnBlock(id string, w *core.MsgBlock) error {
	if sm.isSyncing.Load() {
		log.Warnf("TriggerSync: 正在同步，拒绝处理新区块")
		return nil
	}

	// 若已关闭，直接返回
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return nil
	}
	// 创建带返回通道的消息
	replyChan := make(chan error, 1)
	sm.msgChan <- blockMsg{
		id:    id,
		blk:   w,
		reply: replyChan,
	}
	// 等待处理结果
	return <-replyChan
}

// OnTx 接收交易事件，发送到消息通道串行处理
func (sm *SyncManager) OnTx(id string, w *core.MsgTx) error {
	log.Infof("处理交易")
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return nil
	}
	replyChan := make(chan error, 1)
	sm.msgChan <- txMsg{
		id:    id,
		tx:    w,
		reply: replyChan,
	}
	return <-replyChan
}

// OnHandshake 接收握手事件，发送到消息通道串行处理
func (sm *SyncManager) OnHandshake(id string, w *wire.ProtoHandshake) error {
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return nil
	}
	replyChan := make(chan error, 1)
	sm.msgChan <- handshakeMsg{
		id:    id,
		hs:    w,
		reply: replyChan,
	}
	return <-replyChan
}

// OnHandshakeAck 接收握手确认事件，发送到消息通道串行处理
func (sm *SyncManager) OnHandshakeAck(id string, w *wire.ProtoHandshakeAck) error {
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return nil
	}
	replyChan := make(chan error, 1)
	sm.msgChan <- handshakeAckMsg{
		id:    id,
		ack:   w,
		reply: replyChan,
	}
	return <-replyChan
}

func New(config *Config) (*SyncManager, error) {
	// 初始化消息通道（缓冲区可根据需求调整）
	msgChan := make(chan interface{}, 100)
	quitChan := make(chan struct{})

	sm := &SyncManager{
		wg:              sync.WaitGroup{},
		txMemPool:       config.TxMemPool,
		chain:           config.Chain,
		chainParams:     config.ChainParams,
		progressLogger:  newBlockProgressLogger("Syncing", log),
		msgChan:         msgChan,
		quit:            quitChan,
		rejectedTxns:    make(map[chainhash.Hash]struct{}),
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
		headerList:      list.New(),
		feeEstimator:    config.FeeEstimator,
		peerNotifier:    config.PeerNotifier, // 关键：补充赋值，避免 nil
		parentReqCount:  make(map[string]int),
	}

	sm.chain.Subscribe(sm.handleBlockchainNotification)
	return sm, nil
}

// 消息处理循环：串行处理所有消息
func (sm *SyncManager) msgHandler() {
	defer sm.wg.Done()

	for {
		select {
		case msg := <-sm.msgChan:
			// 根据消息类型处理
			switch m := msg.(type) {
			case blockMsg:
				m.reply <- sm.handleBlock(m.id, m.blk)
			case txMsg:
				m.reply <- sm.handleTx(m.id, m.tx)
			case handshakeMsg:
				m.reply <- sm.handleHandshake(m.id, m.hs)
			case handshakeAckMsg:
				m.reply <- sm.handleHandshakeAck(m.id, m.ack)
			}
		case <-sm.quit:
			// 收到退出信号，终止循环
			return
		}
	}
}

// 实际处理区块的业务逻辑（仅在msgHandler中调用）
func (sm *SyncManager) handleBlock(id string, blk *core.MsgBlock) error {
	if sm.isSyncing.Load() {
		log.Warnf("TriggerSync: 正在同步，拒绝处理新区块")
		return nil
	}
	// 这里实现原OnBlock的逻辑，可安全访问共享资源
	// 例如：验证区块、添加到区块链、更新请求状态等
	log.Infof("处理区块 from %s", id)
	// ...
	//查询父亲区块   通过父亲区块得到高度 和 区块累计工作量
	//如果父亲区块不存在就丢弃掉
	preBlock, err := sm.chain.GetBlockByHash(&blk.BlockHeader().PrevBlock)
	preBlockHash := &blk.BlockHeader().PrevBlock
	if err != nil || preBlock == nil {
		log.Infof("节点%s：查询父区块（哈希: %s）失败，err: %v", id, preBlockHash.String(), err)

		// 2. 获取当前节点的请求次数（默认0次）
		reqCount, exists := sm.parentReqCount[id]
		if !exists {
			reqCount = 0
		}

		// 3. 判断是否超过最大请求次数（6次）
		if reqCount < 6 {
			// 3.1 未达6次：发送父区块请求，递增计数
			pbInvVect := &wire.InvVect{
				Type: wire.InvTypeBlock,
				Hash: *preBlockHash,
			}
			// 处理protobuf序列化错误（原有代码忽略错误）
			marshalData, marshalErr := proto.Marshal(pbInvVect.ToProto())
			if marshalErr != nil {
				log.Errorf("节点%s：序列化父区块请求失败，err: %v", id, marshalErr)
				return marshalErr
			}

			// 发送请求
			log.Infof("节点%s：向父区块（哈希: %x）发送请求（第%d次）", id, preBlockHash, reqCount+1)
			sm.Network.Send(id, network.GetDataProtocol, marshalData)

			// 更新请求次数
			sm.parentReqCount[id] = reqCount + 1
		} else {
			// 3.2 已达6次：停止请求，触发同步逻辑
			log.Warnf("节点%s：父区块请求已达6次（目标哈希: %x），触发同步", id, preBlockHash)
			localIndex, _ := sm.chain.GetSyncIndex()
			localIndex.PeerId = sm.Network.SelfID()
			marshal, _ := proto.Marshal(localIndex)
			//将本地路标发送给目标节点就能收到
			go sm.Network.Send(id, network.SyncIndexProtocol, marshal)
			// 重置该节点的请求次数（避免后续重复触发）
			delete(sm.parentReqCount, id)
		}
		return nil
	}

	// 4. 父区块存在：重置该节点的请求次数（请求链已正常中断）
	delete(sm.parentReqCount, id)

	block := core.NewBlock(blk)
	block.SetHeight(preBlock.BlockHeight + 1)
	work := blockchain.CalculateBlockWork(blk.BlockHeader().Bits)
	sum := new(big.Int).Add(work, preBlock.GetChainWork())
	block.SetChainWork(sum)
	sm.ProcessBlock(block, blockchain.BFNone)
	return nil
}

// 实际处理交易的业务逻辑（仅在msgHandler中调用）
func (sm *SyncManager) handleTx(id string, tx *core.MsgTx) error {
	// 例如：检查是否为已拒绝交易、添加到内存池等
	txHash := tx.TxHash()
	if _, exists := sm.rejectedTxns[txHash]; exists {
		return nil // 跳过已拒绝的交易
	}
	newTx := core.NewTx(tx)
	acceptedTxs, err := sm.txMemPool.ProcessTransaction(newTx, true, true, 0)
	if err != nil {
		log.Infof("处理结果", err)
		return err
	}
	log.Infof("处理成功", acceptedTxs)
	return nil
}

// 实际处理握手的业务逻辑（仅在msgHandler中调用）
func (sm *SyncManager) handleHandshake(id string, hs *wire.ProtoHandshake) error {
	log.Infof("开始处理握手 from %s", id)
	// 验证节点兼容性、更新节点信息等
	// 获取本地创世块哈希
	localGenesisHash := sm.chain.GetGenesisBlockHash()
	// 获取对方的创世块哈希
	remoteGenesisHash := hs.GenesisHash
	if !bytes.Equal(localGenesisHash[:], remoteGenesisHash) {
		log.Errorf("握手失败：创世块哈希不匹配，本地: %x, 对方: %x, 节点ID: %s",
			localGenesisHash, remoteGenesisHash, id)
		return fmt.Errorf("创世块哈希不匹配，无法建立连接")
	}
	return nil
}

// 实际处理握手确认的业务逻辑（仅在msgHandler中调用）
func (sm *SyncManager) handleHandshakeAck(id string, ack *wire.ProtoHandshakeAck) error {
	log.Infof("处理握手确认 from %s", id)
	// ...
	return nil
}

// Start 启动SyncManager，初始化处理goroutine
func (sm *SyncManager) Start() {
	if atomic.AddInt32(&sm.started, 1) != 1 {
		return // 已启动，直接返回
	}
	// 启动消息处理goroutine
	sm.wg.Add(1)
	go sm.msgHandler()
	log.Infof("SyncManager 启动成功")
}

// Shutdown 关闭SyncManager，释放资源
func (sm *SyncManager) Shutdown() {
	if atomic.AddInt32(&sm.shutdown, 1) != 1 {
		return // 已关闭，直接返回
	}
	close(sm.quit) // 发送退出信号
	sm.wg.Wait()   // 等待处理goroutine退出
	log.Infof("SyncManager 已关闭")
}

func (sm *SyncManager) ProcessBlock(block *core.Block, flags blockchain.BehaviorFlags) (bool, error) {
	// 1. 调用底层区块链核心的区块处理逻辑（已实现完整校验、存储等）
	isMainChain, _, err := sm.chain.ProcessBlock(block, flags)
	if err != nil {
		// 打印错误日志，便于问题排查
		log.Errorf("区块处理失败 [哈希: %v, 高度: %d  Nonce:%d   Time:%d ]: %v", block.Hash(), block.Height(), block.BlockHeader().Nonce, block.BlockHeader().Timestamp, err)
		return false, err
	}
	// 返回"是否为主链区块"及处理结果（忽略底层的"是否为孤儿块"标识，上层无需感知）
	return isMainChain, nil
}

func (sm *SyncManager) handleBlockchainNotification(notification *blockchain.Notification) {
	switch notification.Type {
	case blockchain.NTBlockAccepted:
		block, ok := notification.Data.(*core.Block)
		if !ok {
			log.Infof("Chain accepted notification is not a block.")
			break
		}

		// Generate the inventory vector and relay it.
		iv := wire.NewInvVect(wire.InvTypeBlock, block.Hash())
		sm.peerNotifier.RelayInventory(iv, block.MsgBlock().Header)

	case blockchain.NTBlockConnected:
		block, ok := notification.Data.(*core.Block)
		if !ok {
			log.Infof("Chain connected notification is not a block.")
			break
		}

		for _, tx := range block.Transactions()[1:] {
			sm.txMemPool.RemoveTransaction(tx, false)
			sm.txMemPool.RemoveDoubleSpends(tx)
			sm.txMemPool.RemoveOrphan(tx)
			sm.peerNotifier.TransactionConfirmed(tx)
			acceptedTxs := sm.txMemPool.ProcessOrphans(tx)
			sm.peerNotifier.AnnounceNewTransactions(acceptedTxs)
		}

		// Register block with the fee estimator, if it exists.
		if sm.feeEstimator != nil {
			err := sm.feeEstimator.RegisterBlock(block)

			// If an error is somehow generated then the fee estimator
			// has entered an invalid state. Since it doesn't know how
			// to recover, create a new one.
			if err != nil {
				sm.feeEstimator = mempool.NewFeeEstimator(
					mempool.DefaultEstimateFeeMaxRollback,
					mempool.DefaultEstimateFeeMinRegisteredBlocks, sm.chainParams)
			}
		}

	// A block has been disconnected from the main block chain.
	case blockchain.NTBlockDisconnected:
		block, ok := notification.Data.(*core.Block)
		if !ok {
			log.Infof("Chain disconnected notification is not a block.")
			break
		}

		// Reinsert all of the transactions (except the coinbase) into
		// the transaction pool.
		for _, tx := range block.Transactions()[1:] {
			_, _, err := sm.txMemPool.MaybeAcceptTransaction(tx,
				false, false)
			if err != nil {
				// Remove the transaction and all transactions
				// that depend on it if it wasn't accepted into
				// the transaction pool.
				sm.txMemPool.RemoveTransaction(tx, true)
			}
		}

		// Rollback previous block recorded by the fee estimator.
		if sm.feeEstimator != nil {
			sm.feeEstimator.Rollback(block.Hash())
		}
	}
}

func (sm *SyncManager) Stop() error {
	if atomic.AddInt32(&sm.shutdown, 1) != 1 {
		log.Warnf("Sync manager is already in the process of " +
			"shutting down")
		return nil
	}
	log.Infof("Sync manager shutting down")
	close(sm.quit)
	sm.wg.Wait()
	return nil
}

func (sm *SyncManager) ExistsTxInMempool(hash *chainhash.Hash) bool {
	// 防御性检查：避免空指针异常
	if sm.txMemPool == nil || hash == nil {
		return false
	}

	// 利用内存池的FetchTransaction方法判断交易是否存在
	// 该方法仅在主内存池中查找，找到返回交易，否则返回错误
	_, err := sm.txMemPool.FetchTransaction(hash)
	return err == nil
}

func (sm *SyncManager) TriggerSync(totalIntervals []wire.SyncIndex) {
	log.Infof("触发同步")
	sm.syncLock.Lock()
	defer sm.syncLock.Unlock()

	// 2. 检查是否正在同步：若已在同步，直接拒绝新请求
	if sm.isSyncing.Load() {
		log.Warnf("TriggerSync: 已有同步任务正在执行，拒绝新的同步请求（当前请求包含 %d 个区间）", len(totalIntervals))
		return
	}

	// 3. 标记为“正在同步”，并确保最终重置状态（无论成功/失败）
	sm.isSyncing.Store(true)
	defer func() {
		sm.isSyncing.Store(false)
	}()

	//先筛选节点筛选节点  筛选出全节点
	reqData := network.PersistentPeer{
		IsOnline:        true,
		HandshakeStatus: wire.HandshakeStatus_HANDSHAKE_COMPLETED,
	}
	eligiblePeers, err := sm.Network.GetPeerByCondition(reqData)
	if err != nil {
		log.Infof("查询在线节点失败%s", err)
	}
	if len(eligiblePeers) == 0 {
		log.Warnf("TriggerSync: 没有符合条件的全节点，无法同步区块")
		return
	}
	log.Infof("TriggerSync: 筛选出 %d 个可用全节点", len(eligiblePeers))
	//询问每个节点的最大高度
	// 2. 收集每个节点的最新高度和哈希（节点能力档案）
	type peerHeightInfo struct {
		peerID       string // 节点ID
		latestHeight int32  // 最新区块高度
		latestHash   []byte // 最新区块哈希
	}
	var validPeers []peerHeightInfo
	for _, peer := range eligiblePeers {
		res, err := sm.Network.Send(peer.ID, network.GetPeerLatestHeightProtocol, nil)
		if err != nil {
			log.Infof("获取节点最新高度失败")
		}
		var latestIndex wire.BlockIndex
		err = proto.Unmarshal(res, &latestIndex)
		if err != nil {
			log.Infof("解析失败")
		}
		// 2.3 验证有效性（高度需>0，哈希需非空）
		if latestIndex.Height <= 0 || len(latestIndex.Hash) == 0 {
			log.Warnf("TriggerSync: 节点 %s 最新高度无效（高度: %d, 哈希: %x）",
				peer.ID, latestIndex.Height, latestIndex.Hash)
			continue
		}
		validPeers = append(validPeers, peerHeightInfo{
			peerID:       peer.ID,
			latestHeight: latestIndex.Height,
			latestHash:   latestIndex.Hash,
		})
	}
	if len(validPeers) == 0 {
		log.Warnf("TriggerSync: 没有能提供有效高度的节点")
		return
	}
	// 3. 按节点最新高度降序排序（优先选择高度更高的节点，覆盖更大区间）
	sort.Slice(validPeers, func(i, j int) bool {
		return validPeers[i].latestHeight > validPeers[j].latestHeight
	})
	log.Infof("TriggerSync: 最终筛选出 %d 个有效节点（按高度降序）", len(validPeers))
	type syncInterval struct {
		startHeight int32           // 区间起始高度
		endHeight   int32           // 区间结束高度
		endHash     []byte          // 区间结束高度对应的哈希（用于校验）
		syncIdx     *wire.SyncIndex // 待发送的同步索引（需设置目标节点ID）
	}
	var validIntervals []*syncInterval
	// 遍历解析原始区间列表
	if len(totalIntervals) == 0 {
		log.Warnf("TriggerSync: 待同步区间列表为空，无需分配")
		return
	}
	for _, rawIdx := range totalIntervals {
		// 校验区间格式：每个区间需包含「起始+结束」2个 BlockIndex
		if len(rawIdx.Index) != 2 {
			log.Warnf("TriggerSync: 区间格式无效（BlockIndex数量≠2），PeerId: %s，跳过", rawIdx.PeerId)
			continue
		}
		startBlkIdx := rawIdx.Index[0]
		endBlkIdx := rawIdx.Index[1]
		startH := startBlkIdx.Height
		endH := endBlkIdx.Height
		endHash := endBlkIdx.Hash
		// 校验区间逻辑有效性
		if startH > endH {
			log.Warnf("TriggerSync: 区间高度无效（起始>结束），start: %d, end: %d，跳过", startH, endH)
			continue
		}
		if len(endHash) == 0 {
			log.Warnf("TriggerSync: 区间结束哈希为空，start: %d, end: %d，跳过", startH, endH)
			continue
		}
		// 构造独立的 SyncIndex（避免修改原始对象）
		assignedSyncIdx := &wire.SyncIndex{
			PeerId: "", // 待分配目标节点ID
			Index: []*wire.BlockIndex{
				{Height: startH, Hash: startBlkIdx.Hash}, // 起始高度（允许哈希为零）
				{Height: endH, Hash: endHash},            // 结束高度+哈希（核心校验依据）
			},
		}
		validIntervals = append(validIntervals, &syncInterval{
			startHeight: startH,
			endHeight:   endH,
			endHash:     endHash,
			syncIdx:     assignedSyncIdx,
		})
		// 若解析后无有效区间，返回
		if len(validIntervals) == 0 {
			log.Warnf("TriggerSync: 原始区间列表解析后无有效区间，终止同步")
			return
		}
		log.Infof("TriggerSync: 成功解析 %d 个有效同步区间", len(validIntervals))
		// 5. 为每个有效区间分配节点并发送同步请求
		for _, interval := range validIntervals {
			var targetPeer *peerHeightInfo
			// 遍历有效节点，找到第一个能覆盖该区间的节点（高度≥区间结束高度）
			for _, peer := range validPeers {
				if peer.latestHeight >= interval.endHeight {
					// 额外校验：若节点高度=区间结束高度，需哈希一致（避免数据不匹配）
					if peer.latestHeight == interval.endHeight && !bytes.Equal(peer.latestHash, interval.endHash) {
						log.Warnf("TriggerSync: 节点 %s 高度匹配但哈希不匹配（节点哈希: %x, 区间哈希: %x），跳过",
							peer.peerID, peer.latestHash, interval.endHash)
						continue
					}
					targetPeer = &peer
					break // 优先选择高度最高的节点，找到即退出
				}
			}
			// 无合适节点，记录警告
			if targetPeer == nil {
				log.Warnf("TriggerSync: 无节点能覆盖区间 [start: %d, end: %d]（需高度≥%d），跳过",
					interval.startHeight, interval.endHeight, interval.endHeight)
				continue
			}
			// -------------- 核心修复：填充负责同步的节点ID --------------
			interval.syncIdx.PeerId = targetPeer.peerID
			log.Infof("TriggerSync: 区间 [start: %d, end: %d] 分配给节点 %s（节点最新高度: %d）",
				interval.startHeight, interval.endHeight, targetPeer.peerID, targetPeer.latestHeight)
		}
	}
	log.Infof("TriggerSync: 所有有效区间分配完成（共 %d 个区间）", len(validIntervals))
	//开始执行同步
	for _, interval := range validIntervals {
		hash, _ := chainhash.BytesToHash(interval.endHash)
		targetPeerID := interval.syncIdx.PeerId
		startH := interval.startHeight
		endH := interval.endHeight
		log.Infof("分段开始高度%v", startH)
		log.Infof("分段结束高度%v", endH)
		log.Infof("分段结束Hash%v", hash.String())
		log.Infof("负责的节点ID%v", targetPeerID)
		log.Infof("TriggerSync: 准备向节点[%s]索要区间区块 [起始高度:%d, 结束高度:%d, 结束哈希:%s]", targetPeerID, startH, endH, hash.String())
		// 步骤1：先索要该区间的区块头（Headers-First模式核心：先验证头部合法性）
		if err := sm.requestBlockHeaders(targetPeerID, startH, endH, hash); err != nil {
			log.Errorf("TriggerSync: 向节点[%s]索要区块头失败 [区间:%d-%d]，err:%v",
				targetPeerID, startH, endH, err)
			continue // 跳过该区间，处理下一个
		}
	}
}

func (sm *SyncManager) requestBlockHeaders(targetPeerID string, startH, endH int32, endHash chainhash.Hash) error {
	// 1. 构建区块头请求协议的参数（符合 Bitcoin 协议的 GetHeaders 格式）
	// 注：需根据代码中 `wire` 包的 `ProtoGetHeaders` 结构定义调整（此处假设结构存在）
	getHeadersReq := &wire.ProtoGetHeaders{
		StartHeight: startH,     // 区间起始高度
		EndHeight:   endH,       // 区间结束高度
		EndHash:     endHash[:], // 结束区块的哈希（用于校验区间完整性）
	}
	// 2. Protobuf 序列化请求（与代码中父区块请求逻辑一致）
	reqData, err := proto.Marshal(getHeadersReq)
	if err != nil {
		return fmt.Errorf("序列化区块头请求失败: %w", err)
	}
	headerListRes, err := sm.Network.Send(targetPeerID, network.GetHeadersProtocol, reqData)
	if err != nil {
		return err
	}
	var protoHeaderList wire.ProtoHeaderList
	err = proto.Unmarshal(headerListRes, &protoHeaderList)
	if err != nil {
		log.Infof("解析失败")
		return err
	}
	const batchSize = 32              // 每12个区块头请求一次区块体
	var batchHashes []*chainhash.Hash // 临时存储每批的区块哈希
	var batchHeaders []core.BlockHeader
	headerList := protoHeaderList.GetHeaderList()
	for i, header := range headerList {
		var coreHeader core.BlockHeader
		coreHeader.FromProto(header)
		//每12个分为一组 请求区块体 并同步
		// 获取当前区块头的哈希（用于后续请求区块体）
		blockHash := coreHeader.BlockHash()
		// 将当前区块哈希加入批次临时切片
		batchHashes = append(batchHashes, &blockHash)
		batchHeaders = append(batchHeaders, coreHeader)
		if len(batchHashes) == batchSize || i == len(headerList)-1 {
			// 1. 跳过空批次（防御性检查）
			if len(batchHashes) == 0 {
				batchHashes = batchHashes[:0]
				batchHeaders = batchHeaders[:0]
				continue
			}
			// 2. 构造区块体请求（GetData协议，符合比特币P2P协议规范）
			// 2.1 构建InvVect列表（每个元素对应一个待请求的区块）
			protoGetBlcokReq := &wire.ProtoGetBlock{}
			var protoGetBlcokList [][]byte
			for _, blkHash := range batchHashes {
				// 转为Proto格式（与现有序列化逻辑保持一致）
				protoGetBlcokList = append(protoGetBlcokList, blkHash.GetBytes())
			}
			protoGetBlcokReq.HashList = protoGetBlcokList
			marshal, err := proto.Marshal(protoGetBlcokReq)
			if err != nil {
				return err
			}
			bodyListData, err := sm.Network.Send(targetPeerID, network.GetBodyProtocol, marshal)
			if err != nil {
				return nil
			}
			var bodyRes wire.ProtoBlockBodyList
			err = proto.Unmarshal(bodyListData, &bodyRes)
			if err != nil {
				return err
			}
			bodyList := bodyRes.BodyList
			for k, body := range bodyList {
				headerHash := batchHeaders[k]
				var coreBody core.MsgBlockBody
				if err := coreBody.FromProto(body); err != nil {
					log.Errorf("转换区块体失败: %v", err)
					continue
				}
				block, err := core.NewBlockByHeaderAndBody(&headerHash, &coreBody)
				if err != nil {
					return nil
				}
				sm.ProcessBlock(block, blockchain.BFNone)
			}
			// 清空批次切片，准备下一批
			batchHashes = batchHashes[:0]
			batchHeaders = batchHeaders[:0]
			// 每处理完一批后休眠1秒
			time.Sleep(1 * time.Second)
		}
	}

	//校验全部的区块头
	log.Infof("获取到区块头总长度%v", len(protoHeaderList.GetHeaderList()))
	return nil
}

// 区块同步批次大小（可根据实际网络情况调整）
const syncBatchSize int32 = 128

// 最大索引跨度，用于验证稀疏索引有效性
const maxIndexSpan int32 = 128

// 对比本地与远程节点的同步索引，返回需要同步的区间列表（每个区间包含起始和结束高度）
func CompareSyncIndexes(local, remote *wire.SyncIndex) ([]wire.SyncIndex, bool, error) {
	// 处理空索引情况，确定远程最新高度（结束高度）
	var endHeight int32
	var sortedRemoteHeights []int32

	if len(remote.Index) == 0 {
		endHeight = 0
		return nil, false, nil // 远程无区块，无需同步
	} else {
		// 对远程索引按高度排序（升序），便于处理稀疏索引
		_, heights := buildRemoteHeightMap(remote)
		sortedRemoteHeights = heights
		// 最新高度为最大高度
		endHeight = sortedRemoteHeights[len(sortedRemoteHeights)-1]
	}

	// 双方都无区块，无需同步
	if len(local.Index) == 0 && len(remote.Index) == 0 {
		return nil, false, nil
	}

	// 构建远程高度映射和排序后的高度列表
	remoteHeightMap, sortedRemoteHeights := buildRemoteHeightMap(remote)

	// 本地无区块，从创世区块开始同步到远程最新高度
	var startHeight int32
	if len(local.Index) == 0 {
		startHeight = 0
	} else {
		// 构建本地高度映射和排序后的高度列表
		localHeightMap, sortedLocalHeights := buildLocalHeightMap(local)

		// 寻找最高且哈希一致的共同高度，确定同步起点
		// 从最高的本地高度开始向下查找，找到第一个在远程存在且哈希一致的高度
		foundCommon := false
		// 从最高的本地高度开始检查
		for i := len(sortedLocalHeights) - 1; i >= 0; i-- {
			localHeight := sortedLocalHeights[i]
			// 检查该高度是否存在于远程
			remoteHash, exists := remoteHeightMap[localHeight]
			if exists {
				// 检查哈希是否一致
				if bytes.Equal(localHeightMap[localHeight], remoteHash) {
					startHeight = localHeight + 1
					foundCommon = true
					break
				}
			}
		}

		// 无共同高度，从创世区块开始同步
		if !foundCommon {
			startHeight = 0
		}
	}

	// 检查是否需要同步（起点 <= 终点才需要）
	if startHeight > endHeight {
		return nil, false, nil
	}

	// 验证稀疏索引的有效性（最大跨度检查）
	if err := validateSparseIndex(sortedRemoteHeights); err != nil {
		return nil, false, err
	}

	// 将总范围拆分为多个同步区间
	return splitIntoBatches(startHeight, endHeight, remoteHeightMap, sortedRemoteHeights)
}

// 构建本地节点的高度-哈希映射及排序后的高度列表
func buildLocalHeightMap(local *wire.SyncIndex) (map[int32][]byte, []int32) {
	localHeightMap := make(map[int32][]byte)
	var heights []int32
	for _, idx := range local.Index {
		localHeightMap[idx.Height] = idx.Hash
		heights = append(heights, idx.Height)
	}
	// 按升序排序
	sort.Slice(heights, func(i, j int) bool {
		return heights[i] < heights[j]
	})
	return localHeightMap, heights
}

// 构建远程节点的高度-哈希映射及排序后的高度列表
func buildRemoteHeightMap(remote *wire.SyncIndex) (map[int32][]byte, []int32) {
	remoteHeightMap := make(map[int32][]byte)
	var heights []int32
	for _, idx := range remote.Index {
		remoteHeightMap[idx.Height] = idx.Hash
		heights = append(heights, idx.Height)
	}
	// 按升序排序
	sort.Slice(heights, func(i, j int) bool {
		return heights[i] < heights[j]
	})
	return remoteHeightMap, heights
}

// 验证稀疏索引的最大跨度不超过规定值
func validateSparseIndex(heights []int32) error {
	if len(heights) <= 1 {
		return nil
	}
	for i := 1; i < len(heights); i++ {
		span := heights[i] - heights[i-1]
		if span > maxIndexSpan {
			return fmt.Errorf("sparse index span too large: %d (max allowed: %d)", span, maxIndexSpan)
		}
	}
	return nil
}

// 找到排序高度列表中小于等于目标值的最大高度
func findMaxHeightLeq(sortedHeights []int32, target int32) (int32, bool) {
	left, right := 0, len(sortedHeights)-1
	resultIdx := -1
	for left <= right {
		mid := (left + right) / 2
		if sortedHeights[mid] <= target {
			resultIdx = mid
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	if resultIdx == -1 {
		return 0, false
	}
	return sortedHeights[resultIdx], true
}

// 将总同步范围拆分为多个批次区间
func splitIntoBatches(start, end int32, remoteHeightMap map[int32][]byte, sortedRemoteHeights []int32) ([]wire.SyncIndex, bool, error) {
	var batches []wire.SyncIndex
	currentStart := start

	for currentStart <= end {
		// 计算当前批次的最大可能结束高度
		currentEndMax := currentStart + syncBatchSize - 1
		if currentEndMax > end {
			currentEndMax = end
		}

		// 从远程稀疏索引中找到合适的结束高度（存在且在范围内）
		currentEnd, exists := findMaxHeightLeq(sortedRemoteHeights, currentEndMax)
		if !exists || currentEnd < currentStart {
			return nil, false, fmt.Errorf("no valid remote index for batch starting at %d", currentStart)
		}

		// 获取当前批次终点的哈希
		endHash, exists := remoteHeightMap[currentEnd]
		if !exists {
			return nil, false, fmt.Errorf("remote node missing hash for height %d", currentEnd)
		}

		// 构建包含起始和结束高度的完整区间
		batch := wire.SyncIndex{
			PeerId: "",
			Index: []*wire.BlockIndex{
				{Height: currentStart, Hash: nil},   // 起始高度
				{Height: currentEnd, Hash: endHash}, // 结束高度及哈希
			},
		}
		batches = append(batches, batch)

		// 移动到下一批次
		currentStart = currentEnd + 1
	}

	return batches, len(batches) > 0, nil
}

func (sm *SyncManager) IsSyncing() bool {
	return sm.isSyncing.Load()
}

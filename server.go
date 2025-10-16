package main

import (
	"bitcoin/blockchain"
	"bitcoin/blockchain/indexers"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/db"
	"bitcoin/event"
	"bitcoin/mempool"
	"bitcoin/mining"
	"bitcoin/mining/cpuminer"
	"bitcoin/mining/gpuminer"
	"bitcoin/network"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wire"
	"context"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/lru"
	"google.golang.org/protobuf/proto"
	"math/rand"
	"sync/atomic"

	"bitcoin/netsync"
	"log"
	"sync"
	"time"
)

const (
	defaultTargetOutbound   = 8
	connectionRetryInterval = time.Second * 5
	invCacheExpiry          = 24 * time.Hour // Inv缓存过期时间
	invCacheCleanupInterval = 1 * time.Hour  // 缓存清理间隔
)

var ServiceFlag []wire.ServiceFlag

var ProtoHandshake wire.ProtoHandshake

// 本节点  持有所有组件  配置文件 同步 网络 连接管理
type server struct {
	bytesReceived uint64
	bytesSent     uint64
	started       int32
	shutdown      int32
	shutdownSched int32
	startupTime   int64

	chainParams *core.Params

	sigCache  *txscript.SigCache
	hashCache *txscript.HashCache

	chain   *blockchain.BlockChain
	network network.NetworkLayer

	rpc         *NodeServer
	syncManager *netsync.SyncManager

	txMemPool            *mempool.TxPool
	cpuMiner             *cpuminer.CPUMiner
	gpuMiner             *gpuminer.GPUMiner
	modifyRebroadcastInv chan interface{}

	//版本协商器
	p2pDowngrader *network.P2PDowngrader
	query         chan interface{}

	relayInv  chan relayMsg
	broadcast chan broadcastMsg

	peerHeightsUpdate chan updatePeerHeightsMsg

	wg         sync.WaitGroup
	quit       chan struct{}
	db         db.KeyValueStore
	timeSource blockchain.MedianTimeSource

	feeEstimator *mempool.FeeEstimator

	agentBlacklist []string
	agentWhitelist []string

	cfg *Config

	addrIndex     *indexers.AddrIndex
	addrUtxoIndex *indexers.AddrUtxoIndex
	txIndex       *indexers.TxIndex

	Services []wire.ServiceFlag

	// Inv缓存相关字段
	invCache       map[string]time.Time // 存储已处理的Inv，键为Inv唯一标识，值为过期时间
	invCacheMutex  sync.RWMutex         // 保护invCache的并发访问
	invCacheExpiry time.Duration        // 缓存过期时间
}

type relayMsg struct {
	invVect *wire.InvVect
	data    interface{}
}

type broadcastMsg struct {
	message      wire.Message
	excludePeers []*network.PersistentPeer
}

type updatePeerHeightsMsg struct {
	newHash   *chainhash.Hash
	newHeight int32
}

// 创建区块链实例 blockchain.New
// 合并检查点
// 按需创建可选索引
// 创建区块链实例 blockchain.New
// 这一步只操作本地数据库，不依赖网络。参数里把 DB、索引管理器、SigCache、Prune 大小、UtxoCache 上限等全部传进去，得到 s.chain。
func newServer(cfg *Config, store db.KeyValueStore, bus *event.Bus, chainParams *core.Params, interrupt <-chan struct{}) (*server, error) {
	//知晓本节点能力  本节点是全节点 支持
	var LocalServices = []wire.ServiceFlag{
		wire.ServiceFlag_SERVICE_NONE,
		wire.ServiceFlag_SERVICE_FULL_NODE,
		wire.ServiceFlag_SERVICE_MINER,
		wire.ServiceFlag_SFNodeGetUTXO,
		wire.ServiceFlag_SFNodeBloom,
		wire.ServiceFlag_SFNodeWitness,
	}

	ServiceFlag = LocalServices

	s := server{
		Services:             LocalServices,
		chainParams:          chainParams,
		cfg:                  cfg,
		query:                make(chan interface{}),
		quit:                 make(chan struct{}),
		modifyRebroadcastInv: make(chan interface{}),
		peerHeightsUpdate:    make(chan updatePeerHeightsMsg),
		db:                   store,
		timeSource:           blockchain.NewMedianTime(),
		sigCache:             txscript.NewSigCache(cfg.Bitcoin.SigCacheMaxSize),
		hashCache:            txscript.NewHashCache(cfg.Bitcoin.SigCacheMaxSize),
	}

	var indexes []indexers.Indexer
	//交易到区块
	if cfg.Bitcoin.TxIndex || cfg.Bitcoin.AddrIndex {
		if !cfg.Bitcoin.TxIndex {
			indxLog.Infof("Transaction index enabled because it " +
				"is required by the address index")
			cfg.Bitcoin.TxIndex = true
		} else {
			indxLog.Info("Transaction index is enabled")
		}

		s.txIndex = indexers.NewTxIndex(store, chainParams)
		indexes = append(indexes, s.txIndex)
	}
	//地址到交易
	if cfg.Bitcoin.AddrIndex {
		indxLog.Info("Address index is enabled")
		s.addrIndex = indexers.NewAddrIndex(store, chainParams)
		indexes = append(indexes, s.addrIndex)
		s.addrUtxoIndex = indexers.NewAddrUtxoIndex(store, chainParams)
		indexes = append(indexes, s.addrUtxoIndex)
	}

	var indexManager blockchain.IndexManager
	if len(indexes) > 0 {
		indexManager = indexers.NewManager(store, indexes)
	}

	if s.feeEstimator == nil || s.feeEstimator.LastKnownHeight() != s.chain.BestSnapshot().Height {
		s.feeEstimator = mempool.NewFeeEstimator(mempool.DefaultEstimateFeeMaxRollback, mempool.DefaultEstimateFeeMinRegisteredBlocks, chainParams)
	}

	//-----------------------------------------
	// 本地数据库层 → 区块链（完全不依赖网络）
	//-----------------------------------------
	chain, err := blockchain.New(&blockchain.Config{
		ChainParams:      chainParams,
		Interrupt:        interrupt,
		ChainDB:          store,
		Bus:              bus,
		TimeSource:       s.timeSource,
		SigCache:         s.sigCache,
		HashCache:        s.hashCache,
		IndexManager:     indexManager,
		UtxoCacheMaxSize: uint64(cfg.Bitcoin.UTXOCacheMaxSizeMiB) * 1024 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("创建区块链失败: %w", err)
	}
	s.chain = chain

	//-----------------------------------------
	// 交易池（依赖链，但不依赖网络）
	//-----------------------------------------
	txC := mempool.Config{
		Policy: mempool.Policy{
			DisableRelayPriority: cfg.Bitcoin.NoRelayPriority,       //基于交易优先级的中继
			AcceptNonStd:         cfg.Bitcoin.RelayNonStd,           //是否接受 “非标准交易” 进入内存池。
			FreeTxRelayLimit:     cfg.Bitcoin.FreeTxRelayLimit,      //允许中继的 “免费交易”（手续费为 0 或极低）的总资源上限（通常以 “千字节” 为单位）。
			MaxOrphanTxs:         cfg.Bitcoin.MaxOrphanTxs,          //内存池允许保留的 “孤儿交易” 的最大数量。
			MaxOrphanTxSize:      defaultMaxOrphanTxSize,            //单个孤儿交易的最大字节大小限制（如默认 100,000 字节）。
			MaxSigOpCostPerTx:    blockchain.MaxBlockSigOpsCost / 4, //单个交易允许的最大 “签名操作成本（SigOp Cost）”，此处设为区块最大 SigOp 成本的 1/4。
			MinRelayTxFee:        mempool.DefaultMinRelayTxFee,      //交易被中继（转发给其他节点）的最低手续费率要求（如默认 1 sat/byte）。
			MaxTxVersion:         2,                                 //允许进入内存池的交易的最高版本号。
			RejectReplacement:    cfg.Bitcoin.RejectReplacement,     //是否拒绝 “可替换交易”（如 RBF：Replace-By-Fee）。
		},
		ChainParams:    chainParams,
		FetchUtxoView:  s.chain.FetchUtxoView,
		BestHeight:     func() int32 { return s.chain.BestSnapshot().Height },
		MedianTimePast: func() time.Time { return s.chain.BestSnapshot().MedianTime },
		SigCache:       s.sigCache,
		HashCache:      s.hashCache,
		FeeEstimator:   s.feeEstimator,
		AddrIndex:      s.addrIndex,
		CalcSequenceLock: func(tx *core.Tx, view *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error) {
			return s.chain.CalcSequenceLock(tx, view, true)
		},
	}
	s.txMemPool = mempool.New(&txC)

	//同步管理
	s.syncManager, err = netsync.New(&netsync.Config{
		PeerNotifier: &s,
		Chain:        chain,
		TxMemPool:    s.txMemPool,
		FeeEstimator: s.feeEstimator,
	})
	if err != nil {
		return nil, err
	}

	gblock, _ := s.chain.GetMainBlockHeaderByHeight(0)
	hash := gblock.BlockHash()

	handshakeReq := &wire.ProtoHandshake{
		GenesisHash:     hash[:],
		Services:        ServiceFlag,
		UserAgent:       "BitCoin 2025",
		FeeFilter:       0, //不过滤
		WitnessEnabled:  true,
		LastBlockHeight: s.chain.BestSnapshot().Height,
		LatestHash:      s.chain.BestSnapshot().Hash[:],
	}
	globalLog.Infof("最新的区块Hash%s", s.chain.BestSnapshot().Hash.String())
	globalLog.Infof("最新的区块高度Hash%s", s.chain.BestSnapshot().Height)
	ProtoHandshake = *handshakeReq

	ctx := context.Background()
	config := network.Config{
		//将区块示例注入给网络
		Handshake:      handshakeReq,
		Services:       LocalServices,
		Chain:          chain,
		DB:             store,
		Bus:            bus,
		ListenPort:     cfg.Bitcoin.PeerPort,
		DataDir:        cfg.Bitcoin.DataDir + "/" + cfg.Bitcoin.NetVersion + "/" + "network", // 已按网络版本分目录
		BootstrapPeers: cfg.Bitcoin.BootstrapPeers,                                           // 启动节点地址
		ProtocolPrefix: "/bitcoin" + "/" + cfg.Bitcoin.NetVersion,                            //网络隔离
		EnableQUIC:     true,
		EnableMDNS:     false,
		Logger:         log.Default(),
	}
	netLayer, err := network.NewNetworkLayer(ctx, config)
	if err != nil {
		log.Fatalf("创建网络层失败: %v", err)
	}
	if err := registerProtocols(netLayer, config, s.syncManager, &s); err != nil {
		log.Fatalf("注册协议失败: %v", err)
	}
	s.network = netLayer
	s.syncManager.Network = netLayer

	policy := mining.Policy{
		BlockMinWeight:    cfg.Bitcoin.BlockMinWeight,
		BlockMaxWeight:    cfg.Bitcoin.BlockMaxWeight,
		BlockMinSize:      cfg.Bitcoin.BlockMinSize,
		BlockMaxSize:      cfg.Bitcoin.BlockMaxSize,
		BlockPrioritySize: cfg.Bitcoin.BlockPrioritySize,
		TxMinFreeFee:      cfg.Bitcoin.MinRelayTxFee,
	}
	blockTemplateGenerator := mining.NewBlkTmplGenerator(
		&policy,
		s.chainParams,
		s.txMemPool,
		s.chain,
		s.timeSource,
		s.sigCache, s.hashCache)

	minerAddrs, err := convertMinerAddresses(cfg.Bitcoin.NetVersion, cfg.Mining.Miner.MinerAddress)
	if err != nil {
		// 处理错误，如日志记录或程序退出
		log.Fatalf("转换矿工地址失败: %v", err)
	}
	globalLog.Infof("矿工地址:%s", minerAddrs)

	payToAddr := minerAddrs[rand.Intn(len(minerAddrs))]

	script, err := txscript.PayToAddrScript(payToAddr)
	globalLog.Infof("payToAddr:%d", script)

	s.cpuMiner = cpuminer.New(&cpuminer.Config{
		ProcessBlock:           s.syncManager.ProcessBlock,
		MiningAddrs:            minerAddrs,
		ChainParams:            chainParams,
		BlockTemplateGenerator: blockTemplateGenerator,
	})
	s.gpuMiner = gpuminer.New(&gpuminer.Config{
		ProcessBlock:           s.syncManager.ProcessBlock,
		MiningAddrs:            minerAddrs,
		ChainParams:            chainParams,
		BlockTemplateGenerator: blockTemplateGenerator,
	})

	// RPC
	rpcServer, err := NewRPCServer(&s, cfg.Bitcoin.RPCPort)
	if err != nil {
		log.Fatalf("创建RPC失败: %v", err)
		//报错
		return nil, err
	}
	s.rpc = rpcServer

	return &s, nil
}

func (s *server) Start() {
	if atomic.AddInt32(&s.started, 1) != 1 {
		return
	}

	s.rpc.StartRPC()
	s.network.Start()
	s.syncManager.Start()

	s.wg.Add(1)
	go s.MessageHandler()

	if s.cfg.Mining.StartMining {
		globalLog.Infof("启动挖矿")
		if s.cfg.Mining.MiningType == 1 {
			globalLog.Infof("启动CPU挖矿")
			s.cpuMiner.Start()
		} else if s.cfg.Mining.MiningType == 2 {
			globalLog.Infof("启动GPU挖矿")
		}
	}
}

func (s *server) Stop() error {
	if atomic.AddInt32(&s.shutdown, 1) != 1 {
		srvrLog.Infof("Server is already in the process of shutting down")
		return nil
	}
	s.cpuMiner.Stop()
	s.rpc.StopRPC()
	s.network.Stop()
	s.syncManager.Shutdown()

	close(s.quit)
	return nil
}

func (s *server) WaitForShutdown() {
	s.wg.Wait()
}

//获取版本数据

// 注册所有协议的封装方法
func registerProtocols(netLayer network.NetworkLayer, config network.Config, syncManager *netsync.SyncManager, srv *server) error {
	registerTxProtocol(netLayer, syncManager)
	registerHandshakeProtocol(netLayer, syncManager, srv)
	registerInventoryProtocol(netLayer, syncManager, srv)
	registerRelayProtocol(netLayer, syncManager, srv)
	registerGetDataProtocol(netLayer, syncManager, srv)
	registerBlockReaProtocol(netLayer, syncManager, srv)
	registerSyncIndexProtocol(netLayer, syncManager, srv)
	registerGetPeerSyncIndexProtocol(netLayer, syncManager, srv)
	registerGetPeerLatestHeightProtocol(netLayer, syncManager, srv)
	registerGetHeadersProtocol(netLayer, syncManager, srv)
	registerGetBodyProtocol(netLayer, syncManager, srv)
	return nil
}

func registerGetBodyProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.GetBodyProtocol, func(peerID string, data []byte) ([]byte, error) {
		var protoGetBlcokReq wire.ProtoGetBlock
		if err := proto.Unmarshal(data, &protoGetBlcokReq); err != nil {
			errMsg := fmt.Sprintf("解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		var hashList []*chainhash.Hash
		for _, has := range protoGetBlcokReq.HashList {
			hash, _ := chainhash.BytesToHash(has)
			hashList = append(hashList, &hash)
		}
		list, err := srv.chain.GetBlockBodyByHashList(hashList)
		if err != nil {
			globalLog.Infof("查询错误%s", err)
			return nil, err
		}
		var bodyRes wire.ProtoBlockBodyList
		var bodyList []*wire.ProtoMsgBlockBody
		for _, body := range list {
			toProto := body.ToProto()
			toProto.Hash = body.Hash[:]
			bodyList = append(bodyList, toProto)
		}
		bodyRes.BodyList = bodyList
		marshal, _ := proto.Marshal(&bodyRes)
		return marshal, nil
	})
}

func registerGetHeadersProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.GetHeadersProtocol, func(peerID string, data []byte) ([]byte, error) {
		var protoGetHeaders wire.ProtoGetHeaders
		if err := proto.Unmarshal(data, &protoGetHeaders); err != nil {
			errMsg := fmt.Sprintf("解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		//获取区间内所有的区块头
		headerList, err := srv.chain.GetHeaderByInterval(protoGetHeaders.StartHeight, protoGetHeaders.EndHeight, protoGetHeaders.EndHash)
		if err != nil {
			return nil, err
		}
		var protoHeaders wire.ProtoHeaderList
		var protoHeaderList []*wire.ProtoBlockHeader
		for _, header := range headerList {
			toProto := header.ToProto()
			protoHeaderList = append(protoHeaderList, toProto)
		}
		protoHeaders.HeaderList = protoHeaderList
		marshal, err := proto.Marshal(&protoHeaders)
		if err != nil {
			return nil, err
		}
		return marshal, nil
	})
}

func registerGetPeerLatestHeightProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.GetPeerLatestHeightProtocol, func(peerID string, data []byte) ([]byte, error) {
		hash, _ := srv.chain.GetMainLatestHash()
		height, _ := srv.chain.GetMainLatestHeight()
		syncIndex := &wire.BlockIndex{
			Hash:   hash[:],
			Height: height,
		}
		marshal, _ := proto.Marshal(syncIndex)
		return marshal, nil
	})
}

func registerGetPeerSyncIndexProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.PeerSyncIndexProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的路标数据（长度：%d字节）\n", peerID, len(data))
		// 解析交易
		var syncIndex wire.SyncIndex
		if err := proto.Unmarshal(data, &syncIndex); err != nil {
			errMsg := fmt.Sprintf("路标解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		/*		for _, idxs := range syncIndex.Index {
				globalLog.Infof("")
				hash, _ := chainhash.BytesToHash(idxs.GetHash())
				globalLog.Infof("远程路标%v  %v", hash.String(), idxs.GetHeight())
			}*/
		localIndex, _ := srv.chain.GetSyncIndex()
		/*		for _, idxs := range localIndex.Index {
					globalLog.Infof("")
					hash, _ := chainhash.BytesToHash(idxs.GetHash())
					globalLog.Infof("本地路标%v  %v", hash.String(), idxs.GetHeight())
				}
		*/
		//与本地比较 确定从哪个区块开始同步
		indexes, b, err := netsync.CompareSyncIndexes(localIndex, &syncIndex)
		if err != nil {
			return nil, nil
		}
		if b {
			/*			for _, idxs := range indexes {
						globalLog.Infof("")
						for _, idx := range idxs.Index {
							hash, _ := chainhash.BytesToHash(idx.GetHash())
							globalLog.Infof("需要同步的区间%v  %v", hash.String(), idx.GetHeight())
						}
					}*/
			srv.syncManager.TriggerSync(indexes)
		}
		return nil, nil
	})
}

// 猪八戒吃人参果得3口  这些我一口就行
func registerSyncIndexProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.SyncIndexProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的路标数据（长度：%d字节）\n", peerID, len(data))
		// 解析交易
		var syncIndex wire.SyncIndex
		if err := proto.Unmarshal(data, &syncIndex); err != nil {
			errMsg := fmt.Sprintf("路标解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return buildErrorResp(errMsg), err
		}
		globalLog.Infof("将本地路标发送给对方 路标解析成功...........................................................")
		//与本地比较 确定从哪个区块开始同步
		localIndex, _ := srv.chain.GetSyncIndex()
		localIndex.PeerId = netLayer.SelfID()
		marshal, _ := proto.Marshal(localIndex)
		//将本地路标发送给目标节点就能收到
		go netLayer.Send(peerID, network.PeerSyncIndexProtocol, marshal)
		return nil, nil
	})
}

// --------------------------
// 2. 交易协议注册（仅处理交易相关逻辑）
// --------------------------
// 依赖：netLayer（注册协议）、txMemPool（交易入池）、sigCache（交易验证）
func registerTxProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
) {
	netLayer.RegisterProtocol(network.TxProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的交易数据（长度：%d字节）\n", peerID, len(data))

		// 解析交易
		var tx wire.ProtoMsgTx
		if err := proto.Unmarshal(data, &tx); err != nil {
			errMsg := fmt.Sprintf("交易解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return buildErrorResp(errMsg), err
		}
		var msgtx core.MsgTx
		msgtx.FromProto(&tx)

		/*		tx1 := core.NewTx(&msgtx)
				iv := wire.NewInvVect(wire.InvTypeTx, tx1.Hash())
		*/

		// 调用交易池处理交易（核心业务）
		if err := syncManager.OnTx(peerID, &msgtx); err != nil {
			errMsg := fmt.Sprintf("交易入池失败（peer=%s，txID=%s）：%v", peerID, tx, err)
			globalLog.Errorf(errMsg)
			return buildErrorResp(errMsg), err
		}

		// 处理成功
		successMsg := fmt.Sprintf("交易处理成功（peer=%s，txID=%s）", peerID, tx)
		globalLog.Infof(successMsg)
		return buildSuccessResp(successMsg), nil
	})
}

// --------------------------
// 3. 握手协议注册（仅处理握手相关逻辑）
// --------------------------
// 依赖：netLayer（注册协议）、chainParams（验证链版本）
func registerHandshakeProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.HandshakeProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的握手数据（长度：%d字节）\n", peerID, len(data))

		// 解析握手消息（假设结构是 wire.ProtoHandshake）
		var handshake wire.ProtoHandshake
		if err := proto.Unmarshal(data, &handshake); err != nil {
			errMsg := fmt.Sprintf("握手解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return buildErrorResp(errMsg), err
		}
		hash, _ := chainhash.BytesToHash(handshake.LatestHash)

		globalLog.Infof("对方最新Hash%s", hash)
		globalLog.Infof("对方最新高度%v", handshake.LastBlockHeight)

		//拿到了对方的Version
		// 调用交易池处理交易（核心业务）
		if err := syncManager.OnHandshake(peerID, &handshake); err != nil {
			errMsg := fmt.Sprintf("握手失败（peer=%s，txID=%s）：%v", peerID, handshake.ProtocolVersion, err)
			globalLog.Errorf(errMsg)
			//中断连接
			netLayer.Disconnect(peerID)
			return buildErrorResp(errMsg), err
		}
		// 握手成功
		successMsg := fmt.Sprintf("握手成功（peer=%s，链版本=%d）", peerID, handshake.ProtocolVersion)
		globalLog.Infof(successMsg)

		netLayer.MarkPeerHandshaked(peerID)
		go func() {
			//先查询这个节点 如果存在就更新 如果不存在就创建保存
			persistentPeer, err2 := netLayer.QueryPersistentPeer(peerID)
			peer, err := netLayer.GetConnectedPeerById(peerID)
			if err != nil {
				globalLog.Errorf("获取节点 [%s] 信息失败: %v", peerID, err)
				return
			}
			// 2. 转换节点地址：multiaddr.Multiaddr → 字符串切片（ProtoPersistentPeer 需字符串格式）
			addrStrs := make([]string, 0, len(peer.Addrs))
			for _, addr := range peer.Addrs {
				addrStr := addr.String()
				if addrStr == "" {
					continue // 过滤空地址
				}
				addrStrs = append(addrStrs, addrStr)
			}
			if len(addrStrs) == 0 {
				globalLog.Warnf("节点 [%s] 无有效地址，跳过保存", peerID)
			}

			if err2 != nil {
				//不存在这个节点 需要新增
				// 构造持久化节点协议消息（ProtoPersistentPeer）
				// 核心字段：ID（唯一标识）、Addrs（地址列表）、LastSeen（最后活跃时间）
				newCache := lru.NewCache(network.MaxKnownInventory)
				newPersistentPeer := &network.PersistentPeer{
					ID:       peer.ID,
					Addrs:    addrStrs,
					LastSeen: time.Now().Unix(), // 标记当前时间为最后活跃时间

					Direction:   wire.ConnectionDirection_DIR_INBOUND,
					ConnTime:    int64(0),
					DisconnTime: int64(-1),

					UserAgent:          handshake.UserAgent,
					ProtocolVersion:    uint32(handshake.ProtocolVersion), // 对方协议版本
					Services:           handshake.Services,                // 对方节点类型
					BanScore:           0,
					BanUntil:           -1, // -1 表示未封禁
					IsTrusted:          false,
					HandshakeStatus:    wire.HandshakeStatus_HANDSHAKE_COMPLETED,
					KnownInventory:     &newCache,
					InvQueue:           make([]*wire.InvVect, 0, network.MaxInvTrickleSize),
					TrickleTimer:       time.NewTimer(network.DefaultTrickleInterval),
					PendingRequests:    make(map[string]time.Time),
					LastRecvTime:       time.Now(),
					WitnessEnabled:     true,
					LastAnnouncedBlock: &hash,
					LastBlockHeight:    handshake.LastBlockHeight,
				}
				globalLog.Infof("保存节点%d", newPersistentPeer)
				if err := netLayer.SaveOrUpdatePersistentPeer(*newPersistentPeer); err != nil {
					globalLog.Errorf("新增持久化节点[%s]失败: %v", peer.ID, err)
				} else {
					globalLog.Infof("成功新增节点[%s]（类型: %v, 高度: %d）", peer.ID, newPersistentPeer.Services, handshake.LastBlockHeight)
				}
			} else {
				globalLog.Infof("更新节点.................................................")
				// 更新节点：同步最新握手信息
				persistentPeer.LastSeen = time.Now().Unix()
				persistentPeer.Addrs = addrStrs
				persistentPeer.UserAgent = handshake.UserAgent
				persistentPeer.ProtocolVersion = uint32(handshake.ProtocolVersion)
				persistentPeer.Services = handshake.Services
				persistentPeer.ConnTime = time.Now().Unix()
				persistentPeer.DisconnTime = -1
				persistentPeer.LastAnnouncedBlock = &hash
				persistentPeer.LastBlockHeight = handshake.LastBlockHeight

				if persistentPeer.KnownInventory == nil {
					cache := lru.NewCache(network.MaxKnownInventory)
					persistentPeer.KnownInventory = &cache
				}
				if persistentPeer.InvQueue == nil {
					persistentPeer.InvQueue = make([]*wire.InvVect, 0, network.MaxInvTrickleSize)
				}
				// 3. 初始化Trickle定时器（控制Inv批量发送频率）
				if persistentPeer.TrickleTimer == nil {
					persistentPeer.TrickleTimer = time.NewTimer(network.DefaultTrickleInterval)
				} else {
					// 若定时器已存在，重置为默认间隔（避免使用旧的超时时间）
					if !persistentPeer.TrickleTimer.Stop() {
						<-persistentPeer.TrickleTimer.C // 清空可能的未处理事件
					}
					persistentPeer.TrickleTimer.Reset(network.DefaultTrickleInterval)
				}
				// 4. 初始化待响应请求映射（检测请求超时用）
				if persistentPeer.PendingRequests == nil {
					persistentPeer.PendingRequests = make(map[string]time.Time)
				}

				// 5. 初始化最后收发时间（用于空闲检测）
				if persistentPeer.LastRecvTime.IsZero() {
					persistentPeer.LastRecvTime = time.Now()
				}
				if persistentPeer.LastSendTime.IsZero() {
					persistentPeer.LastSendTime = time.Now()
				}

				// 6. 初始化区块链相关运行时字段
				if persistentPeer.LastAnnouncedBlock == nil {
					persistentPeer.LastAnnouncedBlock = &chainhash.Hash{} // 空哈希初始化
				}
				// 更新到数据库
				if err := netLayer.SaveOrUpdatePersistentPeer(persistentPeer); err != nil {
					globalLog.Errorf("更新节点[%s]失败: %v", peer.ID, err)
				} else {
					globalLog.Infof("成功更新节点[%s]（最新高度: %d）", peer.ID, handshake.LastBlockHeight)
				}
			}
		}()
		//与本地节点握手 是否触发同步
		height, _ := srv.chain.GetMainLatestHeight()
		latestHash, _ := srv.chain.GetMainLatestHash()
		go func() {
			if height < handshake.LastBlockHeight {
				globalLog.Infof("本地主链高度小于握手节点高度需要同步")
				localIndex, _ := srv.chain.GetSyncIndex()
				localIndex.PeerId = netLayer.SelfID()
				marshal, _ := proto.Marshal(localIndex)
				//将本地路标发送给目标节点就能收到
				// 延迟3秒
				time.Sleep(3 * time.Second)
				netLayer.Send(peerID, network.SyncIndexProtocol, marshal)
			} else {
				globalLog.Infof("无需同步 本地链高度%v", height)
			}
		}()
		ProtoHandshake.LastBlockHeight = height
		ProtoHandshake.LatestHash = latestHash[:]
		ack, _ := proto.Marshal(&ProtoHandshake)
		resp := wire.CommonResp{
			Code:    200,
			Message: "握手成功!",
			Data:    ack,
		}
		marshal, _ := proto.Marshal(&resp)
		return marshal, nil
	})
}

func registerInventoryProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.InventoryProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的资源消息（长度：%d字节）\n", peerID, len(data))
		var protoInvVect wire.ProtoInvVect
		if err := proto.Unmarshal(data, &protoInvVect); err != nil {
			errMsg := fmt.Sprintf("资源消息解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		var invMes wire.InvVect
		invMes.FromProto(&protoInvVect)
		handleInvVect(netLayer, syncManager, peerID, invMes, srv)
		return nil, nil
	})
}

func registerGetDataProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.GetDataProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的资源消息（长度：%d字节）\n", peerID, len(data))
		var protoInvVect wire.ProtoInvVect
		if err := proto.Unmarshal(data, &protoInvVect); err != nil {
			errMsg := fmt.Sprintf("资源消息解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		var invMes wire.InvVect
		invMes.FromProto(&protoInvVect)
		//将目标需要的资源查询并发送  send RelayProtocol
		switch invMes.Type {
		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			globalLog.Infof("发送交易消息")
			blockHash, txIndexInBlock, _, err := srv.txIndex.GetBlockInfoForTx(&invMes.Hash)
			if err != nil {
				return nil, nil
			}
			tx, err := srv.chain.GetTxByBlockHashAndIndex(blockHash, txIndexInBlock)
			if err != nil {
				return nil, nil
			}
			msgTxData, _ := proto.Marshal(tx.ToProto())
			protoRelayMsg := &wire.ProtoRelayMsg{
				InvVect: invMes.ToProto(),
				Data:    msgTxData,
			}
			binaryData, _ := proto.Marshal(protoRelayMsg)
			go netLayer.Send(peerID, network.RelayProtocol, binaryData)
		case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
			globalLog.Infof("发送区块消息")
			block, err := srv.chain.GetBlockByHash(&invMes.Hash)
			if err != nil {
				globalLog.Infof("错误是%s", err)
				globalLog.Infof("区块不存在%s", invMes.Hash.String())
				return nil, nil
			}
			msgBlockData, _ := proto.Marshal(block.MsgBlock().ToProto())
			protoRelayMsg := &wire.ProtoRelayMsg{
				InvVect: invMes.ToProto(),
				Data:    msgBlockData,
			}
			globalLog.Infof("当前的节点ID:%s", peerID)
			binaryData, _ := proto.Marshal(protoRelayMsg)
			go netLayer.Send(peerID, network.RelayProtocol, binaryData)
		default:
			errMsg := fmt.Sprintf("不支持的中继消息类型：%v（peer=%s）", invMes.Type, peerID)
			globalLog.Errorf(errMsg)
		}
		return nil, nil
	})
}

// A请求B  B拿到Hash 返回区块 区块请求
func registerBlockReaProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	// 闭包捕获 syncManager，定义区块处理器
	netLayer.RegisterProtocol(network.DataReqProtocol, func(peerID string, data []byte) ([]byte, error) {
		fmt.Printf("\n收到来自 %s 的区块请求数据（长度：%d字节）\n", peerID, len(data))

		var protoInvVect wire.ProtoInvVect
		if err := proto.Unmarshal(data, &protoInvVect); err != nil {
			errMsg := fmt.Sprintf("资源消息解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		var result []byte
		var invMes wire.InvVect
		invMes.FromProto(&protoInvVect)
		//将目标需要的资源查询并发送  send RelayProtocol
		switch invMes.Type {
		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			globalLog.Infof("发送交易消息")
			blockHash, txIndexInBlock, _, err := srv.txIndex.GetBlockInfoForTx(&invMes.Hash)
			if err != nil {
				return buildErrorResp("交易未找到"), nil
			}
			tx, err := srv.chain.GetTxByBlockHashAndIndex(blockHash, txIndexInBlock)
			if err != nil {
				return buildErrorResp("交易未找到"), nil
			}
			msgTxData, _ := proto.Marshal(tx.ToProto())
			result = msgTxData
		case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
			globalLog.Infof("发送区块消息")
			block, err := srv.chain.GetBlockByHash(&invMes.Hash)
			if err != nil {
				return buildErrorResp("区块未找到"), nil
			}
			msgBlockData, _ := proto.Marshal(block.MsgBlock().ToProto())
			result = msgBlockData
		default:
			errMsg := fmt.Sprintf("不支持的中继消息类型：%v（peer=%s）", invMes.Type, peerID)
			globalLog.Errorf(errMsg)
		}
		return buildSuccessRespWithData("查询成功", result), nil
	})
}

// 添加Inv记录缓存
func handleInvVect(netLayer network.NetworkLayer, syncManager *netsync.SyncManager, peerID string, invMes wire.InvVect, srv *server) {
	globalLog.Infof("处理Inv消息")
	switch invMes.Type {
	case wire.InvTypeTx, wire.InvTypeWitnessTx:
		handleRelayTx(netLayer, syncManager, peerID, invMes, srv)
	case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
		handleRelayBlock(netLayer, syncManager, peerID, invMes, srv)
	default:
		errMsg := fmt.Sprintf("不支持的中继消息类型：%v（peer=%s）", invMes.Type, peerID)
		globalLog.Errorf(errMsg)
	}
}

func handleRelayTx(netLayer network.NetworkLayer, syncManager *netsync.SyncManager, peerID string, invMes wire.InvVect, srv *server) (string, error) {
	_, _, _, err := srv.txIndex.GetBlockInfoForTx(&invMes.Hash)
	if syncManager.ExistsTxInMempool(&invMes.Hash) || err == nil {
		return fmt.Sprintf("交易已存在（hash=%s）", invMes.Hash), nil
	}
	globalLog.Infof("不存在这个交易  向目标节点请求这个区块")
	//实现方法
	binaryData, _ := proto.Marshal(invMes.ToProto())
	go netLayer.Send(peerID, network.GetDataProtocol, binaryData)
	return fmt.Sprintf("交易类型的Inv消息处理成功（hash=%s）", invMes.Hash), nil
}

func handleRelayBlock(netLayer network.NetworkLayer, syncManager *netsync.SyncManager, peerID string, invMes wire.InvVect, srv *server) (string, error) {
	_, err := srv.chain.GetBlockByHash(&invMes.Hash)
	if err == nil {
		return fmt.Sprintf("区块已存在（hash=%s）", invMes.Hash), nil
	}
	globalLog.Infof("不存在这个区块  向目标节点请求这个区块")
	//实现方法
	binaryData, _ := proto.Marshal(invMes.ToProto())
	go netLayer.Send(peerID, network.GetDataProtocol, binaryData)
	return fmt.Sprintf("区块类型的Inv消息处理成功（hash=%s）", invMes.Hash), nil
}

func registerRelayProtocol(
	netLayer network.NetworkLayer,
	syncManager *netsync.SyncManager,
	srv *server,
) {
	netLayer.RegisterProtocol(network.RelayProtocol, func(peerID string, data []byte) ([]byte, error) {
		globalLog.Infof("收到中继消息")
		fmt.Printf("\n收到来自 %s 的中继消息（长度：%d字节）\n", peerID, len(data))
		var protoRelayMsg wire.ProtoRelayMsg
		if err := proto.Unmarshal(data, &protoRelayMsg); err != nil {
			errMsg := fmt.Sprintf("中继消息解析失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		//处理中继消息
		var relayMsg relayMsg
		if err := relayMsg.fromProto(&protoRelayMsg); err != nil {
			errMsg := fmt.Sprintf("中继消息转换失败（peer=%s）：%v", peerID, err)
			globalLog.Errorf(errMsg)
			return nil, err
		}
		// 3. 验证消息有效性
		if err := validateRelayMsg(&relayMsg); err != nil {
			errMsg := fmt.Sprintf("中继消息验证失败（peer=%s, hash=%s）：%v",
				peerID, relayMsg.invVect.Hash, err)
			globalLog.Errorf(errMsg)
			// 记录不良行为，但不立即断开连接，避免误判
			netLayer.AdjustPeerScore(peerID, -10)
			return nil, err
		}
		bytes := protoRelayMsg.Data

		// 4. 根据消息类型处理
		switch relayMsg.invVect.Type {
		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			var protoMsgTx wire.ProtoMsgTx
			if err := proto.Unmarshal(bytes, &protoMsgTx); err != nil {
				globalLog.Infof("交易解析失败")
				return nil, nil
			}
			var msgTx core.MsgTx
			msgTx.FromProto(&protoMsgTx)
			srv.syncManager.OnTx(peerID, &msgTx)
		case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
			var protoMsgBlock wire.ProtoMsgBlock
			if err := proto.Unmarshal(bytes, &protoMsgBlock); err != nil {
				globalLog.Infof("区块解析失败")
				return nil, nil
			}
			var msgBlock core.MsgBlock
			msgBlock.FromProto(&protoMsgBlock)
			srv.syncManager.OnBlock(peerID, &msgBlock)
		default:
			errMsg := fmt.Sprintf("不支持的中继消息类型：%v（peer=%s）", relayMsg.invVect.Type, peerID)
			globalLog.Errorf(errMsg)
			return buildErrorResp(errMsg), errors.New(errMsg)
		}
		return nil, nil
	})
}

// 握手信息应该携带  节点类型 全节点 轻量级节点
func NewProtoHandshakeMsg(nonce uint64,
	lastBlockHeight int32, genesisHash []byte) *wire.ProtoHandshake {
	return &wire.ProtoHandshake{
		ProtocolVersion: int32(wire.ProtocolVersion),
		Services:        nil,
		Timestamp:       time.Now().Unix(),
		Nonce:           nonce,
		UserAgent:       "/bitcoin:1.0.0/",
		GenesisHash:     genesisHash,
		LastBlockHeight: lastBlockHeight,
		DisableRelayTx:  false,
	}
}

// 构建成功响应（结构化返回，便于 peer 解析）
func buildSuccessResp(message string) []byte {
	resp := wire.CommonResp{
		Code:    200,
		Message: message,
	}
	marshal, err := proto.Marshal(&resp)
	if err != nil {
		globalLog.Errorf("构建成功响应失败：%v", err)
		return []byte(`{"code":500,"message":"响应构建失败"}`) // 降级兜底
	}
	return marshal
}

func buildSuccessRespWithData(message string, data []byte) []byte {
	resp := wire.CommonResp{
		Code:    200,
		Message: message,
		Data:    data,
	}
	marshal, err := proto.Marshal(&resp)
	if err != nil {
		globalLog.Errorf("构建成功响应失败：%v", err)
		return []byte(`{"code":500,"message":"响应构建失败"}`) // 降级兜底
	}
	return marshal
}

// 构建错误响应
func buildErrorResp(message string) []byte {
	resp := wire.CommonResp{
		Code:    500,
		Message: message,
	}
	marshal, err := proto.Marshal(&resp)
	if err != nil {
		globalLog.Errorf("构建错误响应失败：%v", err)
		return []byte(`{"code":500,"message":"响应构建失败"}`) // 降级兜底
	}
	return marshal
}

// 将字符串地址转换为btcutil.Address切片
func convertMinerAddresses(netVersion string, strAddrs []string) ([]utils.Address, error) {
	if len(strAddrs) == 0 {
		return nil, errors.New("没有配置矿工地址")
	}
	// 根据网络版本获取对应的网络参数
	params, err := getNetParams(netVersion)
	if err != nil {
		return nil, err
	}
	// 转换每个地址
	addrs := make([]utils.Address, 0, len(strAddrs))
	for _, addrStr := range strAddrs {
		addr, err := utils.DecodeAddress(addrStr, params)
		if err != nil {
			return nil, fmt.Errorf("地址 %s 无效: %w", addrStr, err)
		}
		addrs = append(addrs, addr)

	}
	return addrs, nil
}

// 根据网络版本获取对应的chaincfg.Params
func getNetParams(netVersion string) (*core.Params, error) {
	switch netVersion {
	case "mainnet":
		return &core.MainNetParams, nil
	case "testnet3":
		return &core.TestNet3Params, nil
	case "testnet4":
		return &core.TestNet4Params, nil
	case "simnet":
		return &core.SimNetParams, nil
	case "regtest":
		return &core.RegressionNetParams, nil
	case "signet":
		return &core.SigNetParams, nil
	default:
		return nil, fmt.Errorf("不支持的网络版本: %s", netVersion)
	}
}

func getChaincfgNetParams(netVersion string) (*chaincfg.Params, error) {
	switch netVersion {
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("不支持的网络版本: %s", netVersion)
	}
}

func (s *server) AnnounceNewTransactions(txns []*mempool.TxDesc) {
	// Generate and relay inventory vectors for all newly accepted
	// transactions.
	s.relayTransactions(txns)
}

func (s *server) relayTransactions(txns []*mempool.TxDesc) {
	for _, txD := range txns {
		iv := wire.NewInvVect(wire.InvTypeTx, txD.Tx.Hash()) // 生成交易库存向量
		s.RelayInventory(iv, txD)                            // 广播
	}
}

// 这是统一入口，用于将 Inv 消息广播给所有符合条件的对等节点。
func (s *server) RelayInventory(invVect *wire.InvVect, data interface{}) {
	s.relayInv <- relayMsg{invVect: invVect, data: data}
}

func (s *server) UpdatePeerHeights(latestBlkHash *chainhash.Hash, latestHeight int32) {
	s.peerHeightsUpdate <- updatePeerHeightsMsg{
		newHash:   latestBlkHash,
		newHeight: latestHeight,
	}
}

func (s *server) TransactionConfirmed(tx *core.Tx) {
	// Rebroadcasting is only necessary when the RPC server is active.
	if s.rpc == nil {
		return
	}

	iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
	s.RemoveRebroadcastInventory(iv)
}

func (s *server) RemoveRebroadcastInventory(iv *wire.InvVect) {
	// Ignore if shutting down.
	if atomic.LoadInt32(&s.shutdown) != 0 {
		return
	}
	s.modifyRebroadcastInv <- broadcastInventoryDel(iv)
}

type broadcastInventoryDel *wire.InvVect

// 处理服务器的各种消息通道，包括relayInv和broadcast
func (s *server) MessageHandler() {
	defer s.wg.Done()

	// 确保通道已初始化
	if s.relayInv == nil {
		s.relayInv = make(chan relayMsg, 100)
	}
	if s.broadcast == nil {
		s.broadcast = make(chan broadcastMsg, 100)
	}

	for {
		select {
		case <-s.quit:
			// 收到退出信号，终止消息处理
			srvrLog.Info("消息处理器收到退出信号，正在停止")
			return
		case relayMsg := <-s.relayInv:
			// 处理库存中继消息
			s.handleRelayInv(relayMsg)
		case broadcastMsg := <-s.broadcast:
			// 处理广播消息
			s.handleBroadcast(broadcastMsg)
		case updateMsg := <-s.peerHeightsUpdate:
			// 处理节点高度更新（已有的通道处理）
			s.handlePeerHeightsUpdate(updateMsg)
		case msg := <-s.modifyRebroadcastInv:
			// 处理重新广播库存修改（已有的通道处理）
			s.handleModifyRebroadcastInv(msg)
		}
	}
}

// 处理节点高度更新（已有功能，保持完整）
func (s *server) handlePeerHeightsUpdate(msg updatePeerHeightsMsg) {
	// 实现节点高度更新逻辑
	srvrLog.Debugf("更新节点高度: %s, 新高度: %d", msg.newHash, msg.newHeight)
	// 实际实现中应更新节点状态并考虑重新同步等逻辑
}

// 处理库存中继消息，将库存向量发送给合适的节点
func (s *server) handleRelayInv(msg relayMsg) {
	srvrLog.Infof("handleRelayInv..........................")
	invProto := msg.invVect.ToProto()
	binaryData, err := proto.Marshal(invProto)
	if err != nil {
		srvrLog.Errorf("序列化protobuf消息失败: %v", err)
		return
	}
	reqData := network.PersistentPeer{
		IsOnline:        true,
		HandshakeStatus: wire.HandshakeStatus_HANDSHAKE_COMPLETED,
	}
	onlinePeer, _ := s.network.GetPeerByCondition(reqData)
	globalLog.Infof("将消息发送给目标节点%d", len(onlinePeer))
	for _, peer := range onlinePeer {
		if s.shouldRelayToPeer(&peer, msg.invVect, msg.data) {
			// 假设network层有发送数据的方法
			go s.network.Send(peer.ID, network.InventoryProtocol, binaryData)
		}
	}
}

// handleBroadcast 处理广播消息，将消息发送给所有符合条件的节点（排除指定节点）
func (s *server) handleBroadcast(msg broadcastMsg) {
	srvrLog.Infof("handleBroadcast..........................")
}

// 辅助函数：判断是否应该向节点中继指定库存
func (s *server) shouldRelayToPeer(peer *network.PersistentPeer, invVect *wire.InvVect, data interface{}) bool {
	// 对于交易，检查节点的手续费过滤设置
	if invVect.Type == wire.InvTypeTx {
		if tx, ok := data.(*core.Tx); ok {
			// 计算交易的手续费率
			feeRate := calculateFeeRate(tx)
			// 如果节点设置了手续费过滤且交易费率低于过滤值，则不中继
			if peer.FeeFilter > 0 && feeRate < peer.FeeFilter {
				return false
			}
		}
	}
	// 可以添加更多过滤逻辑，如节点是否已经拥有此库存等
	return true
}

// 辅助函数：计算交易的手续费率
func calculateFeeRate(tx *core.Tx) int64 {
	return 1000 // 默认1000 sat/byte
}

// 处理重新广播库存修改（已有功能，保持完整）
func (s *server) handleModifyRebroadcastInv(msg interface{}) {
	switch m := msg.(type) {
	case broadcastInventoryDel:
		srvrLog.Debugf("移除重新广播库存: %s", m.Hash)
		// 实际实现中应从重新广播列表中移除指定库存
	default:
		srvrLog.Errorf("未知的重新广播库存修改类型: %T", msg)
	}
}

// 将relayMsg转换为protobuf结构体ProtoRelayMsg
func (rm *relayMsg) toProto() (*wire.ProtoRelayMsg, error) {
	if rm == nil {
		return nil, errors.New("relayMsg is nil")
	}

	// 转换invVect字段
	var pbInvVect *wire.ProtoInvVect
	if rm.invVect != nil {
		pbInvVect = rm.invVect.ToProto()
	} else {
		return nil, errors.New("invVect cannot be nil")
	}

	/*	var dataBytes []byte
		var err error

		switch d := rm.data.(type) {
		case *core.MsgBlock:
			blockProto := d.ToProto()
			dataBytes, err = proto.Marshal(blockProto)
		case *core.MsgTx:
			txProto := d.ToProto()
			dataBytes, err = proto.Marshal(txProto)
		case *core.BlockHeader:
			blockHeaderProto := d.ToProto()
			dataBytes, err = proto.Marshal(blockHeaderProto)
		case core.BlockHeader:
			blockHeaderProto := d.ToProto()
			dataBytes, err = proto.Marshal(blockHeaderProto)
		default:
			return nil, fmt.Errorf("unsupported data type for serialization: %T", d)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to serialize data: %w", err)
		}*/

	return &wire.ProtoRelayMsg{
		InvVect: pbInvVect,
		//Data:    dataBytes,中继续消息不携带数据
	}, nil
}

// 从protobuf结构体ProtoRelayMsg转换回relayMsg
func (rm *relayMsg) fromProto(pb *wire.ProtoRelayMsg) error {
	if pb == nil {
		return errors.New("ProtoRelayMsg is nil")
	}

	// 确保relayMsg实例已初始化
	if rm == nil {
		return errors.New("relayMsg instance is nil")
	}

	// 转换invVect字段
	rm.invVect = &wire.InvVect{}
	rm.invVect.FromProto(pb.InvVect)

	/*	// 检查数据是否存在
		if len(pb.Data) == 0 {
			return errors.New("no data found in ProtoRelayMsg")
		}
		// 根据invVect类型反序列化data字段
		switch rm.invVect.Type {
		case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
			block := &core.MsgBlock{}
			blockProto := &wire.ProtoMsgBlock{}

			// 先反序列化为ProtoMsgBlock
			if err := proto.Unmarshal(pb.Data, blockProto); err != nil {
				return fmt.Errorf("failed to unmarshal block data: %w", err)
			}

			// 再转换为MsgBlock
			block.FromProto(blockProto)
			rm.data = block

		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			tx := &core.MsgTx{}
			txProto := &wire.ProtoMsgTx{}

			// 先反序列化为ProtoMsgTx
			if err := proto.Unmarshal(pb.Data, txProto); err != nil {
				return fmt.Errorf("failed to unmarshal transaction data: %w", err)
			}

			// 再转换为MsgTx
			tx.FromProto(txProto)
			rm.data = tx
		default:
			return fmt.Errorf("unsupported inventory type: %v", rm.invVect.Type)
		}*/
	return nil
}

// 验证中继消息的基本有效性
func validateRelayMsg(rm *relayMsg) error {
	if rm == nil {
		return errors.New("relayMsg为空")
	}
	if rm.invVect == nil {
		return errors.New("invVect为空")
	}
	if rm.invVect.Hash.IsEqual(&chainhash.Hash{}) {
		return errors.New("无效的哈希值")
	}
	/*	if rm.data == nil {
		return errors.New("数据部分为空")
	}*/
	// 检查类型匹配
	/*	switch rm.invVect.Type {
		case wire.InvTypeTx, wire.InvTypeWitnessTx:
			if _, ok := rm.data.(*core.MsgTx); !ok {
				return errors.New("消息类型与数据不匹配，期望交易数据")
			}
		case wire.InvTypeBlock, wire.InvTypeWitnessBlock:
			if _, ok := rm.data.(*core.MsgBlock); !ok {
				return errors.New("消息类型与数据不匹配，期望区块数据")
			}
		default:
			return fmt.Errorf("不支持的消息类型: %v", rm.invVect.Type)
		}*/
	return nil
}

// 判断是否应该向指定节点中继消息
func shouldRelayToPeer(peer network.PersistentPeer, rm *relayMsg) bool {
	// 对于交易，检查节点的手续费过滤设置
	if rm.invVect.Type == wire.InvTypeTx || rm.invVect.Type == wire.InvTypeWitnessTx {
		if tx, ok := rm.data.(*core.MsgTx); ok {
			// 计算交易的手续费率
			newTx := core.NewTx(tx)
			feeRate := calculateFeeRate(newTx)
			// 如果节点设置了手续费过滤且交易费率低于过滤值，则不中继
			if peer.FeeFilter > 0 && feeRate < peer.FeeFilter {
				globalLog.Debugf("交易手续费率 %d 低于节点 %s 的过滤值 %d，不中继",
					feeRate, peer.ID, peer.FeeFilter)
				return false
			}
		}
	}
	// 检查节点是否已经拥有此数据
	// 检查节点服务类型是否支持该数据类型
	return true
}

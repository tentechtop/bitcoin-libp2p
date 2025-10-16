package main

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	pebble "bitcoin/db/pebblev2"
	"bitcoin/event"
	"bitcoin/mining"
	"flag"
	"fmt"
	"time"

	"log"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"runtime/trace"
)

var (
	cfg *Config
)

func btcMain(serverChan chan<- *server) error {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "配置文件路径（可选，省略则自动查找 btc.yml）")
	flag.StringVar(&cfgPath, "c", "", "配置文件路径（-config 的简写）")
	flag.Parse()
	cfg, err := loadConfigFile(cfgPath)
	if err != nil {
		log.Fatalf("无法加载 btc.yml: %v", err)
	}
	globalLog.Infof("配置读取成功")
	defer func() {
		if logRotator != nil {
			btcdLog.Infof("退出时关闭日志")
			logRotator.Close()
		}
	}()
	interrupt := interruptListener()
	defer btcdLog.Info("Shutdown complete")

	store, err := pebble.New(cfg.Bitcoin.DataDir + "/" + cfg.Bitcoin.NetVersion)
	if err != nil {
		panic(err)
	}

	//初始化创世区块
	//创世交易 创世区块生成时间  创世交易版本  创世难度1   填充到

	if cfg.Bitcoin.CpuProfile != "" {
		f, err := os.Create(cfg.Bitcoin.CpuProfile)
		if err != nil {
			btcdLog.Errorf("Unable to create cpu profile: %v", err)
			return err
		}
		pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	if cfg.Bitcoin.MemoryProfile != "" {
		f, err := os.Create(cfg.Bitcoin.MemoryProfile)
		if err != nil {
			btcdLog.Errorf("Unable to create memory profile: %v", err)
			return err
		}
		defer f.Close()
		defer pprof.WriteHeapProfile(f)
		defer runtime.GC()
	}

	if cfg.Bitcoin.TraceProfile != "" {
		f, err := os.Create(cfg.Bitcoin.TraceProfile)
		if err != nil {
			btcdLog.Errorf("Unable to create execution trace: %v", err)
			return err
		}
		trace.Start(f)
		defer f.Close()
		defer trace.Stop()
	}

	if interruptRequested(interrupt) {
		return nil
	}
	bus := event.New()

	//
	version := cfg.Bitcoin.NetVersion

	// 建立 NetVersion 与网络参数的映射
	netParamsMap := map[string]*params{
		"mainnet":  &mainNetParams,
		"testnet3": &testNet3Params,
		"testnet4": &testNet4Params,
		"regtest":  &regressionNetParams,
		"simnet":   &simNetParams,
		"signet":   &sigNetParams,
	}

	// 根据 NetVersion 选择对应的参数
	selectedParams, exists := netParamsMap[version]
	if !exists {
		return fmt.Errorf("不支持的网络版本: %s", version)
	}
	activeNetParams = selectedParams // 更新激活的参数
	btcdLog.Infof("已激活网络: %s", version)

	//秒级时间
	activeNetParams.TargetTimePerBlock = time.Duration(cfg.Bitcoin.BlockGenerationTime) * time.Second
	activeNetParams.HalvingPeriod = cfg.Bitcoin.HalvingPeriod
	compact := blockchain.BigToCompact(blockchain.HexToBig(cfg.Bitcoin.InitDifficultyTarget))
	activeNetParams.PowLimitBits = compact
	activeNetParams.GenesisBlock.Header.Bits = compact

	msgBlock := activeNetParams.GenesisBlock
	block := core.NewBlock(msgBlock)
	calcMerkleRoot := blockchain.CalcMerkleRoot(block.Transactions(), false)
	activeNetParams.GenesisBlock.Header.MerkleRoot = calcMerkleRoot

	// -------------------------- 新增：计算创世区块Nonce --------------------------
	// 1. 复制创世区块头（避免直接修改原对象）
	genesisHeader := activeNetParams.GenesisBlock.Header
	// 2. 解析难度目标（由配置的InitDifficultyTarget转换而来的PowLimitBits）
	target := blockchain.CompactToBig(activeNetParams.PowLimitBits)
	btcdLog.Infof("开始计算创世区块Nonce，难度目标: %x", target.Bytes())
	var foundNonce bool
	// 3. 暴力枚举Nonce（从0到uint32最大值）
	for nonce := uint32(0); nonce <= mining.MaxNonce; nonce++ {
		// 每枚举1000万次打印一次进度（可选，便于调试）
		if nonce%10000000 == 0 && nonce != 0 {
			btcdLog.Debugf("创世区块Nonce枚举进度: %d/%d", nonce, mining.MaxNonce)
		}

		// 更新当前Nonce到区块头
		genesisHeader.Nonce = nonce

		// 4. 计算当前区块头的哈希
		blockHash := genesisHeader.BlockHash()

		// 5. 校验哈希是否满足难度目标（哈希转大整数 <= 难度目标）
		if blockchain.HashToBig(&blockHash).Cmp(target) <= 0 {
			// 找到有效Nonce，更新创世区块
			activeNetParams.GenesisBlock.Header.Nonce = nonce
			activeNetParams.GenesisHash = &blockHash
			foundNonce = true
			btcdLog.Infof("创世区块Nonce计算成功！Nonce: %d, 区块哈希: %s", nonce, blockHash.String())
			break
		}
	}

	// 6. 异常处理：若未找到有效Nonce（难度目标过高）
	if !foundNonce {
		err := fmt.Errorf("枚举所有Nonce(%d)未找到满足难度目标的创世区块", mining.MaxNonce)
		btcdLog.Error(err.Error())
		return err
	}

	server, err := newServer(cfg, store, bus, activeNetParams.Params, interrupt)
	if err != nil {
		return err
	}
	defer func() {
		btcdLog.Infof("Gracefully shutting down the server...")
		server.Stop()
		server.WaitForShutdown()
		srvrLog.Infof("Server shutdown complete")
	}()
	server.Start()
	btcdLog.Infof("组件全部启动完成")
	if serverChan != nil {
		serverChan <- server
	}
	<-interrupt
	return nil
}

func main() {

	// 配置GC（垃圾回收）：未显式设置GOGC时，将GC阈值设为10%（优化区块/交易处理的突发内存分配）
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(10)
	}

	// 核心逻辑委托给btcdMain（规避Go中defer在os.Exit时不执行的问题）
	if err := btcMain(nil); err != nil {
		os.Exit(1)
	}
	/*
		ctx := context.Background()

		// 配置网络层
		config := network.Config{
			ListenPort:     4001,
			DataDir:        "./chaindata/network",
			BootstrapPeers: []string{}, // 启动节点地址
			ProtocolPrefix: "/myblockchain",
			EnableQUIC:     true,
			EnableMDNS:     true,
			Logger:         log.Default(),
		}

		fmt.Printf("chaincfg.Bus 地址: %p\n", config.Bus) // 如果这里已经是 0，说明传错对象
		// 创建网络层实例
		netLayer, err := network.NewNetworkLayer(ctx, config)
		if err != nil {
			log.Fatalf("创建网络层失败: %v", err)
		}
		defer netLayer.Stop()
		// 启动网络层
		if err := netLayer.Start(); err != nil {
			log.Fatalf("启动网络层失败: %v", err)
		}
		// 打印节点信息
		fmt.Printf("节点ID: %s\n", netLayer.SelfID())
		fmt.Println("节点地址:")
		for _, addr := range netLayer.SelfAddrs() {
			fmt.Printf("  %s/p2p/%s\n", addr, netLayer.SelfID())
		}
		// 等待退出信号
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("开始退出...")

		if err := netLayer.Stop(); err != nil {
			log.Printf("停止网络层失败: %v", err)
		}

		fmt.Println("程序已安全退出")

		defer func() {
			if logRotator != nil {
				btcdLog.Infof("退出时关闭日志")
				logRotator.Close()
			}
		}()
		globalLog.Infof("启动比特币")*/
}

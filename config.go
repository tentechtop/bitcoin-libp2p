package main

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"time"
)

var runServiceCommand func(string) error

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

const (
	defaultDataDirname          = "data"
	defaultLogLevel             = "info"
	defaultLogDirname           = "logs"
	defaultLogFilename          = "btc.log"
	defaultMaxPeers             = 125
	defaultBanDuration          = time.Hour * 24
	defaultBanThreshold         = 100
	defaultConnectTimeout       = time.Second * 30
	defaultMaxRPCClients        = 10
	defaultMaxRPCWebsockets     = 25
	defaultMaxRPCConcurrentReqs = 20
	defaultDbType               = "ffldb"
	defaultFreeTxRelayLimit     = 15.0

	defaultBlockMinSize          = 0
	defaultBlockMaxSize          = 750000
	defaultBlockMinWeight        = 0
	defaultBlockMaxWeight        = 3000000
	blockMaxSizeMin              = 1000
	blockMaxWeightMin            = 4000
	defaultGenerate              = false
	defaultMaxOrphanTransactions = 100
	defaultMaxOrphanTxSize       = 100000
	defaultSigCacheMaxSize       = 100000
	defaultUtxoCacheMaxSizeMiB   = 250
	defaultTxIndex               = false
	defaultAddrIndex             = false
	pruneMinSize                 = 1536
)

type Config struct {
	Bitcoin struct {
		NetVersion     string   `mapstructure:"netVersion"`
		PeerPort       int      `mapstructure:"peerPort"`
		RPCPort        string   `mapstructure:"rpcPort"`
		DebugPort      int      `mapstructure:"debugPort"`
		EnableQUIC     bool     `mapstructure:"enable_quic"`
		EnableMDNS     bool     `mapstructure:"enable_mdns"`
		BootstrapPeers []string `mapstructure:"bootstrap_peers"`
		DataDir        string   `mapstructure:"dataDir"`
		LogDir         string   `mapstructure:"logDir"`
		Whitelists     []string `mapstructure:"whitelists"`
		DisableBanning bool     `mapstructure:"disableBanning"`
		BanDuration    string   `mapstructure:"banDuration"`
		BanThreshold   int      `mapstructure:"banThreshold"`
		MaxOrphanTxs   int      `mapstructure:"maxOrphanTxs"`
		Proxy          struct {
			Enable    bool   `mapstructure:"enable"`
			ProxyUser string `mapstructure:"proxyUser"`
			ProxyPass string `mapstructure:"proxyPass"`
		} `mapstructure:"proxy"`
		Prune                bool   `mapstructure:"prune"`
		UTXOCacheMaxSizeMiB  int    `mapstructure:"utxoCacheMaxSizeMiB"`
		SigCacheMaxSize      uint   `mapstructure:"sigCacheMaxSize"`
		RPCMaxClients        int    `mapstructure:"RPCMaxClients"`
		RPCMaxConcurrentReqs int    `mapstructure:"RPCMaxConcurrentReqs"`
		CpuProfile           string `mapstructure:"cpuProfile"`
		MemoryProfile        string `mapstructure:"memoryProfile"`
		TraceProfile         string `mapstructure:"traceProfile"`
		AddrIndex            bool   `mapstructure:"addrIndex"`
		TxIndex              bool   `mapstructure:"txIndex"`
		DropAddrIndex        bool   `mapstructure:"dropAddrIndex"`
		DropTxIndex          bool   `mapstructure:"dropTxIndex"`
		InitDifficultyTarget string `mapstructure:"initDifficultyTarget"`
		AdjustmentInterval   int    `mapstructure:"adjustmentInterval"`
		BlockGenerationTime  int32  `mapstructure:"blockGenerationTime"`
		HalvingPeriod        int32  `mapstructure:"halvingPeriod"`
		BlockMinWeight       uint32 `mapstructure:"blockMinWeight"`
		BlockMaxWeight       uint32 `mapstructure:"blockMaxWeight"`

		BlockMinSize uint32 `mapstructure:"blockMinSize"`
		BlockMaxSize uint32 `mapstructure:"blockMaxSize"`

		BlockPrioritySize uint32 `mapstructure:"blockPrioritySize"`
		MinRelayTxFee     int64  `mapstructure:"minRelayTxFee"`

		NoRelayPriority   bool    `mapstructure:"noRelayPriority"`
		RelayNonStd       bool    `mapstructure:"relayNonStd"`
		FreeTxRelayLimit  float64 `mapstructure:"freeTxRelayLimit"`
		RejectReplacement bool    `mapstructure:"rejectReplacement"`
	} `mapstructure:"bitcoin"`

	Mining struct {
		StartMining bool `mapstructure:"startMining"`
		MiningType  int  `mapstructure:"miningType"`
		Miner       struct {
			MinerAddress []string `mapstructure:"minerAddress"`
			MergeTxOut   bool     `mapstructure:"mergeTxOut"`
		} `mapstructure:"miner"`
	} `mapstructure:"mining"`

	Chain struct {
		DisableCheckpoints bool     `mapstructure:"disableCheckpoints"`
		AddCheckpoints     []string `mapstructure:"addCheckpoints"`
	} `mapstructure:"chain"`
}

//使用默认 btc.yml
//指定任意 yml
//./yourapp -c /path/to/xxx.yml
//# 或
//./yourapp --config ./dev.yml

// 统一加载配置入口
// 1. 如果传了文件路径，直接读该文件
// 2. 如果没传，在 “可执行文件目录 -> 当前目录” 中查找 btc.yml
func loadConfigFile(configFile string) (*Config, error) {
	v := viper.New()

	if configFile != "" {
		// 用户显式指定了文件
		v.SetConfigFile(configFile)
	} else {
		// 默认策略：先找 exe 同目录，再找当前目录
		baseDir := "."
		exe, err := os.Executable()
		if err != nil {
			// 失败时使用当前目录作为备选
			baseDir = "."
		} else {
			baseDir = filepath.Dir(exe)
		}
		v.SetConfigName("btc")
		v.SetConfigType("yml")
		v.AddConfigPath(baseDir)
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	return &cfg, nil
}

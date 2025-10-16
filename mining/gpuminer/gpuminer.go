package gpuminer

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	"bitcoin/mining"
	"bitcoin/utils"
	"runtime"
	"sync"
)

type Config struct {
	ChainParams            *core.Params
	BlockTemplateGenerator *mining.BlkTmplGenerator
	MiningAddrs            []utils.Address
	ProcessBlock           func(*core.Block, blockchain.BehaviorFlags) (bool, error)
	ConnectedCount         func() int32
	IsCurrent              func() bool
}

var (
	defaultNumWorkers = uint32(runtime.NumCPU())
)

type GPUMiner struct {
	sync.Mutex
	g                 *mining.BlkTmplGenerator
	cfg               Config
	numWorkers        uint32
	started           bool
	discreteMining    bool
	submitBlockLock   sync.Mutex
	wg                sync.WaitGroup
	workerWg          sync.WaitGroup
	updateNumWorkers  chan struct{}
	queryHashesPerSec chan float64
	updateHashes      chan uint64
	speedMonitorQuit  chan struct{}
	quit              chan struct{}
}

func New(cfg *Config) *GPUMiner {
	return &GPUMiner{
		g:                 cfg.BlockTemplateGenerator,
		cfg:               *cfg,
		numWorkers:        defaultNumWorkers,
		updateNumWorkers:  make(chan struct{}),
		queryHashesPerSec: make(chan float64),
		updateHashes:      make(chan uint64),
	}
}

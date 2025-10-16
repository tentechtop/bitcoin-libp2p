package main

import (
	"bitcoin/blockchain"
	"bitcoin/blockchain/indexers"
	"bitcoin/mempool"
	"bitcoin/mining"
	"bitcoin/mining/cpuminer"
	"bitcoin/mining/gpuminer"
	"bitcoin/netsync"
	"bitcoin/network"
	"fmt"
	"os"
	"path/filepath"

	"bitcoin/btclog"
	"github.com/jrick/logrotate/rotator"
)

type logWriter struct{}

func (logWriter) Write(p []byte) (n int, err error) {
	// 先写标准输出（确保日志不丢失）
	stdoutN, stdoutErr := os.Stdout.Write(p)
	if stdoutErr != nil {
		return stdoutN, stdoutErr
	}

	// 若 logRotator 已初始化，再写文件（避免 nil 指针）
	if logRotator != nil {
		rotatorN, rotatorErr := logRotator.Write(p)
		// 取最大写入长度，优先返回文件写入错误（若有）
		if rotatorErr != nil {
			return rotatorN, rotatorErr
		}
	}

	return len(p), nil
}

// Loggers per subsystem.  A single backend logger is created and all subsystem
// loggers created from it will write to the backend.  When adding new
// subsystems, add the subsystem logger variable here and to the
// subsystemLoggers map.
//
// Loggers can not be used before the log rotator has been initialized with a
// log file.  This must be performed early during application startup by calling
// initLogRotator.
var (
	// backendLog is the logging backend used to create all subsystem loggers.
	// The backend must not be used before the log rotator has been initialized,
	// or data races and/or nil pointer dereferences will occur.
	backendLog = btclog.NewBackend(logWriter{})

	// logRotator is one of the logging outputs.  It should be closed on
	// application shutdown.
	logRotator *rotator.Rotator

	adxrLog = backendLog.Logger("ADXR")
	amgrLog = backendLog.Logger("AMGR")
	cmgrLog = backendLog.Logger("CMGR")
	bcdbLog = backendLog.Logger("BCDB")
	btcdLog = backendLog.Logger("BTC")
	chanLog = backendLog.Logger("CHAN")
	discLog = backendLog.Logger("DISC")
	indxLog = backendLog.Logger("INDX")
	minrLog = backendLog.Logger("MINR")
	peerLog = backendLog.Logger("PEER")
	rpcsLog = backendLog.Logger("RPCS")
	scrpLog = backendLog.Logger("SCRP")
	srvrLog = backendLog.Logger("SRVR")
	syncLog = backendLog.Logger("SYNC")
	txmpLog = backendLog.Logger("TXMP")
	netLog  = backendLog.Logger("NET")

	// 新增：通用日志（全局可用，标识为 "GLOBAL"）
	globalLog = backendLog.Logger("GLOBAL")
)

// Initialize package-global logger variables.
func init() {
	mining.UseLogger(minrLog)
	cpuminer.UseLogger(minrLog)
	gpuminer.UseLogger(minrLog)
	netsync.UseLogger(syncLog)
	blockchain.UseLogger(chanLog)
	mempool.UseLogger(txmpLog)
	network.UseLogger(netLog)
	indexers.UseLogger(indxLog)
}

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]btclog.Logger{
	"ADXR": adxrLog,
	"AMGR": amgrLog,
	"CMGR": cmgrLog,
	"BCDB": bcdbLog,
	"BTCD": btcdLog,
	"CHAN": chanLog,
	"DISC": discLog,
	"INDX": indxLog,
	"MINR": minrLog,
	"PEER": peerLog,
	"RPCS": rpcsLog,
	"SCRP": scrpLog,
	"SRVR": srvrLog,
	"SYNC": syncLog,
	"TXMP": txmpLog,
	// 新增：通用日志加入映射
	"GLOBAL": globalLog,
	"NET":    netLog,
}

// initLogRotator initializes the logging rotater to write logs to logFile and
// create roll files in the same directory.  It must be called before the
// package-global log rotater variables are used.
func initLogRotator(logFile string) {
	logDir, _ := filepath.Split(logFile)
	err := os.MkdirAll(logDir, 0700)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create log directory: %v\n", err)
		os.Exit(1)
	}
	r, err := rotator.New(logFile, 10*1024, false, 3)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create file rotator: %v\n", err)
		os.Exit(1)
	}

	logRotator = r
}

// setLogLevel sets the logging level for provided subsystem.  Invalid
// subsystems are ignored.  Uninitialized subsystems are dynamically created as
// needed.
func setLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems.
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Defaults to info if the log level is invalid.
	level, _ := btclog.LevelFromString(logLevel)
	logger.SetLevel(level)
}

// setLogLevels sets the log level for all subsystem loggers to the passed
// level.  It also dynamically creates the subsystem loggers as needed, so it
// can be used to initialize the logging system.
func setLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level.  Dynamically
	// create loggers as needed.
	for subsystemID := range subsystemLoggers {
		setLogLevel(subsystemID, logLevel)
	}
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}

// pickNoun returns the singular or plural form of a noun depending
// on the count n.
func pickNoun(n uint64, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

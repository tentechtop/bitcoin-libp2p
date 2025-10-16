package main

import (
	"bitcoin/blockchain"
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
	"bitcoin/network"
	"bitcoin/rpc"
	"bitcoin/txscript"
	"bitcoin/utils"
	"bitcoin/wallet"
	pb "bitcoin/wire"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	"log"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type NodeServer struct {
	pb.UnimplementedBitCoinRpcServer
	srv        *server      // 持有核心服务器实例
	rpcServer  *grpc.Server // gRPC服务器实例
	rpcLis     net.Listener // gRPC监听句柄
	listenAddr string       // 监听地址
	isRunning  int32        // 原子标记服务是否运行中
}

func (s *NodeServer) GetCachaeUTXO(ctx context.Context, req *pb.GetAddressAllUtxoRequest) (*pb.UtxoList, error) {
	cache := s.srv.chain.GetUtxoCache()
	allUTXO := cache.GetAllUTXOs()
	// 3. 打印查询结果数量，便于调试与监控
	utxoCount := len(allUTXO)
	// 4. 初始化Proto格式UTXO切片（预分配容量优化性能）
	pbAllUTXO := make([]*pb.ProtoUtxoEntry, 0, utxoCount)
	var totalBalance int64 // 用于统计总余额，使用uint64避免溢出
	// 5. 循环转换UTXO格式（核心逻辑）
	for idx, utxo := range allUTXO {
		// 调用core层UTXO的ToProto()方法转换格式，**必须处理错误**
		protoUtxo, err := utxo.ToProto()
		if err != nil {
			// 记录错误详情（包含索引和UTXO简要信息），便于定位问题
			globalLog.Errorf("UTXO转换为Proto格式失败，索引：%d，错误：%v，UTXO信息：%+v", idx, err, utxo)
			// 单个UTXO转换失败不中断整体请求，跳过无效数据
			continue
		}
		// 转换成功：将Proto格式UTXO添加到结果切片
		pbAllUTXO = append(pbAllUTXO, protoUtxo)
		// 累加余额（假设ProtoUtxoEntry中有Amount字段表示金额）
		totalBalance += protoUtxo.Amount
	}
	return &pb.UtxoList{
		Utxos:        pbAllUTXO,
		TotalCount:   int32(utxoCount),
		TotalBalance: totalBalance,
	}, nil
}

func (s *NodeServer) GetUTXOByAddressAndCache(ctx context.Context, req *pb.GetAddressAllUtxoRequest) (*pb.UtxoList, error) {
	allUTXO, err := s.srv.chain.GetAddressAllUTXO(req.Address)
	if err != nil {
		// 修正错误日志：将"区块"改为"UTXO"，避免误导
		globalLog.Errorf("查询全部UTXO失败：%v", err)
		// 修正返回错误信息：与日志和业务逻辑对齐
		return nil, status.Errorf(500, "获取UTXO列表失败：%v", err)
	}
	// 3. 打印查询结果数量，便于调试与监控
	utxoCount := len(allUTXO)
	globalLog.Infof("查询到 %d 个UTXO", utxoCount)
	globalLog.Infof("查询到 %d ", allUTXO)
	// 4. 初始化Proto格式UTXO切片（预分配容量优化性能）
	pbAllUTXO := make([]*pb.ProtoUtxoEntry, 0, utxoCount)
	var totalBalance int64 // 用于统计总余额，使用uint64避免溢出
	// 5. 循环转换UTXO格式（核心逻辑）
	for idx, utxo := range allUTXO {
		// 调用core层UTXO的ToProto()方法转换格式，**必须处理错误**
		protoUtxo, err := utxo.ToProto()
		if err != nil {
			// 记录错误详情（包含索引和UTXO简要信息），便于定位问题
			globalLog.Errorf("UTXO转换为Proto格式失败，索引：%d，错误：%v，UTXO信息：%+v", idx, err, utxo)
			// 单个UTXO转换失败不中断整体请求，跳过无效数据
			continue
		}

		// 转换成功：将Proto格式UTXO添加到结果切片
		pbAllUTXO = append(pbAllUTXO, protoUtxo)

		// 累加余额（假设ProtoUtxoEntry中有Amount字段表示金额）
		totalBalance += protoUtxo.Amount
	}

	address := req.GetAddress()
	netParams, err := getNetParams(s.srv.cfg.Bitcoin.NetVersion)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}
	targetAddr, err := utils.DecodeAddress(address, netParams)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败：%v", err)
	}
	unconfirmedTxs := s.srv.addrIndex.UnconfirmedTxnsForAddress(targetAddr)
	//提取出未确认的
	for _, txid := range unconfirmedTxs {

		for _, vout := range txid.MsgTx().TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(vout.PkScript, netParams)
			if err != nil || len(addrs) == 0 {
				continue
			}
			// 检查是否匹配目标地址
			matches := false
			for _, addr := range addrs {
				if addr.EncodeAddress() == targetAddr.EncodeAddress() {
					matches = true
					break
				}
			}
			if !matches {
				continue
			}
			/*		// 检查该输出是否被其他未确认交易花费
					currentOutPoint := core.OutPoint{
						Hash:  txID,
						Index: uint32(voutIdx),
					}*/
			entry := blockchain.NewUtxoEntry(vout, -1, false)
			proto, _ := entry.ToProto()
			pbAllUTXO = append(pbAllUTXO, proto)
		}
	}

	// 返回包含结果的响应
	return &pb.UtxoList{
		Utxos:        pbAllUTXO,
		TotalCount:   int32(utxoCount),
		TotalBalance: totalBalance,
	}, nil
}

func (s *NodeServer) GetAllPeer(ctx context.Context, req *pb.GetPeerReq) (*pb.GetPeerRes, error) {
	matchedPeers, err := s.srv.network.GetAllPeer()
	if err != nil {
		return nil, fmt.Errorf("查询失败: %v", err)
	}

	// 将结果转换为protobuf格式
	peerList := make([]*pb.ProtoPersistentPeer, 0, len(matchedPeers))
	for _, peer := range matchedPeers {
		protoPeer := peer.ToProto()
		peerList = append(peerList, protoPeer)
	}

	// 返回包含结果的响应
	return &pb.GetPeerRes{
		PeerList: peerList,
	}, nil
}

func (s *NodeServer) GetPeerByCondition(ctx context.Context, req *pb.ProtoPersistentPeer) (*pb.GetPeerRes, error) {
	var persistentPeer network.PersistentPeer
	// 将protobuf请求转换为内部PersistentPeer结构
	persistentPeer.FromProto(req)

	// 调用network层方法获取符合条件的节点
	matchedPeers, err := s.srv.network.GetPeerByCondition(persistentPeer)
	if err != nil {
		return nil, fmt.Errorf("查询失败: %v", err)
	}
	globalLog.Infof("当前查询%d", len(matchedPeers))

	// 将结果转换为protobuf格式
	peerList := make([]*pb.ProtoPersistentPeer, 0, len(matchedPeers))
	for _, peer := range matchedPeers {
		protoPeer := peer.ToProto()
		peerList = append(peerList, protoPeer)
	}

	// 返回包含结果的响应
	return &pb.GetPeerRes{
		PeerList: peerList,
	}, nil
}

func (s *NodeServer) GetPeerById(ctx context.Context, req *pb.GetPeerReq) (*pb.GetPeerRes, error) {
	// 检查请求中的节点ID是否为空
	if req.ID == "" {
		return nil, fmt.Errorf("节点ID不能为空")
	}

	// 通过网络层获取指定ID的已连接节点信息
	peerInfo, err := s.srv.network.GetConnectedPeerById(req.ID)
	if err != nil {
		// 节点未找到或未连接时，返回空列表而不是错误，便于前端处理
		return &pb.GetPeerRes{PeerList: []*pb.ProtoPersistentPeer{}}, nil
	}

	// 查询该节点的持久化信息
	persistentPeer, err := s.srv.network.QueryPersistentPeer(req.ID)
	if err != nil {
		// 如果查询持久化信息失败，创建一个基础的节点信息
		handshakeStatus := pb.HandshakeStatus_HANDSHAKE_NOT_STARTED
		handshaked := s.srv.network.IsPeerHandshaked(req.ID)
		if handshaked {
			handshakeStatus = pb.HandshakeStatus_HANDSHAKE_COMPLETED
		}

		persistentPeer = network.PersistentPeer{
			ID: peerInfo.ID,
			Addrs: func() []string {
				var addrs []string
				for _, addr := range peerInfo.Addrs {
					addrs = append(addrs, addr.String())
				}
				return addrs
			}(),
			LastSeen:        time.Now().Unix(),
			HandshakeStatus: handshakeStatus,
			IsOnline:        s.srv.network.IsOnline(req.ID),
		}
	}

	// 转换为protobuf响应格式
	protoPeer := persistentPeer.ToProto()
	return &pb.GetPeerRes{
		PeerList: []*pb.ProtoPersistentPeer{protoPeer},
	}, nil
}

func (s *NodeServer) GetOnlineAndHandshakePeer(ctx context.Context, req *pb.GetPeerReq) (*pb.GetPeerRes, error) {
	// 获取所有已连接的在线节点
	onlinePeers := s.srv.network.ConnectedPeers()
	if len(onlinePeers) == 0 {
		return &pb.GetPeerRes{PeerList: []*pb.ProtoPersistentPeer{}}, nil
	}

	// 筛选出已完成握手的节点
	var handshakePeers []network.PersistentPeer
	for _, peer := range onlinePeers {
		// 检查节点是否已握手
		if s.srv.network.IsPeerHandshaked(peer.ID) {
			// 获取该节点的详细持久化信息
			persistentPeer, err := s.srv.network.QueryPersistentPeer(peer.ID)
			persistentPeer.HandshakeStatus = pb.HandshakeStatus_HANDSHAKE_COMPLETED
			persistentPeer.IsOnline = true
			if err == nil {
				handshakePeers = append(handshakePeers, persistentPeer)
			} else {
				// 如果查询失败，至少添加基本信息
				handshakePeers = append(handshakePeers, network.PersistentPeer{
					ID: peer.ID,
					Addrs: func() []string {
						var addrs []string
						for _, addr := range peer.Addrs {
							addrs = append(addrs, addr.String())
						}
						return addrs
					}(),
					LastSeen:        time.Now().Unix(),
					HandshakeStatus: 1, // 表示已握手
				})
			}
		}
	}

	// 转换为protobuf响应格式
	peerList := make([]*pb.ProtoPersistentPeer, 0, len(handshakePeers))
	for _, p := range handshakePeers {
		// 转换PersistentPeer为ProtoPersistentPeer
		protoPeer := p.ToProto()
		peerList = append(peerList, protoPeer)
	}

	return &pb.GetPeerRes{
		PeerList: peerList,
	}, nil
}

func (s *NodeServer) GetConfirmedTxByAddress(ctx context.Context, req *pb.GetTxByAddressReq) (*pb.GetTxByAddressRes, error) {
	address := req.GetAddress()
	netParams, err := getNetParams(s.srv.cfg.Bitcoin.NetVersion)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}
	targetAddr, err := utils.DecodeAddress(address, netParams)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败：%v", err)
	}

	// 获取地址相关的已确认交易哈希列表（分页参数：0为起始索引，20为每页数量，true表示正向排序）
	txHashes, _, err := s.srv.addrIndex.TxHashesForAddress(targetAddr, 0, 20, true)
	if err != nil {
		log.Printf("查询地址的已确认交易哈希失败: %v", err)
		return nil, fmt.Errorf("查询交易哈希失败：%v", err)
	}

	// 初始化结果切片
	resultTxs := make([]*pb.JsonTx, 0, len(txHashes))

	// 遍历交易哈希，查询并转换交易详情
	for _, txHash := range txHashes {
		// 根据哈希查询完整交易信息
		blockHash, txIndexInBlock, _, err := s.srv.txIndex.GetBlockInfoForTx(txHash)
		if err != nil {
			return nil, fmt.Errorf("failed to get block info for tx %s: %w", txHash.String(), err)
		}

		tx, err := s.srv.chain.GetTxByBlockHashAndIndex(blockHash, txIndexInBlock)
		if err != nil {
			log.Printf("查询交易详情失败 (hash: %s): %v", txHash.String(), err)
			continue // 单个交易查询失败不影响其他交易
		}

		// 转换交易格式（core.Tx -> DTO）
		dto := rpc.MsgTxToDTO(tx)

		// 构建pb.JsonTx对象
		jsonTx := &pb.JsonTx{
			TxId:     txHash.String(), // 使用原始哈希字符串作为交易ID
			Version:  tx.Version,
			LockTime: tx.LockTime,
			TxIn:     dto.TxIn,
			TxOut:    dto.TxOut,
		}
		resultTxs = append(resultTxs, jsonTx)
	}

	return &pb.GetTxByAddressRes{
		Txs: resultTxs,
	}, nil
}

func (s *NodeServer) GetUnconfirmedTxByAddress(ctx context.Context, req *pb.GetTxByAddressReq) (*pb.GetTxByAddressRes, error) {
	address := req.GetAddress()
	netParams, err := getNetParams(s.srv.cfg.Bitcoin.NetVersion)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}
	targetAddr, err := utils.DecodeAddress(address, netParams)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败：%v", err)
	}
	unconfirmedTxs := s.srv.addrIndex.UnconfirmedTxnsForAddress(targetAddr)
	if unconfirmedTxs == nil {
		// 无未确认交易时返回空列表（避免nil）
		return &pb.GetTxByAddressRes{Txs: []*pb.JsonTx{}}, nil
	}
	// 转换交易格式（core.Tx -> pb.JsonTx）
	resultTxs := make([]*pb.JsonTx, 0, len(unconfirmedTxs))
	for _, tx := range unconfirmedTxs {
		// 使用现有转换工具将交易转换为DTO格式
		dto := rpc.MsgTxToDTO(tx.MsgTx())

		// 构建pb.JsonTx对象
		jsonTx := &pb.JsonTx{
			TxId:     tx.Hash().String(),
			Version:  tx.MsgTx().Version,
			LockTime: tx.MsgTx().LockTime,
			TxIn:     dto.TxIn,
			TxOut:    dto.TxOut,
			// 如需其他字段（如手续费、确认数等）可在此补充
		}
		resultTxs = append(resultTxs, jsonTx)
	}
	return &pb.GetTxByAddressRes{Txs: resultTxs}, nil
}

func (s *NodeServer) BitCoinTransfer(ctx context.Context, req *pb.TransferReq) (*pb.JsonTx, error) {
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("助记词不能为空")
	}
	if req.Index < 0 {
		return nil, fmt.Errorf("索引不能为空")
	}
	if req.AddressType == "" {
		return nil, fmt.Errorf("地址类型不能为空")
	}
	if req.NetType == "" {
		return nil, fmt.Errorf("网络类型不能为空")
	}
	if req.Amount <= 0 {
		return nil, fmt.Errorf("转账金额不能为空")
	}
	if req.ToAddress == "" {
		return nil, fmt.Errorf("转账地址不能为空")
	}
	addrTypeStr := strings.ToUpper(req.AddressType)
	// 2. 类型转换：将 string 转为 wallet.BTCAddressType（自定义字符串类型）
	addrType := wallet.BTCAddressType(addrTypeStr)
	// 3. 合法性校验：仅允许支持的地址类型（P2PKH/P2WPKH）
	switch addrType {
	case wallet.BTCAddressTypeP2PKH, wallet.BTCAddressTypeP2WPKH:
		// 合法类型，继续执行
	default:
		return nil, fmt.Errorf("不支持的地址类型：%s，仅支持 P2PKH 或 P2WPKH", req.AddressType)
	}
	params, err := getChaincfgNetParams(req.NetType)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}
	mnemonic := wallet.ValidateMnemonic(req.Mnemonic)
	if !mnemonic {
		return nil, fmt.Errorf("助记词不符合BIP-39标准")
	}
	fromAddrStr, privateKey, _, err := wallet.GenerateBtcAddressFromMnemonic(
		req.Mnemonic,
		"",
		addrType,
		params,
		req.Index)
	if err != nil {
		return nil, fmt.Errorf("解析源地址失败：%v", err)
	}

	netParams, err := getNetParams(req.NetType)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}

	// 解析源地址（btcd 标准地址结构体）
	fromAddr, err := utils.DecodeAddress(fromAddrStr, netParams)
	if err != nil {
		return nil, fmt.Errorf("解析源地址失败：%v", err)
	}
	// 解析目标地址
	toAddr, err := utils.DecodeAddress(req.ToAddress, netParams)
	if err != nil {
		return nil, fmt.Errorf("解析目标地址失败：%v", err)
	}

	//获取地址下的UTXO  构建一笔交易用于转账
	allUTXO, err := s.srv.chain.GetAddressAllUTXOFull(fromAddrStr)
	if err != nil {
		// 修正错误日志：将"区块"改为"UTXO"，避免误导
		globalLog.Errorf("查询全部UTXO失败：%v", err)
		// 修正返回错误信息：与日志和业务逻辑对齐
		return nil, status.Errorf(500, "获取UTXO列表失败：%v", err)
	}
	//判断内存中是否

	const (
		SatoshiPerBTC = 1e8                 // 1BTC = 1亿聪
		TxVersion     = 1                   // 交易版本（比特币主流版本1）
		LockTime      = 0                   // 锁时间（0表示立即生效）
		SigHashType   = txscript.SigHashAll // 签名覆盖所有输入输出
	)
	targetConfirms := uint32(6) // 目标6个区块确认（可配置）
	feeRateBtcPerKb, err := s.srv.feeEstimator.EstimateFee(targetConfirms)
	globalLog.Infof("费用估算比率%s", feeRateBtcPerKb)
	if err != nil {
		// 检查是否为区块不足错误
		if strings.Contains(err.Error(), "not enough blocks have been observed") {
			globalLog.Warnf("区块数据不足，无法估算费率，将使用默认费率. 错误: %v", err)

			// 根据网络类型设置默认费率（单位：BTC/KB）
			// 主网默认10 sat/byte = 0.00000001 BTC/byte = 0.00001 BTC/KB
			// 测试网默认5 sat/byte
			switch req.NetType {
			case "mainnet":
				feeRateBtcPerKb = 0.00001 // 10 sat/byte
			case "testnet", "regtest":
				feeRateBtcPerKb = 0.000005 // 5 sat/byte
			default:
				feeRateBtcPerKb = 0.00001 // 默认值
			}
		} else {
			return nil, fmt.Errorf("费用估算失败：%v", err)
		}
	}
	feeRateSatoshiPerByte := s.srv.feeEstimator.BtcPerKilobyteToSatoshiPerByte(feeRateBtcPerKb) // 转换为“聪/字节”
	globalLog.Infof("费用估算:%.2f", feeRateSatoshiPerByte)

	var (
		selectedUTXOs []*blockchain.UtxoEntryFull
		totalInput    int64 // 选中UTXO的总金额（聪）
		txSizeEst     int   // 交易预估大小（字节，用于计算手续费）
	)

	if addrType == wallet.BTCAddressTypeP2PKH {
		txSizeEst = 148 + 80 // P2PKH输入：148字节，2输出：80字节
	} else { // P2WPKH
		txSizeEst = 68 + 80 // P2WPKH输入（含见证）：68字节，2输出：80字节
	}
	sort.Slice(allUTXO, func(i, j int) bool {
		return allUTXO[i].Amount() > allUTXO[j].Amount()
	})

	txHeight, _ := s.srv.chain.GetMainLatestHeight()
	coinbaseMaturity := int32(params.CoinbaseMaturity)

	// 遍历UTXO，累加总余额（排除无效UTXO）
	for _, utxo := range allUTXO {
		if utxo == nil || utxo.Amount() <= 0 {
			globalLog.Warnf("跳过无效UTXO：金额为0或nil")
			continue
		}
		// 步骤2：新增——Coinbase UTXO成熟度校验
		if utxo.IsCoinBase() { // 判断是否为Coinbase类型UTXO
			// 获取UTXO所在的区块高度（转换为int64，与当前区块高度类型一致）
			originHeight := utxo.BlockHeight()
			// 计算「当前区块高度 - UTXO区块高度」= 已确认的区块数
			blocksSincePrev := txHeight - originHeight

			// 异常处理：当前区块高度 < UTXO区块高度（理论不可能，避免数据异常）
			if blocksSincePrev < 0 {
				globalLog.Warnf("跳过异常Coinbase UTXO：当前区块高度=%d < UTXO区块高度=%d（数据不一致）",
					txHeight, originHeight)
				continue
			}

			// 核心校验：未达到成熟度要求，跳过该UTXO
			if blocksSincePrev < coinbaseMaturity {
				globalLog.Warnf("跳过未成熟Coinbase UTXO：UTXO区块高度=%d，当前区块高度=%d，已确认%d块（需成熟%d块）",
					originHeight, txHeight, blocksSincePrev, coinbaseMaturity)
				continue
			}

			// 日志：记录已选中的成熟Coinbase UTXO
			globalLog.Infof("选中成熟Coinbase UTXO：区块高度=%d，已确认%d块（满足成熟度），金额=%d聪",
				originHeight, blocksSincePrev, utxo.Amount())
		}

		// 累加UTXO金额
		selectedUTXOs = append(selectedUTXOs, utxo)
		totalInput += utxo.Amount()
		// 每增加1个输入，更新交易预估大小
		if addrType == wallet.BTCAddressTypeP2PKH {
			txSizeEst += 148
		} else {
			txSizeEst += 68
		}
		// 计算当前所需手续费（手续费 = 交易大小 × 费率）
		requiredFee := int64(float64(feeRateSatoshiPerByte) * float64(txSizeEst))
		// 检查是否满足：总输入 ≥ 转账金额 + 手续费（预留找零空间）
		if totalInput >= req.Amount+requiredFee {
			break
		}
	}
	// 校验UTXO是否足够
	requiredFee := int64(float64(feeRateSatoshiPerByte) * float64(txSizeEst))
	if totalInput < req.Amount+requiredFee {
		return nil, fmt.Errorf("UTXO余额不足：总输入%d聪，需转账%d聪+手续费%s聪",
			totalInput, req.Amount, requiredFee)
	}
	globalLog.Infof("交易手续费%s", requiredFee)
	// 计算找零金额（找零 = 总输入 - 转账金额 - 手续费）
	changeAmount := totalInput - req.Amount - requiredFee
	// 初始化交易结构体
	tx := &core.MsgTx{
		Version:  TxVersion,
		LockTime: LockTime,
		TxIn:     make([]*core.TxIn, 0, len(selectedUTXOs)),
		TxOut:    make([]*core.TxOut, 0, 2), // 1个收款输出 + 1个找零输出（若changeAmount>0）
	}
	// 步骤3.1：构建交易输入（TxIn）
	for _, utxo := range selectedUTXOs {
		// 解析UTXO对应的交易ID（chainhash.Hash）

		// 构建输入：引用UTXO的“前序交易ID”和“输出索引”
		txIn := &core.TxIn{
			PreviousOutPoint: core.OutPoint{
				Hash:  utxo.Hash,
				Index: utxo.Index, // UTXO在其交易中的输出索引
			},
			Sequence: 0xffffffff, // 默认序列值（无RBF）
		}
		tx.TxIn = append(tx.TxIn, txIn)
	}

	toScriptPubKey, err := txscript.PayToAddrScript(toAddr)
	if err != nil {
		return nil, fmt.Errorf("生成目标地址脚本公钥失败：%v", err)
	}
	tx.TxOut = append(tx.TxOut, &core.TxOut{
		Value:    req.Amount,
		PkScript: toScriptPubKey,
	})
	// 输出2：找零（若找零金额>0，找零地址与源地址同类型）
	if changeAmount > 0 {
		// 生成找零地址的脚本公钥
		changeScriptPubKey, err := txscript.PayToAddrScript(fromAddr)
		if err != nil {
			return nil, fmt.Errorf("生成找零地址脚本公钥失败：%v", err)
		}
		tx.TxOut = append(tx.TxOut, &core.TxOut{
			Value:    changeAmount,
			PkScript: changeScriptPubKey,
		})
	}
	//使用私钥对交易进行签名
	priKey, pubKey := btcec.PrivKeyFromBytes(privateKey)

	if priKey == nil || pubKey == nil {
		return nil, fmt.Errorf("从私钥字节流解析密钥对失败")
	}
	// --------------- 核心步骤1：遍历所有交易输入，为每个输入生成签名 ---------------
	for i, txIn := range tx.TxIn {
		// 1. 获取当前输入对应的UTXO（包含前序输出的脚本公钥和金额）
		if i >= len(selectedUTXOs) {
			return nil, fmt.Errorf("输入索引%d超出UTXO列表长度", i)
		}
		utxo := selectedUTXOs[i]
		subScript := utxo.PkScript() // 前序输出的脚本公钥（签名必需，又称"子脚本"）
		utxoAmount := utxo.Amount()  // 前序UTXO金额（P2WPKH签名需BIP143金额校验）
		// 2. 生成压缩格式公钥（节省空间，比特币生态默认推荐）
		pubKey := priKey.PubKey()
		pubKeyData := pubKey.SerializeCompressed()
		// 3. 按地址类型生成签名（P2PKH vs P2WPKH）
		switch addrType {
		case wallet.BTCAddressTypeP2PKH:
			// -------------------------- P2PKH签名逻辑 --------------------------
			// 3.1 计算P2PKH签名哈希（覆盖交易所有输入输出，符合SigHashAll规则）
			sighash, err := txscript.CalcSignatureHash(
				subScript,   // 前序输出脚本公钥
				SigHashType, // 签名哈希类型（全量覆盖）
				tx,          // 待签名交易
				i,           // 当前输入索引
			)
			if err != nil {
				return nil, fmt.Errorf("输入%d计算P2PKH签名哈希失败：%v", i, err)
			}

			// 3.2 用私钥对哈希签名（ECDSA算法）
			sig := ecdsa.Sign(priKey, sighash)
			// 3.3 拼接签名与哈希类型（比特币要求签名后缀必须附加哈希类型）
			sigData := append(sig.Serialize(), byte(SigHashType))

			// 3.4 构建P2PKH签名脚本：[签名, 压缩公钥]
			scriptBuilder := txscript.NewScriptBuilder()
			if err := scriptBuilder.AddData(sigData); err != nil {
				return nil, fmt.Errorf("输入%d添加签名到脚本失败：%v", i, err)
			}
			if err := scriptBuilder.AddData(pubKeyData); err != nil {
				return nil, fmt.Errorf("输入%d添加公钥到脚本失败：%v", i, err)
			}
			// 生成最终签名脚本并赋值给交易输入
			sigScript, err := scriptBuilder.Script()
			if err != nil {
				return nil, fmt.Errorf("输入%d构建P2PKH签名脚本失败：%v", i, err)
			}
			txIn.SignatureScript = sigScript

		case wallet.BTCAddressTypeP2WPKH:
			// -------------------------- P2WPKH签名逻辑（隔离见证） --------------------------
			// 3.1 生成P2WPKH见证签名（BIP143标准，需传入前序UTXO金额）

			fetcher := txscript.NewCannedPrevOutputFetcher(utxo.PkScript(), utxo.Amount())
			sigHashes := txscript.NewTxSigHashes(tx, fetcher)

			witnessSig, err := txscript.RawTxInWitnessSignature(
				tx,          // 待签名交易
				sigHashes,   // SigHashes：nil时自动计算（简化逻辑，多输入场景可预计算优化性能）
				i,           // 当前输入索引
				utxoAmount,  // 前序UTXO金额（BIP143必需，防止重放攻击）
				subScript,   // 前序输出脚本公钥（P2WPKH脚本格式为：OP_0 + 20字节地址哈希）
				SigHashType, // 签名哈希类型
				priKey,      // 私钥
			)

			if err != nil {
				return nil, fmt.Errorf("输入%d生成P2WPKH见证签名失败：%v", i, err)
			}

			// 3.2 构建隔离见证数据：[见证签名, 压缩公钥]（P2WPKH见证固定格式）
			txWitness := core.TxWitness{witnessSig, pubKeyData}
			// 赋值给交易输入的Witness字段（P2WPKH无需设置SignatureScript，留空即可）
			txIn.Witness = txWitness

		default:
			return nil, fmt.Errorf("不支持的签名地址类型：%s", addrType)
		}
	}
	// --------------- 核心步骤2：交易序列化（生成可广播的十六进制字符串） ---------------
	// 签名完成后，将交易序列化为比特币标准格式的十六进制字符串（用于后续广播）
	txBuffer := bytes.NewBuffer(nil)
	if err := tx.Serialize(txBuffer); err != nil {
		return nil, fmt.Errorf("交易序列化失败（签名后）：%v", err)
	}

	err = s.srv.syncManager.OnTx("", tx)
	if err != nil {
		return nil, fmt.Errorf("交易创建失败：%v", err)
	}

	dto := rpc.MsgTxToDTO(tx)

	// --------------- 核心步骤3：构建返回结果（包含交易ID和Hex） ---------------
	txHash := tx.TxHash() // 计算交易哈希（即TxId）
	return &pb.JsonTx{
		TxId:     txHash.String(), // 交易ID（十六进制字符串）
		Version:  tx.Version,      // 交易版本
		LockTime: tx.LockTime,     // 锁时间（0表示立即生效）
		TxIn:     dto.TxIn,
		TxOut:    dto.TxOut,
	}, nil
}

func (s *NodeServer) CreateBtcAddressByMnemonic(ctx context.Context, req *pb.CreateBtcAddressByMnemonicReq) (*pb.BtcAddress, error) {
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("助记词不能为空")
	}
	if req.Index < 0 {
		return nil, fmt.Errorf("索引不能为空")
	}
	if req.AddressType == "" {
		return nil, fmt.Errorf("地址类型不能为空")
	}
	if req.NetType == "" {
		return nil, fmt.Errorf("网络类型不能为空")
	}
	addrTypeStr := strings.ToUpper(req.AddressType)
	// 2. 类型转换：将 string 转为 wallet.BTCAddressType（自定义字符串类型）
	addrType := wallet.BTCAddressType(addrTypeStr)
	// 3. 合法性校验：仅允许支持的地址类型（P2PKH/P2WPKH）
	switch addrType {
	case wallet.BTCAddressTypeP2PKH, wallet.BTCAddressTypeP2WPKH:
		// 合法类型，继续执行
	default:
		return nil, fmt.Errorf("不支持的地址类型：%s，仅支持 P2PKH 或 P2WPKH", req.AddressType)
	}

	params, err := getChaincfgNetParams(req.NetType)
	if err != nil {
		return nil, fmt.Errorf("未找到该网络参数")
	}
	mnemonic := wallet.ValidateMnemonic(req.Mnemonic)
	if !mnemonic {
		return nil, fmt.Errorf("助记词不符合BIP-39标准")
	}
	address, _, _, err := wallet.GenerateBtcAddressFromMnemonic(
		req.Mnemonic,
		"",
		addrType,
		params,
		req.Index)
	if err != nil {
		return nil, fmt.Errorf("助记词生成地址失败%d", err)
	}
	return &pb.BtcAddress{
		Index:   req.Index,
		Address: address,
	}, nil
}

func (s *NodeServer) CreateEthAddressByMnemonic(ctx context.Context, req *pb.CreateEthAddressByMnemonicReq) (*pb.EthAddress, error) {
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("助记词不能为空")
	}
	if req.Index < 0 {
		return nil, fmt.Errorf("索引不能为空")
	}
	mnemonic := wallet.ValidateMnemonic(req.Mnemonic)
	if !mnemonic {
		return nil, fmt.Errorf("助记词不符合BIP-39标准")
	}
	address, _, _, err := wallet.GenerateEthAddressFromMnemonic(req.Mnemonic, "", req.Index)
	if err != nil {
		return nil, fmt.Errorf("助记词生成地址失败%d", err)
	}
	return &pb.EthAddress{
		Index:   req.Index,
		Address: address,
	}, nil
}

func (s *NodeServer) CreateWallet(ctx context.Context, req *pb.CreateWalletReq) (*pb.JsonWallet, error) {
	//参数判断
	if req.Name == "" {
		return nil, fmt.Errorf("钱包名称不能为空")
	}
	if req.Password == "" {
		return nil, fmt.Errorf("钱包密码不能为空")
	}
	if req.PasswordHint == "" {
		return nil, fmt.Errorf("钱包密码提示不能为空")
	}
	newWallet, err := wallet.NewWallet(req.Name, req.Password, req.PasswordHint)
	if err != nil {
		return nil, fmt.Errorf("钱包创建失败%d", err)
	}
	mnemonic, err := newWallet.ExportMnemonic(req.Password)
	if err != nil {
		return nil, fmt.Errorf("助记词导出失败%d", err)
	}
	return &pb.JsonWallet{
		Name:         newWallet.GetName(),
		Password:     req.Password,
		PasswordHint: newWallet.GetPasswordHint(),
		Mnemonic:     mnemonic,
	}, nil
}

func (s *NodeServer) GetUTXOByTxIdAndOutIndex(ctx context.Context, req *pb.GetUTXOByTxIdAndOutIndexReq) (*pb.JsonUTXO, error) {
	if req.TxId == "" {
		return nil, fmt.Errorf("交易ID不能为空")
	}
	if req.Index < 0 {
		return nil, fmt.Errorf("输出索引不符合规范")
	}
	utxo, err := s.srv.chain.GetUTXOByTxIdAndOutIndex(req.TxId, req.Index)
	if err != nil {
		return nil, fmt.Errorf("获取UTXO失败: %v", err)
	}
	disasmString, _ := txscript.DisasmString(utxo.PkScript())
	return &pb.JsonUTXO{
		Amount:      utxo.Amount(),
		PkScript:    disasmString,
		BlockHeight: utxo.BlockHeight(),
		PackedFlags: uint32(utxo.PackedFlags()),
	}, nil
}

func (s *NodeServer) GetBlockByHash(ctx context.Context, req *pb.GetBlockByHashReq) (*pb.JsonBlock, error) {
	// 1. 验证输入哈希不为空
	if req.Hash == "" {
		return nil, fmt.Errorf("哈希值不能为空")
	}
	str, err2 := chainhash.NewHashFromStr(req.Hash)
	if err2 != nil {
		return nil, status.Errorf(400, "哈希格式无效（需十六进制字符串）: %v", err2)
	}
	// 3. 从区块链中获取区块
	block, err := s.srv.chain.GetBlockByHash(str)
	if err != nil {
		return nil, fmt.Errorf("获取区块失败: %v", err)
	}

	transactions := block.GetBody().Transactions //转JSONTx

	// 4. 转换交易列表：core.MsgTx → JsonTx
	jsonTxs := make([]*pb.JsonTx, 0, len(transactions))
	for _, tx := range transactions {
		if tx == nil {
			globalLog.Warnf("区块 %s 中存在空交易，已跳过", req.Hash)
			continue
		}
		// 4.1 复用 rpc 包工具：将核心交易转为 DTO 格式（含 Hex 可读字段）
		txDTO := rpc.MsgTxToDTO(tx)
		if txDTO == nil {
			globalLog.Warnf("交易 %s 转换 DTO 失败，已跳过", tx.TxHash().String())
			continue
		}
		// 4.2 构建 JsonTx（映射 DTO 字段并补充交易 ID）
		jsonTx := &pb.JsonTx{
			TxId:     tx.TxHash().String(), // 交易哈希转为十六进制字符串
			Version:  txDTO.Version,
			TxIn:     txDTO.TxIn,  // 直接复用 DTO 的交易输入（已转 Hex）
			TxOut:    txDTO.TxOut, // 直接复用 DTO 的交易输出
			LockTime: txDTO.LockTime,
		}
		jsonTxs = append(jsonTxs, jsonTx)
	}

	return &pb.JsonBlock{
		Hash:         block.BlockHash.String(),
		Height:       block.BlockHeight,
		ChainWork:    block.GetChainWork().String(),
		Version:      block.BlockHeader().Version,
		PrevBlock:    block.BlockHeader().PrevBlock.String(),  // 前序区块哈希（Hex）
		MerkleRoot:   block.BlockHeader().MerkleRoot.String(), // 默克尔根（Hex）
		Timestamp:    block.BlockHeader().Timestamp,           // 时间戳（秒级）
		Bits:         block.BlockHeader().Bits,                // 难度目标
		Nonce:        block.BlockHeader().Nonce,               // 随机数
		Transactions: jsonTxs,                                 // 转换后的交易列表
		IsMainChain:  block.IsMainChain,
	}, nil
}

func (s *NodeServer) GetBlockByHeight(ctx context.Context, req *pb.GetBlockByHeightReq) (*pb.JsonBlock, error) {
	// 1. 验证输入参数有效性
	if req.Height < 0 {
		return nil, status.Errorf(400, "区块高度无效（不能为负数）: %d", req.Height)
	}
	// 2. 从区块链核心层获取指定高度的区块
	block, err := s.srv.chain.GetBlockByHeight(req.Height)
	if err != nil {
		// 区分“区块不存在”和“服务端异常”（若底层链实现支持，可细化判断）
		return nil, status.Errorf(404, "获取区块失败：高度 %d 不存在或查询异常: %v", req.Height, err)
	}
	// 3. 提取区块中的交易列表（核心交易格式：core.MsgTx）
	transactions := block.GetBody().Transactions

	// 4. 转换交易列表：core.MsgTx → pb.JsonTx（复用rpc层转换工具，保持格式统一）
	jsonTxs := make([]*pb.JsonTx, 0, len(transactions))
	for _, tx := range transactions {
		if tx == nil {
			globalLog.Warnf("区块高度 %d 中存在空交易，已跳过", req.Height)
			continue
		}

		// 4.1 先转为DTO（含Hex可读字段，适配gRPC传输）
		txDTO := rpc.MsgTxToDTO(tx)
		if txDTO == nil {
			globalLog.Warnf("区块高度 %d 中交易 %s 转换DTO失败，已跳过", req.Height, tx.TxHash().String())
			continue
		}

		// 4.2 构建最终返回的JsonTx（补充交易ID，映射DTO字段）
		jsonTx := &pb.JsonTx{
			TxId:     tx.TxHash().String(), // 交易哈希（十六进制字符串）
			Version:  txDTO.Version,
			TxIn:     txDTO.TxIn,  // 复用DTO的交易输入（已转Hex格式）
			TxOut:    txDTO.TxOut, // 复用DTO的交易输出
			LockTime: txDTO.LockTime,
		}
		jsonTxs = append(jsonTxs, jsonTx)
	}

	// 5. 构造并返回gRPC响应（字段映射与GetBlockByHash完全一致）
	return &pb.JsonBlock{
		Hash:         block.BlockHash.String(),                // 区块哈希（Hex）
		Height:       block.BlockHeight,                       // 区块高度（与请求参数一致，冗余返回提升易用性）
		ChainWork:    block.GetChainWork().String(),           // 链工作量（大整数转字符串）
		Version:      block.BlockHeader().Version,             // 区块版本号
		PrevBlock:    block.BlockHeader().PrevBlock.String(),  // 前序区块哈希（Hex）
		MerkleRoot:   block.BlockHeader().MerkleRoot.String(), // 默克尔根（Hex）
		Timestamp:    block.BlockHeader().Timestamp,           // 区块时间戳（秒级Unix时间）
		Bits:         block.BlockHeader().Bits,                // 难度目标（压缩格式）
		Nonce:        block.BlockHeader().Nonce,               // 工作量证明随机数
		Transactions: jsonTxs,
		IsMainChain:  block.IsMainChain,
	}, nil
}

func (s *NodeServer) GetTxByTxId(ctx context.Context, req *pb.GetTxByTxIdReq) (*pb.JsonTx, error) {
	if req.TxId == "" {
		return nil, fmt.Errorf("交易ID不能为空")
	}
	txIdHash, err2 := chainhash.NewHashFromStr(req.TxId)
	if err2 != nil {
		return nil, status.Errorf(400, "哈希格式无效（需十六进制字符串）: %v", err2)
	}
	blockHash, txIndexInBlock, _, err := s.srv.txIndex.GetBlockInfoForTx(txIdHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block info for tx %s: %w", txIdHash.String(), err)
	}
	globalLog.Infof("所在区块Hash %s  所在区块 %d", blockHash, txIndexInBlock)
	tx, err := s.srv.chain.GetTxByBlockHashAndIndex(blockHash, txIndexInBlock)
	if err != nil {
		return nil, fmt.Errorf("获取交易失败: %v", err)
	}
	if err != nil {
		return nil, fmt.Errorf("获取交易失败: %v", err)
	}
	txDTO := rpc.MsgTxToDTO(tx)
	return &pb.JsonTx{
		TxId:     tx.TxHash().String(), // 交易哈希（十六进制字符串）
		Version:  txDTO.Version,
		TxIn:     txDTO.TxIn,  // 复用DTO的交易输入（已转Hex格式）
		TxOut:    txDTO.TxOut, // 复用DTO的交易输出
		LockTime: txDTO.LockTime,
	}, nil
}

func (s *NodeServer) GetMainBlockByHeight(ctx context.Context, req *pb.GetMainBlockByHeightReq) (*pb.GetBlockReplyDTO, error) {
	globalLog.Infof("请求数据%d", req)

	block, err := s.srv.chain.GetMainBlockByHeight(req.Height)
	if err != nil {
		return nil, status.Errorf(500, "获取区块失败：%v", err)
	}

	// 4. 构造并返回gRPC响应
	return &pb.GetBlockReplyDTO{
		Block: rpc.MsgBlockToDTO(block.MsgBlock()),
	}, nil
}

func (s *NodeServer) GetAddressAllUTXO(ctx context.Context, req *pb.GetAddressAllUtxoRequest) (*pb.UtxoList, error) {
	allUTXO, err := s.srv.chain.GetAddressAllUTXO(req.Address)
	if err != nil {
		// 修正错误日志：将"区块"改为"UTXO"，避免误导
		globalLog.Errorf("查询全部UTXO失败：%v", err)
		// 修正返回错误信息：与日志和业务逻辑对齐
		return nil, status.Errorf(500, "获取UTXO列表失败：%v", err)
	}
	// 3. 打印查询结果数量，便于调试与监控
	utxoCount := len(allUTXO)
	globalLog.Infof("查询到 %d 个UTXO", utxoCount)
	// 4. 初始化Proto格式UTXO切片（预分配容量优化性能）
	pbAllUTXO := make([]*pb.ProtoUtxoEntry, 0, utxoCount)
	var totalBalance int64 // 用于统计总余额，使用uint64避免溢出
	// 5. 循环转换UTXO格式（核心逻辑）
	for idx, utxo := range allUTXO {
		// 调用core层UTXO的ToProto()方法转换格式，**必须处理错误**
		protoUtxo, err := utxo.ToProto()
		if err != nil {
			// 记录错误详情（包含索引和UTXO简要信息），便于定位问题
			globalLog.Errorf("UTXO转换为Proto格式失败，索引：%d，错误：%v，UTXO信息：%+v", idx, err, utxo)
			// 单个UTXO转换失败不中断整体请求，跳过无效数据
			continue
		}

		// 转换成功：将Proto格式UTXO添加到结果切片
		pbAllUTXO = append(pbAllUTXO, protoUtxo)

		// 累加余额（假设ProtoUtxoEntry中有Amount字段表示金额）
		totalBalance += protoUtxo.Amount
	}

	// 4. 构造并返回gRPC响应
	return &pb.UtxoList{
		Utxos:        pbAllUTXO,
		TotalCount:   int32(utxoCount),
		TotalBalance: totalBalance,
	}, nil
}

func (s *NodeServer) GetAllBlock(ctx context.Context, req *pb.Message) (*pb.BlockList, error) {
	globalLog.Infof("请求数据%d", req)
	coreBlocks, err := s.srv.chain.GetAllBlock()
	if err != nil {
		globalLog.Errorf("查询全部区块失败：%v", err)
		// 返回 500 内部错误（服务端查询逻辑异常）
		return nil, status.Errorf(500, "获取区块列表失败：%v", err)
	}
	blockCount := len(coreBlocks)
	globalLog.Infof("查询到 %d 个区块", len(coreBlocks))
	// 3. 转换数据格式：core.MsgBlock -> pb.Block（适配 gRPC 协议返回）
	// 需确保 core.MsgBlock 有 ToProto() 方法（参考 GetBlock 方法的转换逻辑）
	// 3. 类型转换：core.MsgBlock -> pb.ProtoMsgBlock（依赖core层的ToProto方法）
	// 初始化pb.ProtoMsgBlock切片，容量与核心区块列表一致（优化性能）
	pbBlocks := make([]*pb.ProtoMsgBlock, 0, blockCount)
	for _, coreBlock := range coreBlocks {
		// 调用core.MsgBlock的ToProto()方法转换为gRPC协议类型
		// （参考GetBlock方法中msgBlock.ToProto()的实现逻辑，确保该方法存在）
		pbBlock := coreBlock.ToProto()
		pbBlocks = append(pbBlocks, pbBlock)
	}

	// 4. 构造并返回gRPC响应
	return &pb.BlockList{
		Blocks: pbBlocks, // 将转换后的区块列表赋值给BlockList的blocks字段
	}, nil
}

func (s *NodeServer) GetAllUTXO(ctx context.Context, req *pb.Message) (*pb.UtxoList, error) {
	// 1. 修正请求日志：使用%+v格式化pb.Message，避免类型不匹配错误
	globalLog.Infof("收到获取全部UTXO请求，请求数据: %+v", req)

	// 2. 从区块链核心层查询全部UTXO
	allUTXO, err := s.srv.chain.GetAllUTXO()
	if err != nil {
		// 修正错误日志：将"区块"改为"UTXO"，避免误导
		globalLog.Errorf("查询全部UTXO失败：%v", err)
		// 修正返回错误信息：与日志和业务逻辑对齐
		return nil, status.Errorf(500, "获取UTXO列表失败：%v", err)
	}

	// 3. 打印查询结果数量，便于调试与监控
	utxoCount := len(allUTXO)
	globalLog.Infof("查询到 %d 个UTXO", utxoCount)

	// 4. 初始化Proto格式UTXO切片（预分配容量优化性能）
	pbAllUTXO := make([]*pb.ProtoUtxoEntry, 0, utxoCount)

	// 5. 循环转换UTXO格式（核心逻辑）
	for idx, utxo := range allUTXO {
		// 调用core层UTXO的ToProto()方法转换格式，**必须处理错误**
		protoUtxo, err := utxo.ToProto()
		if err != nil {
			// 记录错误详情（包含索引和UTXO简要信息），便于定位问题
			globalLog.Errorf("UTXO转换为Proto格式失败，索引：%d，错误：%v，UTXO信息：%+v", idx, err, utxo)
			// 单个UTXO转换失败不中断整体请求，跳过无效数据
			continue
		}

		// 转换成功：将Proto格式UTXO添加到结果切片
		pbAllUTXO = append(pbAllUTXO, protoUtxo)
	}

	// 6. 构造并返回gRPC响应
	return &pb.UtxoList{
		Utxos: pbAllUTXO,
	}, nil
}

// 提交交易
func (s *NodeServer) SubmitTransaction(ctx context.Context, req *pb.ProtoMsgTx) (*pb.CommonResp, error) {
	globalLog.Infof("请求数据%d", req.Version)
	//交给区块链验证 并返回结果
	//转成MsgTx
	var tx core.MsgTx
	tx.FromProto(req)

	return &pb.CommonResp{
		Code: 200,
	}, nil
}

func (s *NodeServer) JsonSubmitTransaction(ctx context.Context, req *pb.ProtoMsgTxDTO) (*pb.CommonResp, error) {
	globalLog.Infof("交易详情:%s", req)
	//将ProtoMsgTxDTO 转 ProtoMsgTx
	msgtx := rpc.DTOToMsgTx(req)

	globalLog.Infof("交易详情:%d", msgtx.Version)
	// 提交交易到同步管理器
	err := s.srv.syncManager.OnTx("", msgtx)
	if err != nil {
		// 记录错误日志
		globalLog.Errorf("交易处理失败: %v", err)
		// 构建错误响应（根据实际 proto 定义调整字段）
		return &pb.CommonResp{
			Code:    1,           // 非0表示错误
			Message: err.Error(), // 错误详情
		}, nil
	}

	hash := msgtx.TxHash()
	// 处理成功的响应
	return &pb.CommonResp{
		Code:    0, // 0表示成功
		Message: "交易已成功提交到内存池",
		Data:    hash[:],
	}, nil
}

// 取指定高度区块
func (s *NodeServer) GetBlock(ctx context.Context,
	req *pb.GetBlockRequest) (*pb.GetBlockReply, error) {
	if req == nil {
		return nil, status.Errorf(400, "请求参数不能为空")
	}

	blockHeight := req.Height
	fmt.Printf("收到查询区块高度: %d\n", blockHeight)

	// 实际应用中应该从区块链中查询，这里仅为示例返回创世区块
	if blockHeight != 0 {
		return nil, status.Errorf(404, "区块高度 %d 不存在", blockHeight)
	}

	prevHashHex := "0000000000000000000000000000000000000000000000000000000000000000"
	merkleHex := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	prevHash := mustDecodeHash(prevHashHex)
	merkleRoot := mustDecodeHash(merkleHex)
	header := &core.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  1231006505, // 比特币创世时间
		Bits:       blockchain.InitBits,
		Nonce:      2083236893,
	}

	// 构造创世区块的Coinbase交易
	var coinbaseTx = &core.MsgTx{
		Version: 1,
		TxIn: []*core.TxIn{
			{
				PreviousOutPoint: core.OutPoint{
					Hash:  [32]byte{}, // 无前置交易
					Index: 0xffffffff, // Coinbase标识
				},
				SignatureScript: []byte{
					0x49, // OP_DATA_73
					0x30, 0x46, 0x02, 0x21, 0x00, 0xbb, 0x1a, 0xd2,
					0x6d, 0xf9, 0x30, 0xa5, 0x1c, 0xce, 0x11, 0x0c,
					0xf4, 0x4f, 0x7a, 0x48, 0xc3, 0xc5, 0x61, 0xfd,
					0x97, 0x75, 0x00, 0xb1, 0xae, 0x5d, 0x6b, 0x6f,
					0xfd, 0x13, 0xd, 0x3f, 0x4a, 0x2, 0x21, 0x0,
					0xc5, 0xb4, 0x29, 0x51, 0xac, 0xed, 0xff, 0x14,
					0xab, 0xba, 0x27, 0x36, 0xfd, 0x57, 0x4b, 0xdb,
					0x46, 0x5f, 0x3e, 0x6f, 0x8d, 0xa1, 0x2e, 0x2c,
					0x53, 0x3, 0x95, 0x4a, 0xca, 0x7f, 0x78, 0xf3,
					0x1,  // 73-byte signature
					0x41, // OP_DATA_65
					0x4, 0xa7, 0x13, 0x5b, 0xfe, 0x82, 0x4c, 0x97,
					0xec, 0xc0, 0x1e, 0xc7, 0xd7, 0xe3, 0x36, 0x18,
					0x5c, 0x81, 0xe2, 0xaa, 0x2c, 0x41, 0xab, 0x17,
					0x54, 0x7, 0xc0, 0x94, 0x84, 0xce, 0x96, 0x94,
					0xb4, 0x49, 0x53, 0xfc, 0xb7, 0x51, 0x20, 0x65,
					0x64, 0xa9, 0xc2, 0x4d, 0xd0, 0x94, 0xd4, 0x2f,
					0xdb, 0xfd, 0xd5, 0xaa, 0xd3, 0xe0, 0x63, 0xce,
					0x6a, 0xf4, 0xcf, 0xaa, 0xea, 0x4e, 0xa1, 0x4f,
					0xbb, // 65-byte pubkey
				},
				Sequence: 0xffffffff,
			},
		},
		TxOut: []*core.TxOut{
			{
				Value: 5000000000, // 50 BTC in satoshi
				PkScript: []byte{
					0x41, // OP_DATA_65
					0x4, 0x1b, 0xe, 0x8c, 0x25, 0x67, 0xc1, 0x25,
					0x36, 0xaa, 0x13, 0x35, 0x7b, 0x79, 0xa0, 0x73,
					0xdc, 0x44, 0x44, 0xac, 0xb8, 0x3c, 0x4e, 0xc7,
					0xa0, 0xe2, 0xf9, 0x9d, 0xd7, 0x45, 0x75, 0x16,
					0xc5, 0x81, 0x72, 0x42, 0xda, 0x79, 0x69, 0x24,
					0xca, 0x4e, 0x99, 0x94, 0x7d, 0x8, 0x7f, 0xed,
					0xf9, 0xce, 0x46, 0x7c, 0xb9, 0xf7, 0xc6, 0x28,
					0x70, 0x78, 0xf8, 0x1, 0xdf, 0x27, 0x6f, 0xdf,
					0x84, // 65-byte signature
					0xac, // OP_CHECKSIG
				},
			},
		},
		LockTime: 0,
	}

	msgBlock := &core.MsgBlock{
		Header:       *header,
		Transactions: []*core.MsgTx{coinbaseTx},
	}

	//返回JSON数据
	return &pb.GetBlockReply{
		Block: msgBlock.ToProto(),
	}, nil
}

func (s *NodeServer) GetBlockDTO(ctx context.Context,
	req *pb.GetBlockRequestDTO) (*pb.GetBlockReplyDTO, error) {
	if req == nil {
		return nil, status.Errorf(400, "请求参数不能为空")
	}

	blockHeight := req.Height
	fmt.Printf("收到查询区块高度(DTO): %d\n", blockHeight)

	// 同样只处理创世区块查询
	if blockHeight != 0 {
		return nil, status.Errorf(404, "区块高度 %d 不存在", blockHeight)
	}

	prevHashHex := "0000000000000000000000000000000000000000000000000000000000000000"
	merkleHex := "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
	prevHash := mustDecodeHash(prevHashHex)
	merkleRoot := mustDecodeHash(merkleHex)
	header := &core.BlockHeader{
		Version:    1,
		PrevBlock:  prevHash,
		MerkleRoot: merkleRoot,
		Timestamp:  1231006505,
		Bits:       blockchain.InitBits,
		Nonce:      2083236893,
	}

	var coinbaseTx = &core.MsgTx{
		Version: 1,
		TxIn: []*core.TxIn{
			{
				PreviousOutPoint: core.OutPoint{
					Hash:  [32]byte{},
					Index: 0xffffffff,
				},
				SignatureScript: []byte("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"),
				Sequence:        0xffffffff,
			},
		},
		TxOut: []*core.TxOut{
			{
				Value: 5000000000,
				PkScript: []byte{
					0x41, 0x4, 0x67, 0x8a, 0xfd, 0xb0, 0xfe, 0x55,
					0x48, 0x27, 0x19, 0x67, 0xf1, 0xa6, 0x71, 0x30,
					0xb7, 0x10, 0x5c, 0xd6, 0xa8, 0x28, 0xe0, 0x39,
					0x9, 0xa6, 0x79, 0x62, 0xe0, 0xea, 0x1f, 0x61,
					0xde, 0xb6, 0x49, 0xf6, 0xbc, 0x3f, 0x4c, 0xef,
					0x38, 0xc4, 0xf3, 0x55, 0x4, 0xe5, 0x1e, 0xc1,
					0x12, 0xde, 0x5c, 0x38, 0x4d, 0xf7, 0xba, 0xb,
					0x8d, 0x57, 0x8a, 0x4c, 0x70, 0x2b, 0x6b, 0x11, 0xd5,
					0xf, 0xac,
				},
			},
		},
		LockTime: 0,
	}

	msgBlock := &core.MsgBlock{
		Header:       *header,
		Transactions: []*core.MsgTx{coinbaseTx},
	}

	return &pb.GetBlockReplyDTO{
		Block: rpc.MsgBlockToDTO(msgBlock),
	}, nil
}

func (s *NodeServer) SendMessage(ctx context.Context,
	req *pb.Message) (*pb.Message, error) {
	if req == nil {
		return nil, status.Errorf(400, "请求对象为空")
	}

	return &pb.Message{
		Type: 1,
	}, nil
}

func mustDecodeHash(s string) (h [32]byte) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic(fmt.Sprintf("无效的哈希值: %s, 错误: %v", s, err))
	}
	copy(h[:], b)
	return
}

// NewRPCServer 创建RPC服务器并注入核心server实例
func NewRPCServer(s *server, listenAddr string) (*NodeServer, error) {
	if s == nil {
		return nil, fmt.Errorf("核心server实例不能为空")
	}
	if listenAddr == "" {
		return nil, fmt.Errorf("RPC监听地址不能为空")
	}
	nodeServer := &NodeServer{
		srv:        s,
		rpcServer:  nil,
		rpcLis:     nil, // 初始化为 nil
		listenAddr: listenAddr,
		isRunning:  0,
	}
	return nodeServer, nil
}

func ServeGRPC(listen string) error {
	lis, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	pb.RegisterBitCoinRpcServer(s, &NodeServer{})
	return s.Serve(lis)
}

// StartRPC 启动RPC服务（支持并发安全启动）
func (s *NodeServer) StartRPC() error {
	// 1. 检查核心节点是否已关闭
	select {
	case <-s.srv.quit:
		return fmt.Errorf("核心节点已关闭，无法启动RPC服务")
	default:
	}

	// 2. 原子操作：防止重复启动（CAS：Compare And Swap）
	if !atomic.CompareAndSwapInt32(&s.isRunning, 0, 1) {
		return fmt.Errorf("RPC服务已在运行中（监听地址：%s）", s.listenAddr)
	}

	// 3. 异步启动gRPC服务（避免阻塞调用方）
	go func() {
		// 3.1 创建TCP监听句柄
		lis, err := net.Listen("tcp", s.listenAddr)
		if err != nil {
			log.Printf("[RPC启动失败] 监听地址%s绑定失败：%v", s.listenAddr, err)
			atomic.StoreInt32(&s.isRunning, 0) // 回滚状态：允许后续重试
			return
		}

		// 3.2 创建gRPC服务器（注册日志拦截器）
		rpcServer := grpc.NewServer(
			grpc.UnaryInterceptor(unaryLogInterceptor), // 绑定日志拦截器
		)

		// 3.3 注册Node服务（关键：使用当前s实例，而非新实例）
		pb.RegisterBitCoinRpcServer(rpcServer, s)

		// 3.4 绑定实例到结构体（供StopRPC使用）
		s.rpcLis = lis
		s.rpcServer = rpcServer

		/*		log.Printf("[RPC启动成功] 已开始监听：%s（支持GetBlock、GetBlockDTO、SendMessage）", s.listenAddr)
		 */
		// 3.5 启动服务（阻塞直到优雅关闭）
		serveErr := rpcServer.Serve(lis)
		// 仅处理非预期错误（ErrServerStopped是优雅关闭的正常返回）
		if serveErr != nil && serveErr != grpc.ErrServerStopped {
			log.Printf("[RPC运行异常] 服务意外终止：%v", serveErr)
			atomic.StoreInt32(&s.isRunning, 0) // 回滚状态
			s.rpcLis = nil                     // 清空无效实例
			s.rpcServer = nil
		}
	}()

	return nil
}

// StopRPC 优雅关闭RPC服务
func (s *NodeServer) StopRPC() {
	// 1. 原子操作：防止重复关闭（仅当运行中时执行关闭）
	if !atomic.CompareAndSwapInt32(&s.isRunning, 1, 0) {
		log.Printf("[RPC关闭跳过] 服务未在运行中，无需处理")
		return
	}

	log.Printf("[RPC关闭开始] 正在优雅关闭服务（监听地址：%s）", s.listenAddr)

	// 2. 优雅关闭gRPC服务（等待现有请求处理完成，不接受新请求）
	if s.rpcServer != nil {
		s.rpcServer.GracefulStop() // 非阻塞：启动优雅关闭流程
		log.Printf("[RPC关闭步骤1] gRPC服务已触发优雅关闭，等待现有请求完成")
		s.rpcServer = nil // 清空实例：避免重复操作
	}

	// 3. 关闭监听句柄（彻底释放端口）
	if s.rpcLis != nil {
		if err := s.rpcLis.Close(); err != nil {
			log.Printf("[RPC关闭警告] 监听句柄关闭失败：%v", err)
		} else {
			log.Printf("[RPC关闭步骤2] 监听句柄已关闭，端口已释放")
		}
		s.rpcLis = nil // 清空实例：避免重复操作
	}

	log.Printf("[RPC关闭完成] 服务已完全关闭（可重新启动）")
}

func unaryLogInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	start := time.Now()

	// 调用实际处理逻辑
	resp, err := handler(ctx, req)

	// 打印日志
	duration := time.Since(start)
	log.Printf(
		"RPC请求日志 - 方法：%s | 耗时：%v | 错误：%v",
		info.FullMethod,
		duration,
		err,
	)
	return resp, err
}

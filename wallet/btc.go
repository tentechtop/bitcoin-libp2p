package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

//生成比特币地址  参数 网络参数 主网等等 地址类型 P2PKH P2WPKH

// BTCAddressType 比特币地址类型枚举（支持主流类型）
type BTCAddressType string

const (
	BTCAddressTypeP2PKH  BTCAddressType = "P2PKH"  // 普通地址（Base58编码）
	BTCAddressTypeP2WPKH BTCAddressType = "P2WPKH" // 隔离见证地址（Bech32编码）
)

// 比特币网络参数映射（简化调用）
var (
	BTCMainNet  = &chaincfg.MainNetParams       // 比特币主网
	BTCTestNet3 = &chaincfg.TestNet3Params      // 比特币测试网（Testnet3）
	BTCRegNet   = &chaincfg.RegressionNetParams // 回归测试网（开发用）
)

// 比特币CoinType常量（BIP-44规范）
const (
	BTCCoinTypeMainNet = 0 // 比特币主网CoinType
	BTCCoinTypeTestNet = 1 // 比特币测试网CoinType
)

// GenerateBtcAddress 基于钱包助记词生成比特币地址（已修复公钥问题）
func (w *Wallet) GenerateBtcAddress(addrType BTCAddressType, net *chaincfg.Params, index uint32) (address, privateKey, publicKey string, err error) {
	// 1. 并发安全锁（防止多协程同时操作助记词）
	w.mu.Lock()
	defer w.mu.Unlock()

	// 2. 校验助记词有效性
	if !bip39.IsMnemonicValid(w.mnemonic) {
		return "", "", "", errors.New("钱包助记词无效，无法生成比特币地址")
	}

	// 3. 生成BIP-39 Seed（passphrase可选，此处默认空字符串，可扩展为钱包私有字段）
	passphrase := ""
	seed := bip39.NewSeed(w.mnemonic, passphrase)

	// 4. 创建比特币HD钱包主密钥（BIP-32）
	masterKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return "", "", "", fmt.Errorf("创建HD钱包主密钥失败: %w", err)
	}

	// 5. 确定派生路径（根据地址类型和网络选择CoinType）
	var coinType uint32
	if net == BTCMainNet {
		coinType = BTCCoinTypeMainNet
	} else {
		coinType = BTCCoinTypeTestNet // 测试网/回归网统一用CoinType=1
	}

	// 构建派生路径（BIP-44/P2PKH 或 BIP-84/P2WPKH）
	var derivationPath string
	switch addrType {
	case BTCAddressTypeP2PKH:
		derivationPath = fmt.Sprintf("m/44'/%d'/0'/0/%d", coinType, index)
	case BTCAddressTypeP2WPKH:
		derivationPath = fmt.Sprintf("m/84'/%d'/0'/0/%d", coinType, index)
	default:
		return "", "", "", fmt.Errorf("不支持的比特币地址类型: %s（仅支持P2PKH/P2WPKH）", addrType)
	}

	// 6. 解析派生路径并生成子密钥
	path, err := hdwallet.ParseDerivationPath(derivationPath)
	if err != nil {
		return "", "", "", fmt.Errorf("解析派生路径[%s]失败: %w", derivationPath, err)
	}

	// 逐层派生子密钥（从主密钥到指定索引的子密钥）
	childKey := masterKey
	for _, pathStep := range path {
		childKey, err = childKey.Derive(pathStep)
		if err != nil {
			return "", "", "", fmt.Errorf("派生路径步骤[%d]失败: %w", pathStep, err)
		}
	}

	// 7. 提取私钥（WIF格式，可直接导入比特币钱包）
	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return "", "", "", fmt.Errorf("提取EC私钥失败: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, net, true) // true=压缩私钥（默认推荐）
	if err != nil {
		return "", "", "", fmt.Errorf("生成WIF私钥失败: %w", err)
	}
	privateKey = wif.String() // WIF格式私钥（如：L1c8zLz...）

	// 8. 提取公钥（Hex格式）—— 修复核心：处理错误+赋值公钥
	pubKey, err := childKey.ECPubKey()
	if err != nil {
		return "", "", "", fmt.Errorf("提取EC公钥失败: %w", err)
	}
	// 修复1：处理SerializeCompressedHex的错误（避免异常穿透）
	compressedHex, err := SerializeCompressedHex(pubKey)
	if err != nil {
		return "", "", "", fmt.Errorf("序列化压缩公钥失败: %w", err)
	}
	// 修复2：将Hex格式公钥赋值给返回变量（原代码缺失此步）
	publicKey = compressedHex

	// 9. 生成对应类型的比特币地址
	switch addrType {
	case BTCAddressTypeP2PKH:
		pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, net)
		if err != nil {
			return "", "", "", fmt.Errorf("生成P2PKH地址失败: %w", err)
		}
		address = p2pkhAddr.String() // 如：1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa（主网）

	case BTCAddressTypeP2WPKH:
		pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
		p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, net)
		if err != nil {
			return "", "", "", fmt.Errorf("生成P2WPKH地址失败: %w", err)
		}
		address = p2wpkhAddr.String() // 如：bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq（主网）
	}

	return address, privateKey, publicKey, nil
}

// GenerateBtcAddressFromMnemonic 从外部BIP-39助记词生成比特币地址（已修复公钥问题）
func GenerateBtcAddressFromMnemonic(mnemonic, passphrase string, addrType BTCAddressType, net *chaincfg.Params, index uint32) (address string, privateKey []byte, publicKey string, err error) {
	// 1. 校验助记词
	if !bip39.IsMnemonicValid(mnemonic) {
		return "", []byte{}, "", errors.New("无效的BIP-39助记词（需12/18/24个单词）")
	}

	// 2. 生成Seed
	seed := bip39.NewSeed(mnemonic, passphrase)

	// 3. 创建HD主密钥（逻辑与钱包内方法一致）
	masterKey, err := hdkeychain.NewMaster(seed, net)
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("创建HD主密钥失败: %w", err)
	}

	// 4. 确定CoinType与派生路径
	var coinType uint32
	if net == BTCMainNet {
		coinType = BTCCoinTypeMainNet
	} else {
		coinType = BTCCoinTypeTestNet
	}

	var derivationPath string
	switch addrType {
	case BTCAddressTypeP2PKH:
		derivationPath = fmt.Sprintf("m/44'/%d'/0'/0/%d", coinType, index)
	case BTCAddressTypeP2WPKH:
		derivationPath = fmt.Sprintf("m/84'/%d'/0'/0/%d", coinType, index)
	default:
		return "", []byte{}, "", fmt.Errorf("不支持的地址类型: %s", addrType)
	}

	// 5. 派生子密钥
	path, err := hdwallet.ParseDerivationPath(derivationPath)
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("解析路径[%s]失败: %w", derivationPath, err)
	}

	childKey := masterKey
	for _, pathStep := range path {
		childKey, err = childKey.Derive(pathStep)
		if err != nil {
			return "", []byte{}, "", fmt.Errorf("派生步骤[%d]失败: %w", pathStep, err)
		}
	}

	// 6. 提取私钥（WIF）
	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("提取私钥失败: %w", err)
	}
	wif, err := btcutil.NewWIF(privKey, net, true)
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("生成WIF失败: %w", err)
	}
	privateKey = wif.PrivKey.Serialize()

	// 7. 提取公钥（Hex格式）—— 修复核心：处理错误+赋值公钥
	pubKey, err := childKey.ECPubKey()
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("提取EC公钥失败: %w", err)
	}
	// 修复1：处理SerializeCompressedHex的错误
	compressedHex, err := SerializeCompressedHex(pubKey)
	if err != nil {
		return "", []byte{}, "", fmt.Errorf("序列化压缩公钥失败: %w", err)
	}
	// 修复2：将Hex格式公钥赋值给返回变量（原代码缺失此步）
	publicKey = compressedHex

	// 8. 生成地址
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	switch addrType {
	case BTCAddressTypeP2PKH:
		p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, net)
		if err != nil {
			return "", []byte{}, "", fmt.Errorf("生成P2PKH地址失败: %w", err)
		}
		address = p2pkhAddr.String()
	case BTCAddressTypeP2WPKH:
		p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, net)
		if err != nil {
			return "", []byte{}, "", fmt.Errorf("生成P2WPKH地址失败: %w", err)
		}
		address = p2wpkhAddr.String()
	}
	return address, privateKey, publicKey, nil
}

// SerializeCompressedHex 将 btcec.PublicKey 压缩公钥转为 Hex 字符串（函数本身无问题，保留）
func SerializeCompressedHex(pubKey *btcec.PublicKey) (string, error) {
	if pubKey == nil {
		return "", errors.New("公钥不能为空")
	}
	// 1. 调用 btcec 自带方法获取压缩公钥字节流
	compressedPubKeyBytes := pubKey.SerializeCompressed()
	// 2. 字节流转 Hex 字符串（标准格式，带02/03前缀，区分公钥Y坐标奇偶）
	return hex.EncodeToString(compressedPubKeyBytes), nil
}

package wallet

import (
	"errors"
	"fmt"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

// 生成以太坊地址
// GenerateEthAddress 基于钱包助记词生成指定索引的以太坊地址
// index: 地址索引（从0开始，相同助记词可生成无限个地址）
// 返回：地址（Hex）、私钥（Hex）、公钥（Hex）、错误信息
func (w *Wallet) GenerateEthAddress(index uint32) (address, privateKey, publicKey string, err error) {
	// 并发安全锁（防止多协程同时操作助记词）
	w.mu.Lock()
	defer w.mu.Unlock()

	// 1. 校验钱包助记词有效性
	if !bip39.IsMnemonicValid(w.mnemonic) {
		return "", "", "", errors.New("钱包助记词无效")
	}

	// 2. 生成Seed（passphrase可存储为钱包私有字段，此处默认空）
	passphrase := ""
	seed := bip39.NewSeed(w.mnemonic, passphrase)

	// 3. 创建HD钱包
	hdWallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		return "", "", "", fmt.Errorf("创建HD钱包失败: %w", err)
	}

	// 4. 构建BIP-44派生路径（动态替换index）
	derivationPath := fmt.Sprintf("m/44'/60'/0'/0/%d", index)
	path, err := hdwallet.ParseDerivationPath(derivationPath)
	if err != nil {
		return "", "", "", fmt.Errorf("解析路径[%s]失败: %w", derivationPath, err)
	}

	// 5. 派生账户并提取密钥
	account, err := hdWallet.Derive(path, false)
	if err != nil {
		return "", "", "", fmt.Errorf("派生index=%d的账户失败: %w", index, err)
	}

	// 6. 获取私钥（敏感数据，需加密存储）
	privateKey, err = hdWallet.PrivateKeyHex(account)
	if err != nil {
		return "", "", "", fmt.Errorf("获取私钥失败: %w", err)
	}

	// 7. 获取公钥和地址
	publicKey, err = hdWallet.PublicKeyHex(account)
	if err != nil {
		return "", "", "", fmt.Errorf("获取公钥失败: %w", err)
	}
	address = account.Address.Hex()

	return address, privateKey, publicKey, nil
}

// GenerateEthAddressFromMnemonic 从BIP-39助记词生成以太坊地址
// mnemonic: BIP-39助记词（12/18/24个单词）
// passphrase: Seed加密密码（可选，增强安全性）
// index: 地址索引（从0开始）
// 返回：地址、私钥、公钥、错误信息
func GenerateEthAddressFromMnemonic(mnemonic, passphrase string, index uint32) (address, privateKey, publicKey string, err error) {
	// 1. 校验助记词格式
	if !bip39.IsMnemonicValid(mnemonic) {
		return "", "", "", errors.New("无效的BIP-39助记词（需12/18/24个单词）")
	}

	// 2. 生成Seed（助记词 + passphrase -> Seed）
	seed := bip39.NewSeed(mnemonic, passphrase)

	// 3. 创建HD钱包并派生地址（逻辑同Wallet方法）
	hdWallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		return "", "", "", fmt.Errorf("创建HD钱包失败: %w", err)
	}

	derivationPath := fmt.Sprintf("m/44'/60'/0'/0/%d", index)
	path, err := hdwallet.ParseDerivationPath(derivationPath)
	if err != nil {
		return "", "", "", fmt.Errorf("解析路径[%s]失败: %w", derivationPath, err)
	}

	account, err := hdWallet.Derive(path, false)
	if err != nil {
		return "", "", "", fmt.Errorf("派生账户失败: %w", err)
	}

	// 4. 提取密钥和地址
	privateKey, err = hdWallet.PrivateKeyHex(account)
	if err != nil {
		return "", "", "", fmt.Errorf("获取私钥失败: %w", err)
	}
	publicKey, err = hdWallet.PublicKeyHex(account)
	if err != nil {
		return "", "", "", fmt.Errorf("获取公钥失败: %w", err)
	}
	address = account.Address.Hex()

	return address, privateKey, publicKey, nil
}

package wallet

import (
	"errors"
	"fmt"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/bcrypt"
	"sync"
)

// Wallet 钱包结构体
// 包含余额和用于并发安全的互斥锁
// 包含
type Wallet struct {
	name         string  //名称
	balance      float64 //余额 单位聪 最小单位
	mnemonic     string  // 助记词（敏感，可恢复私钥）
	password     string  // 密码（用于加密私钥/助记词，或验证操作权限）
	passwordHash []byte  // 密码哈希（用于加密私钥/助记词及验证操作）
	passwordHint string  // 密码提示（帮助用户回忆密码）
	mu           sync.Mutex
}

func NewWallet(name, password, passwordHint string) (*Wallet, error) {
	// 简单的密码强度检查
	if len(password) < 8 {
		return nil, errors.New("密码长度不能少于8位")
	}

	// 生成BIP-39标准助记词
	mnemonic, err := generateBIP39Mnemonic()
	if err != nil {
		return nil, err
	}

	// 计算密码哈希（实际应用中应使用更复杂的哈希算法如bcrypt）
	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		name:         name,
		balance:      0, // 新钱包初始余额为0
		mnemonic:     mnemonic,
		passwordHash: passwordHash,
		passwordHint: passwordHint,
	}, nil
}

// 生成符合BIP-39标准的助记词
// 使用12个单词（128位熵 + 4位校验和）
// 生成符合BIP-39标准的助记词（12个单词，128位熵）
// 返回：助记词、错误信息
func generateBIP39Mnemonic() (string, error) {
	// 1. 生成128位熵（对应12个单词，熵长度需为32的倍数，128/256常用）
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", fmt.Errorf("生成熵失败: %w", err) // 返回错误而非终止程序
	}

	// 2. 从熵生成BIP-39助记词（需校验熵的有效性）
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("生成助记词失败: %w", err)
	}

	// 3. 从助记词生成Seed（passphrase可选，增强安全性，此处默认空字符串）
	passphrase := "" // 实际应用中应让用户自定义（非钱包密码，仅用于加密Seed）
	seed := bip39.NewSeed(mnemonic, passphrase)

	// 4. 创建HD钱包（基于Seed，遵循BIP-32标准）
	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		return "", fmt.Errorf("从Seed创建HD钱包失败: %w", err)
	}

	// 5. 以太坊BIP-44标准派生路径：m/44'/60'/0'/0/0
	// - 44': BIP-44协议标识
	// - 60': 以太坊的Coin Type（固定值，见BIP-44注册表）
	// - 0'/ 账户索引（默认0）
	// - 0/ 外部链（用于接收资金，固定0）
	// - 0 地址索引（从0开始，支持生成多个地址）
	path, err := hdwallet.ParseDerivationPath("m/44'/60'/0'/0/0")
	if err != nil {
		return "", fmt.Errorf("解析派生路径失败: %w", err)
	}

	// 6. 派生账户（false表示不永久存储到钱包，仅临时生成）
	account, err := wallet.Derive(path, false)
	if err != nil {
		return "", fmt.Errorf("派生以太坊账户失败: %w", err)
	}

	// 7. 提取地址、私钥、公钥（Hex格式，带0x前缀）
	address := account.Address.Hex()
	privateKey, err := wallet.PrivateKeyHex(account)
	if err != nil {
		return "", fmt.Errorf("获取私钥失败: %w", err)
	}
	publicKey, err := wallet.PublicKeyHex(account)
	if err != nil {
		return "", fmt.Errorf("获取公钥失败: %w", err)
	}

	// 打印调试信息（生产环境需删除，避免泄露敏感数据）
	fmt.Printf("=== 生成BIP-39助记词 ===\n%s\n", mnemonic)
	fmt.Printf("=== 以太坊地址（index=0） ===\n地址: %s\n私钥: %s\n公钥: %s\n", address, privateKey, publicKey)

	// 8. 返回生成的助记词（关键：修复原代码返回空字符串的问题）
	return mnemonic, nil
}

// 验证助记词是否符合BIP-39标准
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// 从助记词恢复钱包
func RestoreWallet(name, password, passwordHint, mnemonic string) (*Wallet, error) {
	// 验证助记词有效性
	if !ValidateMnemonic(mnemonic) {
		return nil, errors.New("无效的助记词")
	}

	// 密码强度检查
	if len(password) < 8 {
		return nil, errors.New("密码长度不能少于8位")
	}

	// 计算密码哈希
	passwordHash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	return &Wallet{
		name:         name,
		balance:      0, // 恢复的钱包需要重新同步余额
		mnemonic:     mnemonic,
		passwordHash: passwordHash,
		passwordHint: passwordHint,
	}, nil
}

// 密码哈希函数（实际应用中应使用更安全的算法）
func hashPassword(password string) ([]byte, error) {
	// bcrypt默认成本10，成本越高破解越难（建议12-14）
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// 验证密码
func (w *Wallet) verifyPassword(password string) bool {
	return bcrypt.CompareHashAndPassword(w.passwordHash, []byte(password)) == nil
}

// GetBalance 获取钱包余额（并发安全）
func (w *Wallet) GetBalance() float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.balance
}

// Deposit 存入金额（并发安全）
func (w *Wallet) Deposit(amount float64) error {
	if amount <= 0 {
		return errors.New("存入金额必须大于0")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.balance += amount
	return nil
}

// Withdraw 取出金额（并发安全）
func (w *Wallet) Withdraw(amount float64, password string) error {
	if amount <= 0 {
		return errors.New("取出金额必须大于0")
	}
	if !w.verifyPassword(password) {
		return errors.New("密码错误，无法完成取款")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.balance < amount {
		return errors.New("余额不足")
	}
	w.balance -= amount
	return nil
}

// GetName 获取钱包名称
func (w *Wallet) GetName() string {
	return w.name
}

// GetPasswordHint 获取密码提示
func (w *Wallet) GetPasswordHint() string {
	return w.passwordHint
}

// ExportMnemonic 导出助记词（需要密码验证，敏感操作）
func (w *Wallet) ExportMnemonic(password string) (string, error) {
	if !w.verifyPassword(password) {
		return "", errors.New("密码错误，无法导出助记词")
	}
	return w.mnemonic, nil
}

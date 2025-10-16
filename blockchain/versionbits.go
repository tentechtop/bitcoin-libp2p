// Copyright (c) 2016-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bitcoin/chaincfg/chainhash"
	"bitcoin/core"
)

const (
	vbLegacyBlockVersion = 4

	vbTopBits = 0x20000000

	vbTopMask = 0xe0000000

	vbNumBits = 29
)

type bitConditionChecker struct {
	bit   uint32
	chain *BlockChain
}

var _ thresholdConditionChecker = bitConditionChecker{}

func (c bitConditionChecker) HasStarted(_ *core.Block) bool {
	return true
}

func (c bitConditionChecker) HasEnded(_ *core.Block) bool {
	return false
}

func (c bitConditionChecker) MinerConfirmationWindow() uint32 {
	return c.chain.chainParams.MinerConfirmationWindow
}

func (c bitConditionChecker) RuleChangeActivationThreshold() uint32 {
	return c.chain.chainParams.RuleChangeActivationThreshold
}

func (c bitConditionChecker) Condition(node *core.Block) (bool, error) {
	conditionMask := uint32(1) << c.bit
	version := uint32(node.BlockHeader().Version)
	if version&vbTopMask != vbTopBits {
		return false, nil
	}
	if version&conditionMask == 0 {
		return false, nil
	}

	expectedVersion, err := c.chain.CalcNextBlockVersion(node.Hash())
	if err != nil {
		return false, err
	}
	return uint32(expectedVersion)&conditionMask == 0, nil
}

func (b *BlockChain) CalcNextBlockVersion(hash *chainhash.Hash) (int32, error) {
	//获取当前节点
	prevNode, err := b.GetBlockByHash(hash)
	if err != nil {
		return 1, nil
	}
	expectedVersion := uint32(vbTopBits)
	for id := 0; id < len(b.chainParams.Deployments); id++ {
		deployment := &b.chainParams.Deployments[id]
		cache := &b.deploymentCaches[id]
		checker := deploymentChecker{deployment: deployment, chain: b}
		state, err := b.thresholdState(prevNode, checker, cache)
		if err != nil {
			return 0, err
		}
		if state == ThresholdStarted || state == ThresholdLockedIn {
			expectedVersion |= uint32(1) << deployment.BitNumber
		}
	}
	return int32(expectedVersion), nil
}

func (b *BlockChain) warnUnknownRuleActivations(node *core.Block) error {
	// Warn if any unknown new rules are either about to activate or have
	// already been activated.
	for bit := uint32(0); bit < vbNumBits; bit++ {
		checker := bitConditionChecker{bit: bit, chain: b}
		cache := &b.warningCaches[bit]
		blockHash := node.BlockHeader().PrevBlock
		hash, err2 := b.GetBlockByHash(&blockHash)
		if err2 != nil {
			return nil
		}

		state, err := b.thresholdState(hash, checker, cache)
		if err != nil {
			return err
		}

		switch state {
		case ThresholdActive:
			if !b.unknownRulesWarned {
				log.Warnf("Unknown new rules activated (bit %d)",
					bit)
				b.unknownRulesWarned = true
			}
		case ThresholdLockedIn:
			window := int32(checker.MinerConfirmationWindow())
			activationHeight := window - (node.Height() % window)
			log.Warnf("Unknown new rules are about to activate in "+
				"%d blocks (bit %d)", activationHeight, bit)
		}
	}
	return nil
}

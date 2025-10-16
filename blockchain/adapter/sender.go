package adapter

import (
	"bitcoin/blockchain"
	"bitcoin/core"
	"bitcoin/event"
)

type ChainSender struct {
	bus *event.Bus
}

func NewChainSender(bus *event.Bus) *ChainSender {
	return &ChainSender{bus: bus}
}

func (c *ChainSender) BroadcastTx(tx *core.Tx) {
	//广播交易
	c.bus.Pub(event.Topic("user.tx.submit"), tx)
}

func (c *ChainSender) BroadcastBlock(block *core.Block) {
	c.bus.Pub(event.Topic("user.block.submit"), block)
}

func (c *ChainSender) SendHandshake(chain *blockchain.BestState) {
	c.bus.Pub(event.Topic("user.handshake.submit"), chain)
}

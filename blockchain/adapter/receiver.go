package adapter

import (
	"bitcoin/blockchain"
	"bitcoin/event"
	"fmt"
)

type ChainReceiver struct {
	bus   *event.Bus
	chain *blockchain.BlockChain
}

func NewChainChainReceiver(bus *event.Bus, chain *blockchain.BlockChain) *ChainReceiver {
	ci := &ChainReceiver{
		bus:   bus,
		chain: chain,
	}

	bus.Sub("net.block.received", ci.handleBlock)
	bus.Sub("net.tx.received", ci.handleTx)
	bus.Sub("net.peer.connected", ci.handleHandshake)
	return ci
}

func (c *ChainReceiver) handleBlock(e event.Event) {
	fmt.Println("chain 接收到")

}

func (c *ChainReceiver) handleTx(e event.Event) {

}

func (c *ChainReceiver) handleHandshake(e event.Event) {

}

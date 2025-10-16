package event

import "sync"

type Topic string

type Event any

type Handler func(e Event)

type Bus struct {
	mu   sync.RWMutex
	subs map[Topic][]Handler
}

// PeerConnectedEvent 网络层向业务层报告“已与某个节点建立连接”
type PeerConnectedEvent struct {
	PeerID string   // 对端 peer ID
	Addrs  []string // 对端多地址（可选，业务层想用时用）
}

// 让链层把“要对谁握手”以及“当前链快照”一起发出去
type SendHandshakeEvent struct {
	PeerID string      // 对端 peer.ID.String()
	Addrs  []string    // 对端 multiaddr 字符串
	Chain  interface{} // *blockchain.BlockChain 或其他需要的数据
}

func New() *Bus { return &Bus{subs: make(map[Topic][]Handler)} }

func (b *Bus) Sub(topic Topic, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[topic] = append(b.subs[topic], h)
}

func (b *Bus) Pub(topic Topic, e Event) {
	b.mu.RLock()
	handlers := append([]Handler(nil), b.subs[topic]...)
	b.mu.RUnlock()
	for _, h := range handlers {
		go h(e)
	}
}

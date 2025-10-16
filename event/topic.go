package event

// 网络层 -> 业务层
const (
	NetBlockReceived Topic = "net.block.received"
	NetTxReceived    Topic = "net.tx.received"
	NetPeerConnected Topic = "net.peer.connected"
)

// 业务层 -> 网络层
const (
	UserSendHandshake Topic = "user.sendHandshake.submit"
	UserTxSubmit      Topic = "user.tx.submit"
	UserBlockSubmit   Topic = "user.block.submit"
)

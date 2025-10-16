package blockchain

import "fmt"

type NotificationType int

type NotificationCallback func(*Notification)

const (
	NTBlockAccepted NotificationType = iota
	NTBlockConnected
	NTBlockDisconnected

	NTPeerConnected
	NTPeerDisconnected
)

var notificationTypeStrings = map[NotificationType]string{
	NTBlockAccepted:     "NTBlockAccepted",
	NTBlockConnected:    "NTBlockConnected",
	NTBlockDisconnected: "NTBlockDisconnected",

	NTPeerConnected:    "NTPeerConnected",
	NTPeerDisconnected: "NTPeerDisconnected",
}

func (n NotificationType) String() string {
	if s, ok := notificationTypeStrings[n]; ok {
		return s
	}
	return fmt.Sprintf("Unknown Notification Type (%d)", int(n))
}

type Notification struct {
	Type NotificationType
	Data interface{}
}

func (b *BlockChain) Subscribe(callback NotificationCallback) {
	b.notificationsLock.Lock()
	b.notifications = append(b.notifications, callback)
	b.notificationsLock.Unlock()
}

func (b *BlockChain) sendNotification(typ NotificationType, data interface{}) {
	n := Notification{Type: typ, Data: data}
	b.notificationsLock.RLock()
	// 复制一份回调列表，避免解锁后列表被修改
	callbacks := make([]NotificationCallback, len(b.notifications))
	copy(callbacks, b.notifications)
	b.notificationsLock.RUnlock() // 提前释放读锁

	// 异步执行所有回调
	for _, callback := range callbacks {
		go callback(&n) // 注意：需确保 n 的生命周期覆盖回调执行时间
	}
}

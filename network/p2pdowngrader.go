package network

import "github.com/decred/dcrd/lru"

const (
	defaultDowngradeCacheSize = 100
)

type P2PDowngrader struct {
	cache lru.Cache
}

func NewP2PDowngrader(cacheSize uint) *P2PDowngrader {
	if cacheSize == 0 {
		cacheSize = defaultDowngradeCacheSize
	}
	return &P2PDowngrader{
		cache: lru.NewCache(cacheSize),
	}
}

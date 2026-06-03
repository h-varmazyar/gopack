package jwt

import (
	"sync"
	"time"
)

type memoryTokenBlacklistStore struct {
	sync.RWMutex
	data map[string]int64
}

func newMemoryTokenBlacklistStore() *memoryTokenBlacklistStore {
	return &memoryTokenBlacklistStore{data: make(map[string]int64)}
}

func (m *memoryTokenBlacklistStore) InvalidateToken(jti string, expiresAt int64) error {
	m.Lock()
	defer m.Unlock()
	m.data[jti] = expiresAt
	return nil
}

func (m *memoryTokenBlacklistStore) IsTokenInvalidated(jti string) (bool, error) {
	m.Lock()
	defer m.Unlock()
	if expiry, ok := m.data[jti]; ok {
		if expiry == 0 || expiry > time.Now().Unix() {
			return true, nil
		}
		delete(m.data, jti)
	}
	return false, nil
}

func (m *memoryTokenBlacklistStore) CleanupExpired() error {
	m.Lock()
	defer m.Unlock()
	now := time.Now().Unix()
	for jti, expiry := range m.data {
		if expiry != 0 && expiry <= now {
			delete(m.data, jti)
		}
	}
	return nil
}

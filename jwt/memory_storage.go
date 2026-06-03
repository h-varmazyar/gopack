package jwt

import (
	"errors"
	"sync"
)

type memoryClaimsStore struct {
	sync.RWMutex
	data map[string]*AuthClaims
}

func newMemoryClaimsStore() *memoryClaimsStore {
	return &memoryClaimsStore{data: make(map[string]*AuthClaims)}
}

func (m *memoryClaimsStore) SaveClaims(claims *AuthClaims) error {
	if claims == nil || claims.Id == "" {
		return errors.New("invalid claims: missing JTI")
	}
	m.Lock()
	defer m.Unlock()
	m.data[claims.Id] = claims
	return nil
}

func (m *memoryClaimsStore) GetClaims(jti string) (*AuthClaims, error) {
	m.Lock()
	defer m.Unlock()
	if claims, ok := m.data[jti]; ok {
		return claims, nil
	}
	return nil, errors.New("claims not found")
}

func (m *memoryClaimsStore) DeleteClaims(jti string) error {
	m.Lock()
	defer m.Unlock()
	delete(m.data, jti)
	return nil
}

package jwt

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type gormTokenBlacklistRecord struct {
	ID        uint `gorm:"primaryKey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	JTI       string `gorm:"uniqueIndex;size:128"`
	ExpiresAt int64  `gorm:"index"`
}

type gormTokenBlacklistStore struct {
	db *gorm.DB
}

func NewGormTokenBlacklistStore(db *gorm.DB) (TokenBlacklistStore, error) {
	if db == nil {
		return nil, errors.New("gorm DB is nil")
	}
	record := &gormTokenBlacklistRecord{}
	if err := db.AutoMigrate(record); err != nil {
		return nil, err
	}
	return &gormTokenBlacklistStore{db: db}, nil
}

func (s *gormTokenBlacklistStore) InvalidateToken(jti string, expiresAt int64) error {
	record := gormTokenBlacklistRecord{JTI: jti, ExpiresAt: expiresAt}
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "jti"}},
		DoUpdates: clause.AssignmentColumns([]string{"expires_at", "updated_at"}),
	}).Create(&record).Error
}

func (s *gormTokenBlacklistStore) IsTokenInvalidated(jti string) (bool, error) {
	var record gormTokenBlacklistRecord
	err := s.db.Where("jti = ?", jti).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	if record.ExpiresAt == 0 || record.ExpiresAt > now {
		return true, nil
	}
	_ = s.db.Delete(&record).Error
	return false, nil
}

func (s *gormTokenBlacklistStore) CleanupExpired() error {
	return s.db.Where("expires_at <= ?", time.Now().Unix()).Delete(&gormTokenBlacklistRecord{}).Error
}

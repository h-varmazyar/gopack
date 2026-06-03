package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type gormClaimsRecord struct {
	gorm.Model
	JTI       string `gorm:"uniqueIndex;size:128"`
	UserID    string `gorm:"index;size:128"`
	Username  string `gorm:"size:256"`
	Subject   string `gorm:"size:256"`
	Issuer    string `gorm:"size:256"`
	IssuedAt  int64  `gorm:"index"`
	ExpiresAt int64  `gorm:"index"`
	Extra     string `gorm:"type:text"` // JSON encoded
}

type gormClaimsStore struct {
	db *gorm.DB
}

func (s *gormClaimsStore) TableName() string {
	return "jwt_users_tokens"
}

func NewGormClaimsStore(db *gorm.DB) (ClaimsStore, error) {
	if db == nil {
		return nil, errors.New("gorm DB is nil")
	}
	record := &gormClaimsRecord{}
	if err := db.AutoMigrate(record); err != nil {
		return nil, err
	}
	return &gormClaimsStore{db: db}, nil
}

func (s *gormClaimsStore) SaveClaims(claims *AuthClaims) error {
	if claims == nil || claims.Id == "" {
		return errors.New("invalid claims: missing JTI")
	}

	record := gormClaimsRecord{
		JTI:       claims.Id,
		UserID:    claims.UserID,
		Username:  claims.Username,
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}
	return s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "jti"}},
		DoUpdates: clause.AssignmentColumns([]string{"user_id", "username", "subject", "issuer", "issued_at", "expires_at", "updated_at"}),
	}).Create(&record).Error
}

func (s *gormClaimsStore) GetClaims(jti string) (*AuthClaims, error) {
	var record gormClaimsRecord
	err := s.db.Where("jti = ?", jti).First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("claims not found")
	}
	if err != nil {
		return nil, err
	}

	claims := &AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        record.JTI,
			Subject:   record.Subject,
			Issuer:    record.Issuer,
			IssuedAt:  record.IssuedAt,
			ExpiresAt: record.ExpiresAt,
		},
		UserID:   record.UserID,
		Username: record.Username,
	}
	return claims, nil
}

func (s *gormClaimsStore) DeleteClaims(jti string) error {
	return s.db.Where("jti = ?", jti).Delete(&gormClaimsRecord{}).Error
}

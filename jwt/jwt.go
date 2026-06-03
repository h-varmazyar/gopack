package jwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/h-varmazyar/gopack/env"
)

type TokenBlacklistStore interface {
	InvalidateToken(jti string, expiresAt int64) error
	IsTokenInvalidated(jti string) (bool, error)
	CleanupExpired() error
}

type SigningMethod string

const (
	RS256          SigningMethod = "rs256"
	defaultExpires time.Duration = time.Minute * 15
)

type Configs struct {
	PublicKey   string        `env:"JWT_PUBLIC_KEY, required, file"`
	PrivateKey  string        `env:"JWT_PRIVATE_KEY, file"`
	Method      SigningMethod `env:"SIGNING_METHOD"`
	method      jwt.SigningMethod
	verifyToken *rsa.PublicKey
	signKey     *rsa.PrivateKey
}

type LoginOptions struct {
	UserID    string
	Username  string
	Subject   string
	Issuer    string
	ExpiresIn time.Duration
	Extra     map[string]interface{}
}

var (
	configs        *Configs
	blacklistStore TokenBlacklistStore = newMemoryTokenBlacklistStore()
)

func SetTokenBlacklistStore(store TokenBlacklistStore) {
	if store == nil {
		blacklistStore = newMemoryTokenBlacklistStore()
		return
	}
	blacklistStore = store
}

func LoadFromEnv(path string) (*Configs, error) {
	var err error
	configs = new(Configs)
	if err = env.Load(path, configs); err != nil {
		return nil, err
	}
	if err = Load(configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func Load(remote *Configs) error {
	configs = remote
	var err error
	if configs.PublicKey == "" {
		return errors.New("invalid public key")
	}
	configs.verifyToken, err = jwt.ParseRSAPublicKeyFromPEM([]byte(configs.PublicKey))
	if err != nil {
		return err
	}
	if configs.PrivateKey != "" {
		configs.signKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(configs.PrivateKey))
		if err != nil {
			return err
		}
	}
	configs.castMethod()
	return nil
}

func (configs *Configs) castMethod() {
	switch configs.Method {
	case RS256:
		configs.method = jwt.SigningMethodRS256
	default:
		configs.method = jwt.SigningMethodNone
	}
}

func Login(opts LoginOptions) (string, error) {
	if configs == nil {
		return "", errors.New("jwt is not initialized")
	}
	if configs.method != jwt.SigningMethodNone && configs.signKey == nil {
		return "", errors.New("signing key is not configured")
	}
	if opts.ExpiresIn <= 0 {
		opts.ExpiresIn = defaultExpires
	}

	now := time.Now().Unix()
	claims := AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        uuid.NewString(),
			Issuer:    opts.Issuer,
			Subject:   opts.Subject,
			IssuedAt:  now,
			ExpiresAt: now + int64(opts.ExpiresIn.Seconds()),
		},
		UserID:   opts.UserID,
		Username: opts.Username,
		Extra:    opts.Extra,
	}

	if claims.Subject == "" {
		if claims.UserID != "" {
			claims.Subject = claims.UserID
		} else {
			claims.Subject = claims.Username
		}
	}

	if claims.Issuer == "" {
		claims.Issuer = "gopack"
	}

	return SignClaims(claims)
}

func Logout(token string) error {
	claims, err := ValidateAuth(token)
	if err != nil {
		return err
	}
	jti := tokenIdentifier(claims, token)
	return blacklistStore.InvalidateToken(jti, claims.ExpiresAt)
}

func ValidateAuth(token string) (*AuthClaims, error) {
	if configs == nil {
		return nil, errors.New("jwt is not initialized")
	}

	t, err := jwt.ParseWithClaims(token, new(AuthClaims), func(token *jwt.Token) (interface{}, error) {
		return configs.verifyToken, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := t.Claims.(*AuthClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	blacklisted, err := isTokenBlacklisted(tokenIdentifier(claims, token))
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, errors.New("token has been invalidated")
	}

	return claims, nil
}

func ParseAuthClaims(token string) (*AuthClaims, error) {
	return ValidateAuth(token)
}

func SignClaims(claims jwt.Claims) (string, error) {
	if configs == nil {
		return "", errors.New("jwt is not initialized")
	}
	if configs.method != jwt.SigningMethodNone && configs.signKey == nil {
		return "", errors.New("signing key is not configured")
	}

	token := jwt.NewWithClaims(configs.method, claims)
	return token.SignedString(configs.signKey)
}

func tokenIdentifier(claims *AuthClaims, rawToken string) string {
	if claims != nil && claims.Id != "" {
		return claims.Id
	}
	checksum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(checksum[:])
}

func isTokenBlacklisted(jti string) (bool, error) {
	return blacklistStore.IsTokenInvalidated(jti)
}

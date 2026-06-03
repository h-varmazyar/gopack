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

// type TokenBlacklistStore interface {
// 	InvalidateToken(jti string, expiresAt int64) error
// 	IsTokenInvalidated(jti string) (bool, error)
// 	CleanupExpired() error
// }

type ClaimsStore interface {
	SaveClaims(claims *AuthClaims) error
	GetClaims(jti string) (*AuthClaims, error)
	DeleteClaims(jti string) error
}

type SigningMethod string

const (
	RS256          SigningMethod = "rs256"
	HS256          SigningMethod = "hs256"
	HS384          SigningMethod = "hs384"
	HS512          SigningMethod = "hs512"
	defaultExpires time.Duration = time.Minute * 15
)

type Configs struct {
	PublicKey   string        `env:"JWT_PUBLIC_KEY, file"`
	PrivateKey  string        `env:"JWT_PRIVATE_KEY, file"`
	SecretKey   string        `env:"JWT_SECRET_KEY"`
	Method      SigningMethod `env:"SIGNING_METHOD"`
	method      jwt.SigningMethod
	verifyToken *rsa.PublicKey
	signKey     *rsa.PrivateKey
	secretKey   []byte
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
	configs *Configs
	// blacklistStore TokenBlacklistStore = newMemoryTokenBlacklistStore()
	claimsStore ClaimsStore = newMemoryClaimsStore()
)

func SetClaimStore(store ClaimsStore) {
	if store == nil {
		claimsStore = newMemoryClaimsStore()
		return
	}
	claimsStore = store
}

func SetClaimsStore(store ClaimsStore) {
	if store == nil {
		claimsStore = newMemoryClaimsStore()
		return
	}
	claimsStore = store
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

	// Determine if using HMAC or RSA
	isHMAC := configs.Method == HS256 || configs.Method == HS384 || configs.Method == HS512

	if isHMAC {
		// HMAC requires secret key
		if configs.SecretKey == "" {
			return errors.New("secret key is required for HMAC signing")
		}
		configs.secretKey = []byte(configs.SecretKey)
	} else {
		// RSA requires public key
		if configs.PublicKey == "" {
			return errors.New("public key is required for RSA signing")
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
	}

	configs.castMethod()
	return nil
}

func (configs *Configs) castMethod() {
	switch configs.Method {
	case RS256:
		configs.method = jwt.SigningMethodRS256
	case HS256:
		configs.method = jwt.SigningMethodHS256
	case HS384:
		configs.method = jwt.SigningMethodHS384
	case HS512:
		configs.method = jwt.SigningMethodHS512
	default:
		configs.method = jwt.SigningMethodNone
	}
}

func Login(opts LoginOptions) (string, error) {
	if configs == nil {
		return "", errors.New("jwt is not initialized")
	}
	isHMAC := configs.Method == HS256 || configs.Method == HS384 || configs.Method == HS512
	if !isHMAC && configs.method != jwt.SigningMethodNone && configs.signKey == nil {
		return "", errors.New("signing key is not configured")
	}
	if isHMAC && len(configs.secretKey) == 0 {
		return "", errors.New("secret key is not configured")
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

	// Save claims to store before signing
	if err := claimsStore.SaveClaims(&claims); err != nil {
		return "", err
	}

	return SignClaims(claims)
}

func Logout(token string) error {
	claims, err := ValidateAuth(token)
	if err != nil {
		return err
	}
	jti := tokenIdentifier(claims, token)
	return claimsStore.DeleteClaims(jti)
}

func ValidateAuth(token string) (*AuthClaims, error) {
	if configs == nil {
		return nil, errors.New("jwt is not initialized")
	}

	t, err := jwt.ParseWithClaims(token, new(AuthClaims), func(token *jwt.Token) (interface{}, error) {
		isHMAC := configs.Method == HS256 || configs.Method == HS384 || configs.Method == HS512
		if isHMAC {
			return configs.secretKey, nil
		}
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

	claimsFromStore, err := claimsStore.GetClaims(claims.Id)
	if err != nil {
		return nil, err
	}

	// Optional: Compare claims from token with those in store for consistency
	if claimsFromStore.UserID != claims.UserID || claimsFromStore.Username != claims.Username {
		return nil, errors.New("token claims do not match stored claims")
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

	isHMAC := configs.Method == HS256 || configs.Method == HS384 || configs.Method == HS512
	if isHMAC {
		if len(configs.secretKey) == 0 {
			return "", errors.New("secret key is not configured")
		}
		token := jwt.NewWithClaims(configs.method, claims)
		return token.SignedString(configs.secretKey)
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

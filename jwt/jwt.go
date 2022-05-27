package jwt

import (
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/h-varmazyar/gopack/env"
)

type SigningMethod string

type Configs struct {
	PublicKey   string        `env:"JWT_PUBLIC_KEY, required, file"`
	PrivateKey  string        `env:"JWT_PRIVATE_KEY, file"`
	Method      SigningMethod `env:"SIGNING_METHOD"`
	method      jwt.SigningMethod
	verifyToken *rsa.PublicKey
	signKey     *rsa.PrivateKey
}

const (
	RS256 SigningMethod = "rs256"
)

func LoadFromEnv(path string) (*Configs, error) {
	var err error
	configs := new(Configs)
	if err = env.Load(path, configs); err != nil {
		return nil, err
	}
	if err = Load(configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func Load(configs *Configs) error {
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

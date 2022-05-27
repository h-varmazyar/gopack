package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt"
)

type BasicClaims struct {
	jwt.StandardClaims
	Username string
}

func (configs *Configs) SignClaims(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(configs.method, claims)
	tokenString, err := token.SignedString(configs.signKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (configs *Configs) ValidateAuth(token string) (*BasicClaims, error) {
	t, err := jwt.ParseWithClaims(token, new(BasicClaims), func(token *jwt.Token) (interface{}, error) {
		return configs.verifyToken, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid token")
	}
	return t.Claims.(*BasicClaims), nil
}

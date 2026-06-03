package jwt

import (
	"github.com/golang-jwt/jwt"
)

type AuthClaims struct {
	jwt.StandardClaims
	UserID   string                 `json:"user_id,omitempty"`
	Username string                 `json:"username,omitempty"`
	Extra    map[string]interface{} `json:"extra,omitempty"`
}

type BasicClaims = AuthClaims

func (c AuthClaims) Valid() error {
	return c.StandardClaims.Valid()
}

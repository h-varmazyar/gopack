package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func generatePEMKeys(t *testing.T) (privatePEM, publicPEM string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}))

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	publicPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return
}

func TestLoginValidateLogout(t *testing.T) {
	privatePEM, publicPEM := generatePEMKeys(t)

	cfg := &Configs{
		PublicKey:  publicPEM,
		PrivateKey: privatePEM,
		Method:     RS256,
	}
	if err := Load(cfg); err != nil {
		t.Fatalf("failed to load jwt config: %v", err)
	}

	token, err := Login(LoginOptions{
		UserID:    "user-1",
		Username:  "alice",
		ExpiresIn: time.Minute,
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	claims, err := ValidateAuth(token)
	if err != nil {
		t.Fatalf("ValidateAuth failed: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Fatalf("expected UserID user-1, got %s", claims.UserID)
	}
	if claims.Username != "alice" {
		t.Fatalf("expected Username alice, got %s", claims.Username)
	}

	if err := Logout(token); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if _, err := ValidateAuth(token); err == nil {
		t.Fatal("expected invalidated token to fail validation")
	}
}

func TestSignClaims(t *testing.T) {
	privatePEM, publicPEM := generatePEMKeys(t)

	cfg := &Configs{
		PublicKey:  publicPEM,
		PrivateKey: privatePEM,
		Method:     RS256,
	}
	if err := Load(cfg); err != nil {
		t.Fatalf("failed to load jwt config: %v", err)
	}

	claims := AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        "token-1",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute).Unix(),
		},
		UserID:   "user-2",
		Username: "bob",
	}

	token, err := SignClaims(claims)
	if err != nil {
		t.Fatalf("SignClaims failed: %v", err)
	}

	parsed, err := ValidateAuth(token)
	if err != nil {
		t.Fatalf("ValidateAuth failed: %v", err)
	}
	if parsed.UserID != "user-2" {
		t.Fatalf("expected UserID user-2, got %s", parsed.UserID)
	}
	if parsed.Username != "bob" {
		t.Fatalf("expected Username bob, got %s", parsed.Username)
	}
}

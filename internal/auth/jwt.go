package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/i-dj/oauth-broker/internal/config"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	Subject   string `json:"sub"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	JWTID     string `json:"jti"`
	Type      string `json:"typ"`
}

type JWTService struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
}

func NewJWTService(cfg config.AuthConfig) *JWTService {
	return &JWTService{
		secret:   []byte(cfg.JWTSecret),
		issuer:   cfg.JWTIssuer,
		audience: cfg.JWTAudience,
		ttl:      cfg.AccessTokenTTL,
	}
}

func (s *JWTService) Issue(deviceID string) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)
	jti, err := randomID(16)
	if err != nil {
		return "", time.Time{}, err
	}
	claims := Claims{
		Subject:   deviceID,
		Issuer:    s.issuer,
		Audience:  s.audience,
		ExpiresAt: expiresAt.Unix(),
		IssuedAt:  now.Unix(),
		JWTID:     jti,
		Type:      "access",
	}
	token, err := s.sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *JWTService) Validate(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	expected := hmacSHA256(s.secret, []byte(signingInput))
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !hmac.Equal(expected, actual) {
		return nil, ErrInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	now := time.Now().UTC().Unix()
	if claims.Type != "access" || claims.Subject == "" || claims.Issuer != s.issuer || claims.Audience != s.audience || claims.ExpiresAt <= now {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func (s *JWTService) sign(claims Claims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := hmacSHA256(s.secret, []byte(signingInput))
	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(sig)), nil
}

func hmacSHA256(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

func randomID(byteLength int) (string, error) {
	buffer := make([]byte, byteLength)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

package config

import (
	"strings"
	"time"
)

type AuthConfig struct {
	JWTSecret              string
	JWTIssuer              string
	JWTAudience            string
	AccessTokenTTL         time.Duration
	SignatureClockSkew     time.Duration
	RegistrationSecret     string
	RegistrationSecretUsed bool
}

func LoadAuth() (AuthConfig, error) {
	accessTTL, err := envDuration("JWT_ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return AuthConfig{}, err
	}
	skew, err := envDuration("DEVICE_SIGNATURE_CLOCK_SKEW", 5*time.Minute)
	if err != nil {
		return AuthConfig{}, err
	}
	registrationSecret := strings.TrimSpace(envOrDefault("DEVICE_REGISTRATION_SECRET", ""))
	return AuthConfig{
		JWTSecret:              envOrDefault("JWT_SECRET", "dev-only-change-me"),
		JWTIssuer:              envOrDefault("JWT_ISSUER", "yesnas-oauth-broker"),
		JWTAudience:            envOrDefault("JWT_AUDIENCE", "yesnas-nas"),
		AccessTokenTTL:         accessTTL,
		SignatureClockSkew:     skew,
		RegistrationSecret:     registrationSecret,
		RegistrationSecretUsed: registrationSecret != "",
	}, nil
}

package config

import (
	"errors"
	"strings"
	"time"
)

type ServerConfig struct {
	ListenAddr      string
	PublicBaseURL   string
	SessionTTL      time.Duration
	CleanupInterval time.Duration
	LogFile         string
}

func LoadServer() (ServerConfig, error) {
	sessionTTL, err := envDuration("SESSION_TTL", 10*time.Minute)
	if err != nil {
		return ServerConfig{}, err
	}
	cleanupInterval, err := envDuration("SESSION_CLEANUP_INTERVAL", time.Minute)
	if err != nil {
		return ServerConfig{}, err
	}
	cfg := ServerConfig{
		ListenAddr:      envOrDefault("LISTEN_ADDR", ":8080"),
		PublicBaseURL:   strings.TrimRight(envOrDefault("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
		SessionTTL:      sessionTTL,
		CleanupInterval: cleanupInterval,
		LogFile:         envOrDefault("LOG_FILE", "logs/oauth-broker.log"),
	}
	if cfg.PublicBaseURL == "" {
		return ServerConfig{}, errors.New("PUBLIC_BASE_URL must not be empty")
	}
	if cfg.SessionTTL <= 0 {
		return ServerConfig{}, errors.New("SESSION_TTL must be greater than zero")
	}
	if cfg.CleanupInterval <= 0 {
		return ServerConfig{}, errors.New("SESSION_CLEANUP_INTERVAL must be greater than zero")
	}
	return cfg, nil
}

package config

import (
	"errors"
	"strings"
)

type DatabaseConfig struct {
	URL string
}

func LoadDatabase() (DatabaseConfig, error) {
	cfg := DatabaseConfig{URL: strings.TrimSpace(envOrDefault("DATABASE_URL", ""))}
	if cfg.URL == "" {
		return DatabaseConfig{}, errors.New("DATABASE_URL must not be empty")
	}
	return cfg, nil
}

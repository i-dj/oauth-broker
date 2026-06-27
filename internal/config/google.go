package config

import (
	"errors"
	"os"
	"strings"
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleScope    = "https://www.googleapis.com/auth/drive"
)

type GoogleConfig struct {
	OAuth OAuthConfig
}

func LoadGoogle(publicBaseURL string) (GoogleConfig, error) {
	cfg := GoogleConfig{OAuth: OAuthConfig{
		ClientID:     strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_SECRET")),
		RedirectURL:  strings.TrimSpace(os.Getenv("GOOGLE_REDIRECT_URL")),
		AuthURL:      googleAuthURL,
		TokenURL:     googleTokenURL,
		Scopes:       []string{googleScope},
	}}
	if scopes := splitCSV(os.Getenv("GOOGLE_SCOPES")); len(scopes) > 0 {
		cfg.OAuth.Scopes = scopes
	}
	if cfg.OAuth.RedirectURL == "" {
		cfg.OAuth.RedirectURL = strings.TrimRight(publicBaseURL, "/") + "/api/oauth/google/callback"
	}
	if err := cfg.Validate(); err != nil {
		return GoogleConfig{}, err
	}
	return cfg, nil
}

func (c GoogleConfig) Validate() error {
	if c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" {
		return errors.New("set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
	}
	if c.OAuth.RedirectURL == "" {
		return errors.New("google redirect URL is empty")
	}
	if c.OAuth.AuthURL == "" || c.OAuth.TokenURL == "" {
		return errors.New("google OAuth endpoints are incomplete")
	}
	if len(c.OAuth.Scopes) == 0 {
		return errors.New("google OAuth scopes are empty")
	}
	return nil
}

package config

import (
	"errors"
	"os"
	"strings"
)

const (
	oneDriveAuthURL  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	oneDriveTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
)

type OneDriveConfig struct {
	OAuth   OAuthConfig
	Enabled bool
}

func LoadOneDrive(publicBaseURL string) (OneDriveConfig, error) {
	cfg := OneDriveConfig{OAuth: OAuthConfig{
		ClientID:     strings.TrimSpace(os.Getenv("ONEDRIVE_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("ONEDRIVE_CLIENT_SECRET")),
		RedirectURL:  strings.TrimSpace(os.Getenv("ONEDRIVE_REDIRECT_URL")),
		AuthURL:      oneDriveAuthURL,
		TokenURL:     oneDriveTokenURL,
		Scopes:       []string{"offline_access", "Files.ReadWrite"},
	}}
	if scopes := splitCSV(os.Getenv("ONEDRIVE_SCOPES")); len(scopes) > 0 {
		cfg.OAuth.Scopes = scopes
	}
	cfg.Enabled = cfg.OAuth.ClientID != "" || cfg.OAuth.ClientSecret != ""
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.OAuth.RedirectURL == "" {
		cfg.OAuth.RedirectURL = strings.TrimRight(publicBaseURL, "/") + "/api/oauth/onedrive/callback"
	}
	return cfg, cfg.Validate()
}

func (c OneDriveConfig) Validate() error {
	if c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" {
		return errors.New("set ONEDRIVE_CLIENT_ID and ONEDRIVE_CLIENT_SECRET")
	}
	if c.OAuth.RedirectURL == "" {
		return errors.New("onedrive redirect URL is empty")
	}
	if c.OAuth.AuthURL == "" || c.OAuth.TokenURL == "" {
		return errors.New("onedrive OAuth endpoints are incomplete")
	}
	if len(c.OAuth.Scopes) == 0 {
		return errors.New("onedrive OAuth scopes are empty")
	}
	return nil
}

package config

import (
	"errors"
	"os"
	"strings"
)

const (
	dropboxAuthURL  = "https://www.dropbox.com/oauth2/authorize"
	dropboxTokenURL = "https://api.dropboxapi.com/oauth2/token"
)

type DropboxConfig struct {
	OAuth   OAuthConfig
	Enabled bool
}

func LoadDropbox(publicBaseURL string) (DropboxConfig, error) {
	cfg := DropboxConfig{OAuth: OAuthConfig{
		ClientID:     strings.TrimSpace(os.Getenv("DROPBOX_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("DROPBOX_CLIENT_SECRET")),
		RedirectURL:  strings.TrimSpace(os.Getenv("DROPBOX_REDIRECT_URL")),
		AuthURL:      dropboxAuthURL,
		TokenURL:     dropboxTokenURL,
		Scopes: []string{
			"files.metadata.read",
			"files.metadata.write",
			"files.content.read",
			"files.content.write",
		},
	}}
	if scopes := splitCSV(os.Getenv("DROPBOX_SCOPES")); len(scopes) > 0 {
		cfg.OAuth.Scopes = scopes
	}
	cfg.Enabled = cfg.OAuth.ClientID != "" || cfg.OAuth.ClientSecret != ""
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.OAuth.RedirectURL == "" {
		cfg.OAuth.RedirectURL = strings.TrimRight(publicBaseURL, "/") + "/api/oauth/dropbox/callback"
	}
	return cfg, cfg.Validate()
}

func (c DropboxConfig) Validate() error {
	if c.OAuth.ClientID == "" || c.OAuth.ClientSecret == "" {
		return errors.New("set DROPBOX_CLIENT_ID and DROPBOX_CLIENT_SECRET")
	}
	if c.OAuth.RedirectURL == "" {
		return errors.New("dropbox redirect URL is empty")
	}
	if c.OAuth.AuthURL == "" || c.OAuth.TokenURL == "" {
		return errors.New("dropbox OAuth endpoints are incomplete")
	}
	if len(c.OAuth.Scopes) == 0 {
		return errors.New("dropbox OAuth scopes are empty")
	}
	return nil
}

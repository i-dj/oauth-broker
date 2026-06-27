package provider

import (
	"context"
	"errors"

	"github.com/i-dj/oauth-broker/internal/config"
	"github.com/i-dj/oauth-broker/internal/model"
	"golang.org/x/oauth2"
)

type GoogleProvider struct {
	config oauth2.Config
}

func NewGoogle(cfg config.GoogleConfig) (*GoogleProvider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &GoogleProvider{config: oauth2.Config{
		ClientID:     cfg.OAuth.ClientID,
		ClientSecret: cfg.OAuth.ClientSecret,
		RedirectURL:  cfg.OAuth.RedirectURL,
		Scopes:       cfg.OAuth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.OAuth.AuthURL,
			TokenURL: cfg.OAuth.TokenURL,
		},
	}}, nil
}

func (p *GoogleProvider) Name() string { return "google" }

func (p *GoogleProvider) AuthURL(req AuthRequest) (string, error) {
	if req.State == "" || req.PKCEVerifier == "" {
		return "", errors.New("state and PKCE verifier are required")
	}
	return p.config.AuthCodeURL(
		req.State,
		oauth2.AccessTypeOffline,
		oauth2.ApprovalForce,
		oauth2.S256ChallengeOption(req.PKCEVerifier),
	), nil
}

func (p *GoogleProvider) Exchange(ctx context.Context, req ExchangeRequest) (*model.TokenSet, error) {
	if req.Code == "" || req.PKCEVerifier == "" {
		return nil, errors.New("authorization code and PKCE verifier are required")
	}
	token, err := p.config.Exchange(ctx, req.Code, oauth2.VerifierOption(req.PKCEVerifier))
	if err != nil {
		return nil, err
	}
	return oauthTokenToModel(token), nil
}

func (p *GoogleProvider) Refresh(ctx context.Context, token *model.TokenSet) (*model.TokenSet, error) {
	if token == nil || token.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}
	source := p.config.TokenSource(ctx, &oauth2.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	})
	newToken, err := source.Token()
	if err != nil {
		return nil, err
	}
	result := oauthTokenToModel(newToken)
	if result.RefreshToken == "" {
		result.RefreshToken = token.RefreshToken
	}
	return result, nil
}

func oauthTokenToModel(token *oauth2.Token) *model.TokenSet {
	return &model.TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
	}
}

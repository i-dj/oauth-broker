package model

import "time"

type SessionStatus string

const (
	SessionPending     SessionStatus = "pending"
	SessionAuthorizing SessionStatus = "authorizing"
	SessionSuccess     SessionStatus = "success"
	SessionFailed      SessionStatus = "failed"
	SessionUsed        SessionStatus = "used"
	SessionCancelled   SessionStatus = "cancelled"
	SessionExpired     SessionStatus = "expired"
)

type TokenSet struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	TokenType    string         `json:"token_type,omitempty"`
	Expiry       time.Time      `json:"expiry,omitempty"`
	Extra        map[string]any `json:"extra,omitempty"`
}

type OAuthSession struct {
	ID           string
	DeviceID     string
	Provider     string
	State        string
	PKCEVerifier string
	Status       SessionStatus
	Token        *TokenSet
	ErrorCode    string
	ErrorMessage string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

func (s *OAuthSession) Clone() *OAuthSession {
	if s == nil {
		return nil
	}
	clone := *s
	if s.Token != nil {
		token := *s.Token
		if s.Token.Extra != nil {
			token.Extra = make(map[string]any, len(s.Token.Extra))
			for key, value := range s.Token.Extra {
				token.Extra[key] = value
			}
		}
		clone.Token = &token
	}
	return &clone
}

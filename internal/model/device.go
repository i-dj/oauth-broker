package model

import "time"

type Device struct {
	ID           string     `json:"device_id"`
	Name         string     `json:"name,omitempty"`
	PublicKeyPEM string     `json:"public_key_pem,omitempty"`
	Disabled     bool       `json:"disabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
}

type CloudToken struct {
	DeviceID  string
	Provider  string
	Token     *TokenSet
	CreatedAt time.Time
	UpdatedAt time.Time
}

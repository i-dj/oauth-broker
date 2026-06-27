package store

import (
	"context"
	"errors"

	"github.com/i-dj/oauth-broker/internal/model"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrExpired        = errors.New("oauth session expired")
	ErrInvalidState   = errors.New("invalid state")
	ErrStateExists    = errors.New("oauth state already exists")
	ErrDeviceExists   = errors.New("device already exists")
	ErrDeviceDisabled = errors.New("device is disabled")
	ErrReplay         = errors.New("request replay detected")
)

type SessionStore interface {
	Create(context.Context, *model.OAuthSession) error
	Get(context.Context, string) (*model.OAuthSession, error)
	GetByState(context.Context, string) (*model.OAuthSession, error)
	MarkAuthorizing(context.Context, string) error
	MarkSuccess(context.Context, string, *model.TokenSet) error
	MarkFailed(context.Context, string, string, string) error
	Redeem(context.Context, string, string) (*model.TokenSet, string, error)
	Cancel(context.Context, string, string) error
}

type DeviceStore interface {
	RegisterDevice(context.Context, *model.Device) error
	GetDevice(context.Context, string) (*model.Device, error)
	UseAuthNonce(context.Context, string, string) error
	TouchDevice(context.Context, string) error
}

type CloudTokenStore interface {
	SaveCloudToken(context.Context, string, string, *model.TokenSet) error
	SaveBrokerRefreshToken(context.Context, string, string, string) error
	GetCloudTokenByBrokerRefreshToken(context.Context, string) (*model.CloudToken, error)
}

type Store interface {
	SessionStore
	DeviceStore
	CloudTokenStore
	Close() error
}

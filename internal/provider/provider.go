package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/i-dj/oauth-broker/internal/model"
)

var ErrNotFound = errors.New("oauth provider not found")

type AuthRequest struct {
	State        string
	PKCEVerifier string
}

type ExchangeRequest struct {
	Code         string
	PKCEVerifier string
}

type Provider interface {
	Name() string
	AuthURL(AuthRequest) (string, error)
	Exchange(context.Context, ExchangeRequest) (*model.TokenSet, error)
	Refresh(context.Context, *model.TokenSet) (*model.TokenSet, error)
}

type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]Provider)}
}

func (r *Registry) Register(p Provider) error {
	name := normalize(p.Name())
	if name == "" {
		return errors.New("provider name is empty")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %q is already registered", name)
	}
	r.providers[name] = p
	return nil
}

func (r *Registry) Get(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[normalize(name)]
	return p, ok
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

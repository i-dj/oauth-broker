package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/i-dj/oauth-broker/internal/model"
	"github.com/i-dj/oauth-broker/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	s := &PostgresStore{pool: pool, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  public_key_pem TEXT NOT NULL,
  disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS device_auth_nonces (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  nonce TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, nonce)
);

CREATE TABLE IF NOT EXISTS oauth_sessions (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  state TEXT NOT NULL UNIQUE,
  exchange_secret_hash TEXT NOT NULL DEFAULT '',
  pkce_verifier TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  token_json JSONB,
  error_code TEXT NOT NULL DEFAULT '',
  error_message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE oauth_sessions ALTER COLUMN exchange_secret_hash SET DEFAULT '';
CREATE INDEX IF NOT EXISTS oauth_sessions_device_idx ON oauth_sessions(device_id);
CREATE INDEX IF NOT EXISTS oauth_sessions_expires_idx ON oauth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS cloud_tokens (
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  token_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, provider)
);

CREATE TABLE IF NOT EXISTS broker_refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, provider)
);
`)
	return err
}

func (s *PostgresStore) RegisterDevice(ctx context.Context, device *model.Device) error {
	now := s.now().UTC()
	_, err := s.pool.Exec(ctx, `
INSERT INTO devices (id, name, public_key_pem, disabled, created_at, updated_at)
VALUES ($1, $2, $3, false, $4, $4)
ON CONFLICT (id) DO UPDATE SET
  name = EXCLUDED.name,
  public_key_pem = EXCLUDED.public_key_pem,
  disabled = false,
  updated_at = EXCLUDED.updated_at
`, device.ID, device.Name, device.PublicKeyPEM, now)
	return err
}

func (s *PostgresStore) GetDevice(ctx context.Context, id string) (*model.Device, error) {
	var d model.Device
	var lastSeen *time.Time
	err := s.pool.QueryRow(ctx, `
SELECT id, name, public_key_pem, disabled, created_at, updated_at, last_seen_at
FROM devices
WHERE id = $1
`, id).Scan(&d.ID, &d.Name, &d.PublicKeyPEM, &d.Disabled, &d.CreatedAt, &d.UpdatedAt, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.LastSeenAt = lastSeen
	if d.Disabled {
		return &d, store.ErrDeviceDisabled
	}
	return &d, nil
}

func (s *PostgresStore) UseAuthNonce(ctx context.Context, deviceID, nonce string) error {
	_, _ = s.pool.Exec(ctx, `DELETE FROM device_auth_nonces WHERE created_at < now() - interval '15 minutes'`)
	_, err := s.pool.Exec(ctx, `INSERT INTO device_auth_nonces (device_id, nonce) VALUES ($1, $2)`, deviceID, nonce)
	if isUniqueViolation(err) {
		return store.ErrReplay
	}
	return err
}

func (s *PostgresStore) TouchDevice(ctx context.Context, deviceID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE devices SET last_seen_at = now(), updated_at = now() WHERE id = $1`, deviceID)
	return err
}

func (s *PostgresStore) Create(ctx context.Context, session *model.OAuthSession) error {
	tokenJSON, err := marshalToken(session.Token)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO oauth_sessions
(id, device_id, provider, state, exchange_secret_hash, pkce_verifier, status, token_json, error_code, error_message, created_at, expires_at)
VALUES ($1,$2,$3,$4,'',$5,$6,$7,$8,$9,$10,$11)
`, session.ID, session.DeviceID, session.Provider, session.State, session.PKCEVerifier, string(session.Status), tokenJSON, session.ErrorCode, session.ErrorMessage, session.CreatedAt, session.ExpiresAt)
	if isUniqueViolation(err) {
		return store.ErrStateExists
	}
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*model.OAuthSession, error) {
	session, err := s.get(ctx, `WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	return s.expireIfNeeded(ctx, session)
}

func (s *PostgresStore) GetByState(ctx context.Context, state string) (*model.OAuthSession, error) {
	session, err := s.get(ctx, `WHERE state = $1`, state)
	if err != nil {
		return nil, err
	}
	return s.expireIfNeeded(ctx, session)
}

func (s *PostgresStore) get(ctx context.Context, where string, arg string) (*model.OAuthSession, error) {
	query := fmt.Sprintf(`
SELECT id, device_id, provider, state, pkce_verifier, status, token_json, error_code, error_message, created_at, expires_at
FROM oauth_sessions %s
`, where)
	var session model.OAuthSession
	var status string
	var tokenBytes []byte
	err := s.pool.QueryRow(ctx, query, arg).Scan(
		&session.ID,
		&session.DeviceID,
		&session.Provider,
		&session.State,
		&session.PKCEVerifier,
		&status,
		&tokenBytes,
		&session.ErrorCode,
		&session.ErrorMessage,
		&session.CreatedAt,
		&session.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	session.Status = model.SessionStatus(status)
	if len(tokenBytes) > 0 {
		token, err := unmarshalToken(tokenBytes)
		if err != nil {
			return nil, err
		}
		session.Token = token
	}
	return &session, nil
}

func (s *PostgresStore) MarkAuthorizing(ctx context.Context, id string) error {
	return s.updateStatus(ctx, id, []model.SessionStatus{model.SessionPending, model.SessionAuthorizing}, model.SessionAuthorizing, false, nil, "", "")
}

func (s *PostgresStore) MarkSuccess(ctx context.Context, id string, token *model.TokenSet) error {
	return s.updateStatus(ctx, id, []model.SessionStatus{model.SessionPending, model.SessionAuthorizing}, model.SessionSuccess, true, token, "", "")
}

func (s *PostgresStore) MarkFailed(ctx context.Context, id, code, message string) error {
	return s.updateStatus(ctx, id, []model.SessionStatus{model.SessionPending, model.SessionAuthorizing}, model.SessionFailed, true, nil, code, message)
}

func (s *PostgresStore) updateStatus(ctx context.Context, id string, allowed []model.SessionStatus, status model.SessionStatus, clearPKCE bool, token *model.TokenSet, code, message string) error {
	session, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !statusAllowed(session.Status, allowed) {
		return store.ErrInvalidState
	}
	tokenJSON, err := marshalToken(token)
	if err != nil {
		return err
	}
	pkceExpr := "pkce_verifier"
	if clearPKCE {
		pkceExpr = "''"
	}
	query := fmt.Sprintf(`
UPDATE oauth_sessions
SET status = $2, pkce_verifier = %s, token_json = $3, error_code = $4, error_message = $5
WHERE id = $1
`, pkceExpr)
	ct, err := s.pool.Exec(ctx, query, id, string(status), tokenJSON, code, message)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Redeem(ctx context.Context, id, deviceID string) (*model.TokenSet, string, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)

	var session model.OAuthSession
	var status string
	var tokenBytes []byte
	err = tx.QueryRow(ctx, `
SELECT id, device_id, provider, status, token_json, expires_at
FROM oauth_sessions
WHERE id = $1
FOR UPDATE
`, id).Scan(&session.ID, &session.DeviceID, &session.Provider, &status, &tokenBytes, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", store.ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	if session.DeviceID != deviceID {
		return nil, "", store.ErrNotFound
	}
	if !s.now().UTC().Before(session.ExpiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE oauth_sessions SET status = $2, token_json = NULL, pkce_verifier = '' WHERE id = $1`, id, string(model.SessionExpired))
		return nil, "", store.ErrExpired
	}
	if model.SessionStatus(status) != model.SessionSuccess || len(tokenBytes) == 0 {
		return nil, "", store.ErrInvalidState
	}
	token, err := unmarshalToken(tokenBytes)
	if err != nil {
		return nil, "", err
	}
	savedToken := token
	if current, err := s.getCloudTokenTx(ctx, tx, deviceID, session.Provider); err == nil && savedToken.RefreshToken == "" {
		copyToken := *savedToken
		copyToken.RefreshToken = current.RefreshToken
		savedToken = &copyToken
	}
	cloudTokenJSON, err := marshalToken(savedToken)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO cloud_tokens (device_id, provider, token_json, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())
ON CONFLICT (device_id, provider) DO UPDATE SET
  token_json = EXCLUDED.token_json,
  updated_at = EXCLUDED.updated_at
`, deviceID, session.Provider, cloudTokenJSON)
	if err != nil {
		return nil, "", err
	}
	_, err = tx.Exec(ctx, `UPDATE oauth_sessions SET status = $2, token_json = NULL, pkce_verifier = '' WHERE id = $1`, id, string(model.SessionUsed))
	if err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return token, session.Provider, nil
}

func (s *PostgresStore) Cancel(ctx context.Context, id, deviceID string) error {
	session, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if session.DeviceID != deviceID {
		return store.ErrNotFound
	}
	if session.Status == model.SessionUsed {
		return store.ErrInvalidState
	}
	_, err = s.pool.Exec(ctx, `UPDATE oauth_sessions SET status = $2, token_json = NULL, pkce_verifier = '' WHERE id = $1`, id, string(model.SessionCancelled))
	return err
}

func (s *PostgresStore) SaveCloudToken(ctx context.Context, deviceID, provider string, token *model.TokenSet) error {
	if token == nil {
		return errors.New("token is nil")
	}
	current, err := s.GetCloudToken(ctx, deviceID, provider)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if token.RefreshToken == "" && current != nil {
		tokenCopy := *token
		tokenCopy.RefreshToken = current.RefreshToken
		token = &tokenCopy
	}
	tokenJSON, err := marshalToken(token)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO cloud_tokens (device_id, provider, token_json, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())
ON CONFLICT (device_id, provider) DO UPDATE SET
  token_json = EXCLUDED.token_json,
  updated_at = EXCLUDED.updated_at
`, deviceID, provider, tokenJSON)
	return err
}

func (s *PostgresStore) SaveBrokerRefreshToken(ctx context.Context, deviceID, provider, brokerRefreshToken string) error {
	if brokerRefreshToken == "" {
		return errors.New("broker refresh token is empty")
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO broker_refresh_tokens (token_hash, device_id, provider, created_at, updated_at)
VALUES ($1, $2, $3, now(), now())
ON CONFLICT (device_id, provider) DO UPDATE SET
  token_hash = EXCLUDED.token_hash,
  updated_at = EXCLUDED.updated_at
`, tokenHash(brokerRefreshToken), deviceID, provider)
	return err
}

func (s *PostgresStore) GetCloudTokenByBrokerRefreshToken(ctx context.Context, brokerRefreshToken string) (*model.CloudToken, error) {
	if brokerRefreshToken == "" {
		return nil, store.ErrNotFound
	}
	var result model.CloudToken
	var tokenBytes []byte
	err := s.pool.QueryRow(ctx, `
SELECT ct.device_id, ct.provider, ct.token_json, ct.created_at, ct.updated_at
FROM broker_refresh_tokens brt
JOIN cloud_tokens ct ON ct.device_id = brt.device_id AND ct.provider = brt.provider
JOIN devices d ON d.id = brt.device_id
WHERE brt.token_hash = $1 AND d.disabled = false
`, tokenHash(brokerRefreshToken)).Scan(&result.DeviceID, &result.Provider, &tokenBytes, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	token, err := unmarshalToken(tokenBytes)
	if err != nil {
		return nil, err
	}
	result.Token = token
	return &result, nil
}
func (s *PostgresStore) getCloudTokenTx(ctx context.Context, tx pgx.Tx, deviceID, provider string) (*model.TokenSet, error) {
	var tokenBytes []byte
	err := tx.QueryRow(ctx, `SELECT token_json FROM cloud_tokens WHERE device_id = $1 AND provider = $2`, deviceID, provider).Scan(&tokenBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return unmarshalToken(tokenBytes)
}
func (s *PostgresStore) GetCloudToken(ctx context.Context, deviceID, provider string) (*model.TokenSet, error) {
	var tokenBytes []byte
	err := s.pool.QueryRow(ctx, `SELECT token_json FROM cloud_tokens WHERE device_id = $1 AND provider = $2`, deviceID, provider).Scan(&tokenBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return unmarshalToken(tokenBytes)
}

func (s *PostgresStore) expireIfNeeded(ctx context.Context, session *model.OAuthSession) (*model.OAuthSession, error) {
	if s.now().UTC().Before(session.ExpiresAt) {
		return session, nil
	}
	if session.Status != model.SessionUsed && session.Status != model.SessionCancelled && session.Status != model.SessionExpired {
		_, _ = s.pool.Exec(ctx, `UPDATE oauth_sessions SET status = $2, token_json = NULL, pkce_verifier = '' WHERE id = $1`, session.ID, string(model.SessionExpired))
		session.Status = model.SessionExpired
		session.Token = nil
		session.PKCEVerifier = ""
	}
	return session, store.ErrExpired
}

func marshalToken(token *model.TokenSet) ([]byte, error) {
	if token == nil {
		return nil, nil
	}
	return json.Marshal(token)
}

func unmarshalToken(data []byte) (*model.TokenSet, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var token model.TokenSet
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func statusAllowed(status model.SessionStatus, allowed []model.SessionStatus) bool {
	for _, item := range allowed {
		if status == item {
			return true
		}
	}
	return false
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

# OAuth Broker

OAuth Broker is a lightweight OAuth gateway for NAS clients. It centralizes OAuth authorization for cloud storage providers such as Google Drive, OneDrive, and Dropbox, stores provider tokens in PostgreSQL, and returns rclone-compatible configuration to the NAS.

The broker owns the provider OAuth credentials. NAS clients do not need to store Google, Microsoft, or Dropbox client secrets.

## Features

- Dynamic provider routes: `/api/oauth/:provider/start` and `/api/oauth/:provider/callback`
- Google Drive, OneDrive, and Dropbox provider implementations
- Device registration with NAS public keys
- Signed device authentication before issuing broker JWTs
- PostgreSQL-backed sessions, device records, provider tokens, and broker refresh tokens
- rclone-compatible refresh endpoint
- `/healthz` endpoint with deployed version, build metadata, hostname, and server IPs
- GitHub Actions release deployment with tag-based version injection

## Configuration

Copy the example environment file and edit it for your deployment:

```bash
cp .env.example .env
```

See `.env.example` for all supported settings and comments. Keep the real `.env` file out of Git.

Important production settings:

| Setting | Purpose |
| --- | --- |
| `PUBLIC_BASE_URL` | Public HTTPS origin of the broker. |
| `DATABASE_URL` | PostgreSQL connection string. |
| `JWT_SECRET` | Strong random secret used to sign broker JWTs. |
| `DEVICE_REGISTRATION_SECRET` | Optional registration guard. Set this in production. |
| `GOOGLE_*` | Google Drive OAuth app credentials and redirect URL. |
| `ONEDRIVE_*` | OneDrive OAuth app credentials and redirect URL. |
| `DROPBOX_*` | Dropbox OAuth app credentials and redirect URL. |

## Provider redirect URLs

Configure these redirect URLs in the provider developer consoles. Replace `https://oauth.example.com` with your own public broker domain.

| Provider | Redirect URL |
| --- | --- |
| Google Drive | `https://oauth.example.com/api/oauth/google/callback` |
| OneDrive | `https://oauth.example.com/api/oauth/onedrive/callback` |
| Dropbox | `https://oauth.example.com/api/oauth/dropbox/callback` |

The path must match exactly.

## API reference

Protected endpoints require:

```http
Authorization: Bearer <broker_jwt>
```

| Method | Path | Auth | Purpose | Example request | Example response |
| --- | --- | --- | --- | --- | --- |
| `GET` | `/healthz` | No | Health check and deployment metadata. | `GET /healthz` | `{"status":"ok","version":"v1.2.3","commit":"abc123","build_date":"2026-06-28T12:00:00Z","hostname":"srv-1","server_ips":["10.0.0.5"]}` |
| `POST` | `/api/devices/register` | Optional registration secret | Register or update a NAS device public key. | `{"device_id":"nas-001","name":"Office NAS","public_key_pem":"-----BEGIN PUBLIC KEY-----\n..."}` | `{"device_id":"nas-001","status":"registered"}` |
| `POST` | `/api/auth/token` | No | Verify a signed NAS request and issue a broker JWT. | `{"device_id":"nas-001","timestamp":1780000000,"nonce":"random","signature":"base64-signature"}` | `{"access_token":"jwt","token_type":"Bearer","expires_in":900,"expires_at":"2026-06-28T12:15:00Z"}` |
| `POST` | `/api/auth/refresh` | Broker JWT | Refresh the broker JWT for the authenticated device. | `{}` | `{"access_token":"jwt","token_type":"Bearer","expires_in":900,"expires_at":"2026-06-28T12:15:00Z"}` |
| `POST` | `/api/oauth/session` | Broker JWT | Create an OAuth authorization session. | `{"provider":"google"}` | `{"session_id":"sess_xxx","provider":"google","status":"pending","authorize_url":"https://oauth.example.com/api/oauth/google/start?session_id=sess_xxx","expires_at":"2026-06-28T12:10:00Z"}` |
| `GET` | `/api/oauth/:provider/start` | No | Redirect the browser to the provider authorization page. | `GET /api/oauth/google/start?session_id=sess_xxx` | `302 Location: https://accounts.google.com/...` |
| `GET` | `/api/oauth/:provider/callback` | Provider callback | Receive provider OAuth callback and store provider tokens. | `GET /api/oauth/google/callback?code=...&state=...` | HTML success or failure page. |
| `GET` | `/api/oauth/status/:session_id` | Broker JWT | Poll authorization status. | `GET /api/oauth/status/sess_xxx` | `{"session_id":"sess_xxx","provider":"google","status":"success","expires_at":"2026-06-28T12:10:00Z"}` |
| `POST` | `/api/oauth/exchange` | Broker JWT | Redeem a successful session for rclone config. | `{"session_id":"sess_xxx"}` | `{"provider":"google","rclone":{"type":"drive","token_url":"https://oauth.example.com/api/rclone/google/token","token":{"access_token":"...","refresh_token":"yesnas_rt_xxx","expires_in":3600}}}` |
| `DELETE` | `/api/oauth/session/:session_id` | Broker JWT | Cancel an OAuth session owned by the device. | `DELETE /api/oauth/session/sess_xxx` | `204 No Content` |
| `POST` | `/api/rclone/:provider/token` | Broker refresh token | rclone-compatible token refresh endpoint. | Form: `grant_type=refresh_token&refresh_token=yesnas_rt_xxx` | `{"access_token":"...","refresh_token":"yesnas_rt_xxx","token_type":"Bearer","expires_in":3600}` |

### Device registration secret

If `DEVICE_REGISTRATION_SECRET` is set, include it when registering devices:

```http
X-Registration-Secret: <secret>
```

### Provider names

Supported provider path names:

| Provider | Path name | rclone type |
| --- | --- | --- |
| Google Drive | `google` | `drive` |
| OneDrive | `onedrive` | `onedrive` |
| Dropbox | `dropbox` | `dropbox` |

## Standard authorization flow

```text
NAS -> POST /api/devices/register
NAS -> POST /api/auth/token
NAS -> POST /api/oauth/session
Browser -> GET /api/oauth/:provider/start?session_id=...
Provider -> GET /api/oauth/:provider/callback
NAS -> GET /api/oauth/status/:session_id
NAS -> POST /api/oauth/exchange
rclone -> POST /api/rclone/:provider/token
```

## Build

```bash
go mod tidy
go test ./...
go vet ./...
go build -o oauth-broker ./cmd/server
```

To embed a version manually:

```bash
go build \
  -buildvcs=false \
  -ldflags "-X github.com/i-dj/oauth-broker/internal/buildinfo.Version=v1.2.3 -X github.com/i-dj/oauth-broker/internal/buildinfo.Commit=$(git rev-parse HEAD) -X github.com/i-dj/oauth-broker/internal/buildinfo.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o oauth-broker ./cmd/server
```

## Run

```bash
./oauth-broker
```

Example systemd unit:

```ini
[Unit]
Description=OAuth Broker
After=network.target

[Service]
WorkingDirectory=/opt/oauth-broker
EnvironmentFile=/opt/oauth-broker/.env
ExecStart=/opt/oauth-broker/oauth-broker
Restart=always
RestartSec=3
User=oauth-broker
Group=oauth-broker

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now oauth-broker
sudo systemctl status oauth-broker
```

## Reverse proxy

Example Caddy configuration:

```caddyfile
oauth.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Use HTTPS in production.

## GitHub tag-based deployment

This repository includes `.github/workflows/release-deploy.yml`.

Deployment is triggered when a version tag is pushed:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The workflow builds a Linux binary and injects the tag into `/healthz` as the deployed version.

Required GitHub Actions secrets:

| Secret | Purpose |
| --- | --- |
| `DEPLOY_HOST` | Server IP or hostname. |
| `DEPLOY_USER` | SSH user used for deployment. |
| `DEPLOY_SSH_KEY` | Private SSH key for the deploy user. |
| `DEPLOY_PORT` | SSH port. Optional; defaults to `22`. |

Server assumptions used by the workflow:

| Item | Default |
| --- | --- |
| Deploy path | `/opt/oauth-broker` |
| Binary path | `/opt/oauth-broker/oauth-broker` |
| systemd service | `oauth-broker` |
| Local health check | `http://127.0.0.1:8080/healthz` |

## Device keys

Each NAS should generate and keep its own device key pair.

- The private key stays on the NAS and is never uploaded.
- The public key is uploaded to the broker during device registration.
- Later, the NAS signs auth requests with the private key.
- The broker verifies signatures using the stored public key.

## Storage model

The service creates and uses PostgreSQL tables for:

- registered NAS devices and public keys
- replay-protection nonces
- OAuth sessions
- real cloud provider tokens
- broker refresh token hashes

Timestamps are stored and returned in UTC.

## Logging

Set `LOG_FILE` to control the log destination. Request logs include client IP, device ID, method, path, status, latency, response size, user agent, and request errors.

## Security notes

- Never commit `.env` or real provider secrets.
- Rotate any secret that has appeared in chat logs, screenshots, or terminal output.
- Keep NAS private keys on the NAS only.
- Use HTTPS for all public broker traffic.
- Set `DEVICE_REGISTRATION_SECRET` in production.
- Broker refresh tokens are stored as hashes, not plaintext.
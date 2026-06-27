package handler

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/i-dj/oauth-broker/internal/auth"
	"github.com/i-dj/oauth-broker/internal/config"
	"github.com/i-dj/oauth-broker/internal/model"
	"github.com/i-dj/oauth-broker/internal/provider"
	"github.com/i-dj/oauth-broker/internal/store"
)

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$`)

type AuthHandler struct {
	store     store.Store
	jwt       *auth.JWTService
	providers *provider.Registry
	cfg       config.AuthConfig
}

func NewAuthHandler(appStore store.Store, jwt *auth.JWTService, providers *provider.Registry, cfg config.AuthConfig) *AuthHandler {
	return &AuthHandler{store: appStore, jwt: jwt, providers: providers, cfg: cfg}
}

type registerDeviceRequest struct {
	DeviceID     string `json:"device_id" binding:"required"`
	Name         string `json:"name"`
	PublicKeyPEM string `json:"public_key_pem" binding:"required"`
}

func (h *AuthHandler) RegisterDevice(c *gin.Context) {
	if h.cfg.RegistrationSecretUsed && c.GetHeader("X-Registration-Secret") != h.cfg.RegistrationSecret {
		writeError(c, http.StatusUnauthorized, "invalid_registration_secret", "invalid registration secret")
		return
	}
	var req registerDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "device_id and public_key_pem are required")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Name = strings.TrimSpace(req.Name)
	req.PublicKeyPEM = strings.TrimSpace(req.PublicKeyPEM)
	if !deviceIDPattern.MatchString(req.DeviceID) {
		writeError(c, http.StatusBadRequest, "invalid_device_id", "device_id format is invalid")
		return
	}
	if err := auth.ValidatePublicKey(req.PublicKeyPEM); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_public_key", "public_key_pem is invalid or unsupported")
		return
	}
	device := &model.Device{ID: req.DeviceID, Name: req.Name, PublicKeyPEM: req.PublicKeyPEM}
	if err := h.store.RegisterDevice(c.Request.Context(), device); err != nil {
		writeError(c, http.StatusInternalServerError, "device_register_failed", "could not register device")
		return
	}
	c.JSON(http.StatusCreated, gin.H{"device_id": req.DeviceID, "status": "registered"})
}

func (h *AuthHandler) IssueToken(c *gin.Context) {
	var req auth.DeviceAuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "device_id, nonce, timestamp and signature are required")
		return
	}
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Nonce = strings.TrimSpace(req.Nonce)
	device, err := h.store.GetDevice(c.Request.Context(), req.DeviceID)
	if err != nil {
		handleAuthStoreError(c, err)
		return
	}
	if err := auth.VerifyDeviceSignature(device.PublicKeyPEM, req, h.cfg.SignatureClockSkew); err != nil {
		writeError(c, http.StatusUnauthorized, "invalid_device_signature", "invalid device signature")
		return
	}
	if err := h.store.UseAuthNonce(c.Request.Context(), req.DeviceID, req.Nonce); err != nil {
		handleAuthStoreError(c, err)
		return
	}
	_ = h.store.TouchDevice(c.Request.Context(), req.DeviceID)
	h.issueJWT(c, req.DeviceID)
}

func (h *AuthHandler) RefreshJWT(c *gin.Context) {
	deviceID := MustDeviceID(c)
	if _, err := h.store.GetDevice(c.Request.Context(), deviceID); err != nil {
		handleAuthStoreError(c, err)
		return
	}
	_ = h.store.TouchDevice(c.Request.Context(), deviceID)
	h.issueJWT(c, deviceID)
}

func (h *AuthHandler) RcloneToken(c *gin.Context) {
	providerName := c.Param("provider")
	p, ok := h.providers.Get(providerName)
	if !ok {
		writeError(c, http.StatusNotFound, "provider_not_found", "provider not found")
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	grantType := strings.TrimSpace(c.PostForm("grant_type"))
	if grantType != "refresh_token" {
		writeError(c, http.StatusBadRequest, "unsupported_grant_type", "only refresh_token grant is supported")
		return
	}
	brokerRefreshToken := strings.TrimSpace(c.PostForm("refresh_token"))
	cloudToken, err := h.store.GetCloudTokenByBrokerRefreshToken(c.Request.Context(), brokerRefreshToken)
	if err != nil {
		handleAuthStoreError(c, err)
		return
	}
	if cloudToken.Provider != p.Name() {
		writeError(c, http.StatusNotFound, "refresh_token_not_found", "refresh token not found")
		return
	}
	newToken, err := p.Refresh(c.Request.Context(), cloudToken.Token)
	if err != nil {
		writeError(c, http.StatusBadGateway, "cloud_token_refresh_failed", "could not refresh cloud token")
		return
	}
	if err := h.store.SaveCloudToken(c.Request.Context(), cloudToken.DeviceID, p.Name(), newToken); err != nil {
		writeError(c, http.StatusInternalServerError, "cloud_token_save_failed", "could not save refreshed cloud token")
		return
	}
	_ = h.store.TouchDevice(c.Request.Context(), cloudToken.DeviceID)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, publicRcloneToken(newToken, brokerRefreshToken))
}
func (h *AuthHandler) issueJWT(c *gin.Context, deviceID string) {
	token, expiresAt, err := h.jwt.Issue(deviceID)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "jwt_issue_failed", "could not issue jwt")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"access_token": token, "token_type": "Bearer", "expires_in": int64(time.Until(expiresAt.UTC()).Seconds()), "expires_at": expiresAt.UTC()})
}

func handleAuthStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(c, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrDeviceDisabled):
		writeError(c, http.StatusForbidden, "device_disabled", "device is disabled")
	case errors.Is(err, store.ErrReplay):
		writeError(c, http.StatusUnauthorized, "replay_detected", "authentication request was already used")
	default:
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func DeviceID(c *gin.Context) (string, bool) {
	value, ok := c.Get("device_id")
	if !ok {
		return "", false
	}
	deviceID, ok := value.(string)
	return deviceID, ok && deviceID != ""
}

func MustDeviceID(c *gin.Context) string {
	deviceID, _ := DeviceID(c)
	return deviceID
}

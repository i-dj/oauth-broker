package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/i-dj/oauth-broker/internal/model"
	"github.com/i-dj/oauth-broker/internal/provider"
	"github.com/i-dj/oauth-broker/internal/store"
)

type OAuthHandler struct {
	store         store.Store
	providers     *provider.Registry
	publicBaseURL string
	sessionTTL    time.Duration
}

func NewOAuthHandler(sessionStore store.Store, providers *provider.Registry, publicBaseURL string, sessionTTL time.Duration) *OAuthHandler {
	return &OAuthHandler{
		store:         sessionStore,
		providers:     providers,
		publicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		sessionTTL:    sessionTTL,
	}
}

type exchangeRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

func (h *OAuthHandler) CreateSession(c *gin.Context) {
	deviceID := MustDeviceID(c)
	providerName := strings.TrimSpace(c.Param("provider"))
	p, ok := h.providers.Get(providerName)
	if !ok {
		writeError(c, http.StatusNotFound, "provider_not_found", "provider not found")
		return
	}

	sessionID, err := randomToken(24)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "random_generation_failed", "could not create oauth session")
		return
	}
	state, err := randomToken(32)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "random_generation_failed", "could not create oauth session")
		return
	}
	pkceVerifier, err := randomToken(32)
	if err != nil {
		writeError(c, http.StatusInternalServerError, "random_generation_failed", "could not create oauth session")
		return
	}

	now := time.Now().UTC()
	session := &model.OAuthSession{
		ID:           sessionID,
		DeviceID:     deviceID,
		Provider:     p.Name(),
		State:        state,
		PKCEVerifier: pkceVerifier,
		Status:       model.SessionPending,
		CreatedAt:    now,
		ExpiresAt:    now.Add(h.sessionTTL),
	}
	if err := h.store.Create(c.Request.Context(), session); err != nil {
		writeError(c, http.StatusInternalServerError, "session_create_failed", "could not create oauth session")
		return
	}

	authorizeURL := h.publicBaseURL + "/api/oauth/" + url.PathEscape(p.Name()) + "/start?session_id=" + url.QueryEscape(sessionID)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, gin.H{
		"session_id":    sessionID,
		"provider":      p.Name(),
		"status":        session.Status,
		"authorize_url": authorizeURL,
		"expires_at":    session.ExpiresAt,
	})
}

func (h *OAuthHandler) StartOAuth(c *gin.Context) {
	providerName := c.Param("provider")
	p, ok := h.providers.Get(providerName)
	if !ok {
		writeError(c, http.StatusNotFound, "provider_not_found", "provider not found")
		return
	}
	sessionID := strings.TrimSpace(c.Query("session_id"))
	if sessionID == "" {
		writeError(c, http.StatusBadRequest, "invalid_request", "session_id is required")
		return
	}
	session, err := h.store.Get(c.Request.Context(), sessionID)
	if err != nil {
		handleStoreError(c, err)
		return
	}
	if session.Provider != p.Name() {
		writeError(c, http.StatusBadRequest, "provider_mismatch", "session belongs to another provider")
		return
	}
	if session.Status != model.SessionPending && session.Status != model.SessionAuthorizing {
		writeError(c, http.StatusConflict, "invalid_session_state", "oauth session cannot be started")
		return
	}
	authURL, err := p.AuthURL(provider.AuthRequest{State: session.State, PKCEVerifier: session.PKCEVerifier})
	if err != nil {
		writeError(c, http.StatusInternalServerError, "authorization_url_failed", "could not build provider authorization URL")
		return
	}
	if err := h.store.MarkAuthorizing(c.Request.Context(), session.ID); err != nil {
		handleStoreError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Redirect(http.StatusFound, authURL)
}

func (h *OAuthHandler) CallbackOAuth(c *gin.Context) {
	providerName := c.Param("provider")
	p, ok := h.providers.Get(providerName)
	if !ok {
		writeCallbackPage(c, false, "Unsupported OAuth provider.")
		return
	}
	state := strings.TrimSpace(c.Query("state"))
	if state == "" {
		writeCallbackPage(c, false, "Missing OAuth state.")
		return
	}
	session, err := h.store.GetByState(c.Request.Context(), state)
	if err != nil {
		writeCallbackPage(c, false, "OAuth session not found or expired.")
		return
	}
	if session.Provider != p.Name() {
		_ = h.store.MarkFailed(c.Request.Context(), session.ID, "provider_mismatch", "callback provider does not match session")
		writeCallbackPage(c, false, "OAuth provider does not match this session.")
		return
	}
	if session.Status != model.SessionPending && session.Status != model.SessionAuthorizing {
		if session.Status == model.SessionSuccess || session.Status == model.SessionUsed {
			writeCallbackPage(c, true, "Authorization already completed. You may return to the NAS.")
		} else {
			writeCallbackPage(c, false, "This OAuth session has ended. Please start again.")
		}
		return
	}
	if providerError := strings.TrimSpace(c.Query("error")); providerError != "" {
		description := strings.TrimSpace(c.Query("error_description"))
		if description == "" {
			description = "Authorization was cancelled or denied by the provider."
		}
		_ = h.store.MarkFailed(c.Request.Context(), session.ID, providerError, description)
		writeCallbackPage(c, false, description)
		return
	}
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		_ = h.store.MarkFailed(c.Request.Context(), session.ID, "missing_code", "authorization code is missing")
		writeCallbackPage(c, false, "Missing authorization code.")
		return
	}
	token, err := p.Exchange(c.Request.Context(), provider.ExchangeRequest{Code: code, PKCEVerifier: session.PKCEVerifier})
	if err != nil {
		_ = h.store.MarkFailed(c.Request.Context(), session.ID, "token_exchange_failed", "provider token exchange failed")
		writeCallbackPage(c, false, "Token exchange failed. Please start the authorization again.")
		return
	}
	if err := h.store.MarkSuccess(c.Request.Context(), session.ID, token); err != nil {
		writeCallbackPage(c, false, "Could not save the authorization result. Please try again.")
		return
	}
	writeCallbackPage(c, true, "Authorization succeeded. Return to the NAS; this window may be closed.")
}

func (h *OAuthHandler) GetStatus(c *gin.Context) {
	deviceID := MustDeviceID(c)
	session, err := h.store.Get(c.Request.Context(), c.Param("session_id"))
	if session == nil {
		handleStoreError(c, err)
		return
	}
	if session.DeviceID != deviceID {
		writeError(c, http.StatusNotFound, "session_not_found", "oauth session not found")
		return
	}
	response := gin.H{
		"session_id": session.ID,
		"provider":   session.Provider,
		"status":     session.Status,
		"expires_at": session.ExpiresAt,
	}
	if session.Status == model.SessionFailed {
		response["error"] = gin.H{"code": session.ErrorCode, "message": session.ErrorMessage}
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, response)
}

func (h *OAuthHandler) Exchange(c *gin.Context) {
	deviceID := MustDeviceID(c)
	var req exchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "session_id is required")
		return
	}
	token, providerName, err := h.store.Redeem(c.Request.Context(), req.SessionID, deviceID)
	if err != nil {
		handleStoreError(c, err)
		return
	}
	brokerRefreshToken, err := newBrokerRefreshToken()
	if err != nil {
		writeError(c, http.StatusInternalServerError, "refresh_token_create_failed", "could not create broker refresh token")
		return
	}
	if err := h.store.SaveBrokerRefreshToken(c.Request.Context(), deviceID, providerName, brokerRefreshToken); err != nil {
		writeError(c, http.StatusInternalServerError, "refresh_token_save_failed", "could not save broker refresh token")
		return
	}
	publicToken := publicRcloneToken(token, brokerRefreshToken)
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, gin.H{
		"provider": providerName,
		"rclone": gin.H{
			"type":          providerNameToRcloneType(providerName),
			"client_id":     "",
			"client_secret": "",
			"scope":         providerNameToRcloneScope(providerName),
			"token_url":     h.publicBaseURL + "/api/rclone/" + url.PathEscape(providerName) + "/token",
			"token":         publicToken,
		},
	})
}

func (h *OAuthHandler) CancelSession(c *gin.Context) {
	deviceID := MustDeviceID(c)
	if err := h.store.Cancel(c.Request.Context(), c.Param("session_id"), deviceID); err != nil {
		handleStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func newBrokerRefreshToken() (string, error) {
	value, err := randomToken(32)
	if err != nil {
		return "", err
	}
	return "yesnas_rt_" + value, nil
}

func publicRcloneToken(token *model.TokenSet, brokerRefreshToken string) gin.H {
	expiresIn := int64(0)
	expiry := time.Time{}
	if token != nil && !token.Expiry.IsZero() {
		expiry = token.Expiry.UTC()
		expiresIn = int64(time.Until(expiry).Seconds())
		if expiresIn < 0 {
			expiresIn = 0
		}
	}
	result := gin.H{
		"access_token":  "",
		"refresh_token": brokerRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
	}
	if token != nil {
		result["access_token"] = token.AccessToken
		if token.TokenType != "" {
			result["token_type"] = token.TokenType
		}
	}
	if !expiry.IsZero() {
		result["expiry"] = expiry
		result["expires_at"] = expiry
	}
	return result
}

func providerNameToRcloneType(providerName string) string {
	switch providerName {
	case "google":
		return "drive"
	case "onedrive":
		return "onedrive"
	case "dropbox":
		return "dropbox"
	default:
		return providerName
	}
}

func providerNameToRcloneScope(providerName string) string {
	switch providerName {
	case "google":
		return "drive"
	case "onedrive":
		return "offline_access Files.ReadWrite"
	case "dropbox":
		return "files.metadata.read files.metadata.write files.content.read files.content.write"
	default:
		return ""
	}
}

func randomToken(byteLength int) (string, error) {
	buffer := make([]byte, byteLength)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func handleStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(c, http.StatusNotFound, "session_not_found", "oauth session not found")
	case errors.Is(err, store.ErrExpired):
		writeError(c, http.StatusGone, "session_expired", "oauth session expired")
	case errors.Is(err, store.ErrInvalidState):
		writeError(c, http.StatusConflict, "invalid_session_state", "oauth session is not in the required state")
	default:
		writeError(c, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func writeError(c *gin.Context, status int, code, message string) {
	c.Header("Cache-Control", "no-store")
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

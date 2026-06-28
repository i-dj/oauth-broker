package handler

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	webassets "github.com/i-dj/oauth-broker/web"
)

var oauthResultTemplate = template.Must(template.ParseFS(webassets.Templates, "templates/oauth_result.html"))

type oauthResultView struct {
	Success   bool
	EventType string
	Provider  string
	Title     string
	Message   string
	Icon      string
	Color     string
}

func writeCallbackPage(c *gin.Context, success bool, message string) {
	provider := strings.TrimSpace(c.Param("provider"))
	view := oauthResultView{
		Success:   success,
		EventType: "oauth_error",
		Provider:  provider,
		Title:     "Authorization failed",
		Message:   message,
		Icon:      "!",
		Color:     "#dc2626",
	}
	if success {
		view.EventType = "oauth_success"
		view.Title = "Authorization completed"
		view.Icon = "✓"
		view.Color = "#16a34a"
	}
	var buffer bytes.Buffer
	if err := oauthResultTemplate.Execute(&buffer, view); err != nil {
		c.String(http.StatusInternalServerError, "could not render oauth result page")
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", buffer.Bytes())
}

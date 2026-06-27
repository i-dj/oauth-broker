package handler

import (
	"bytes"
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
	webassets "github.com/i-dj/oauth-broker/web"
)

var oauthResultTemplate = template.Must(template.ParseFS(webassets.Templates, "templates/oauth_result.html"))

type oauthResultView struct {
	Title   string
	Message string
	Icon    string
	Color   string
}

func writeCallbackPage(c *gin.Context, success bool, message string) {
	view := oauthResultView{
		Title:   "授权失败",
		Message: message,
		Icon:    "!",
		Color:   "#dc2626",
	}
	if success {
		view.Title = "授权成功"
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

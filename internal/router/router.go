package router

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/i-dj/oauth-broker/internal/auth"
	"github.com/i-dj/oauth-broker/internal/buildinfo"
	"github.com/i-dj/oauth-broker/internal/handler"
)

func New(oauthHandler *handler.OAuthHandler, authHandler *handler.AuthHandler, jwt *auth.JWTService) *gin.Engine {
	r := gin.New()
	r.Use(requestLogger(), gin.Recovery(), securityHeaders())

	r.GET("/healthz", healthz)
	r.GET("/version", version)

	api := r.Group("/api")
	{
		api.PUT("/devices/:device_id", authHandler.RegisterDevice)
		api.POST("/auth/token", authHandler.IssueToken)
		api.POST("/auth/refresh", requireJWT(jwt), authHandler.RefreshJWT)
		api.POST("/rclone/:provider/token", authHandler.RcloneToken)
	}

	oauth := r.Group("/api/oauth")
	{
		oauth.GET("/:provider/start", oauthHandler.StartOAuth)
		oauth.GET("/:provider/callback", oauthHandler.CallbackOAuth)

		protected := oauth.Group("")
		protected.Use(requireJWT(jwt))
		protected.POST("/:provider/session", oauthHandler.CreateSession)
		protected.GET("/status/:session_id", oauthHandler.GetStatus)
		protected.POST("/exchange", oauthHandler.Exchange)
		protected.DELETE("/session/:session_id", oauthHandler.CancelSession)
	}
	return r
}

func healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func version(c *gin.Context) {
	info := buildinfo.Current()
	c.JSON(http.StatusOK, gin.H{
		"version":    info.Version,
		"commit":     info.Commit,
		"build_date": info.Date,
		"hostname":   info.Hostname,
		"server_ips": serverIPs(),
		"go_os":      info.GoOS,
		"go_arch":    info.GoArch,
	})
}

func serverIPs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	ips := make([]string, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		c.Next()

		deviceID := "-"
		if value, ok := c.Get("device_id"); ok {
			if text, ok := value.(string); ok && text != "" {
				deviceID = text
			}
		}
		if query != "" {
			path += "?" + query
		}
		log.Printf(
			"request client_ip=%s device_id=%s method=%s path=%q status=%d latency=%s bytes=%d user_agent=%q errors=%q",
			c.ClientIP(),
			deviceID,
			c.Request.Method,
			path,
			c.Writer.Status(),
			time.Since(startedAt).Round(time.Microsecond),
			c.Writer.Size(),
			c.Request.UserAgent(),
			c.Errors.String(),
		)
	}
}

func requireJWT(jwt *auth.JWTService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := strings.TrimSpace(c.GetHeader("Authorization"))
		if len(authorization) <= 7 || !strings.EqualFold(authorization[:7], "Bearer ") {
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "missing_jwt", "message": "Authorization Bearer token is required"}})
			return
		}
		claims, err := jwt.Validate(strings.TrimSpace(authorization[7:]))
		if err != nil {
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "invalid_jwt", "message": "invalid or expired jwt"}})
			return
		}
		c.Set("device_id", claims.Subject)
		c.Next()
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		c.Next()
	}
}

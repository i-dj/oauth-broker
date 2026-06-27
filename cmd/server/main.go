package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/i-dj/oauth-broker/internal/auth"
	"github.com/i-dj/oauth-broker/internal/config"
	"github.com/i-dj/oauth-broker/internal/database"
	"github.com/i-dj/oauth-broker/internal/handler"
	"github.com/i-dj/oauth-broker/internal/provider"
	"github.com/i-dj/oauth-broker/internal/router"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	logFile, err := setupLogging(cfg.Server.LogFile)
	if err != nil {
		log.Fatal(err)
	}
	if logFile != nil {
		defer logFile.Close()
	}
	if cfg.Auth.JWTSecret == "dev-only-change-me" {
		log.Print("warning: JWT_SECRET is not set; using development fallback secret")
	}
	if !cfg.Auth.RegistrationSecretUsed {
		log.Print("warning: DEVICE_REGISTRATION_SECRET is not set; device registration is open")
	}

	providers := provider.NewRegistry()
	googleProvider, err := provider.NewGoogle(cfg.Google)
	if err != nil {
		log.Fatal(err)
	}
	mustRegister(providers, googleProvider)
	if cfg.OneDrive.Enabled {
		oneDriveProvider, err := provider.NewOneDrive(cfg.OneDrive)
		if err != nil {
			log.Fatal(err)
		}
		mustRegister(providers, oneDriveProvider)
	}
	if cfg.Dropbox.Enabled {
		dropboxProvider, err := provider.NewDropbox(cfg.Dropbox)
		if err != nil {
			log.Fatal(err)
		}
		mustRegister(providers, dropboxProvider)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	appStore, err := database.NewPostgresStore(ctx, cfg.Database.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer appStore.Close()

	jwtService := auth.NewJWTService(cfg.Auth)
	oauthHandler := handler.NewOAuthHandler(appStore, providers, cfg.Server.PublicBaseURL, cfg.Server.SessionTTL)
	authHandler := handler.NewAuthHandler(appStore, jwtService, providers, cfg.Auth)
	server := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           router.New(oauthHandler, authHandler, jwtService),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("oauth broker listening on %s", cfg.Server.ListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func setupLogging(logPath string) (*os.File, error) {
	log.SetFlags(log.LstdFlags | log.LUTC | log.Lmicroseconds)
	if logPath == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	writer := io.MultiWriter(os.Stdout, file)
	log.SetOutput(writer)
	gin.DefaultWriter = writer
	gin.DefaultErrorWriter = writer
	log.Printf("logging to %s", logPath)
	return file, nil
}

func mustRegister(registry *provider.Registry, p provider.Provider) {
	if err := registry.Register(p); err != nil {
		log.Fatal(err)
	}
	log.Printf("provider %s registered", p.Name())
}

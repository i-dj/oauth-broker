package config

import "fmt"

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Google   GoogleConfig
	OneDrive OneDriveConfig
	Dropbox  DropboxConfig
}

func Load() (Config, error) {
	loadDotEnv()

	server, err := LoadServer()
	if err != nil {
		return Config{}, fmt.Errorf("load server config: %w", err)
	}
	database, err := LoadDatabase()
	if err != nil {
		return Config{}, fmt.Errorf("load database config: %w", err)
	}
	auth, err := LoadAuth()
	if err != nil {
		return Config{}, fmt.Errorf("load auth config: %w", err)
	}
	google, err := LoadGoogle(server.PublicBaseURL)
	if err != nil {
		return Config{}, fmt.Errorf("load google config: %w", err)
	}
	oneDrive, err := LoadOneDrive(server.PublicBaseURL)
	if err != nil {
		return Config{}, fmt.Errorf("load onedrive config: %w", err)
	}
	dropbox, err := LoadDropbox(server.PublicBaseURL)
	if err != nil {
		return Config{}, fmt.Errorf("load dropbox config: %w", err)
	}
	return Config{
		Server:   server,
		Database: database,
		Auth:     auth,
		Google:   google,
		OneDrive: oneDrive,
		Dropbox:  dropbox,
	}, nil
}

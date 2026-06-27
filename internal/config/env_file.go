package config

import "github.com/joho/godotenv"

func loadDotEnv() {
	_ = godotenv.Load()
}

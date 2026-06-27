package config

import "testing"

func TestLoadServerRejectsInvalidDuration(t *testing.T) {
	t.Setenv("SESSION_TTL", "not-a-duration")
	if _, err := LoadServer(); err == nil {
		t.Fatal("LoadServer() error = nil, want invalid duration error")
	}
}

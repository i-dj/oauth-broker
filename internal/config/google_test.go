package config

import "testing"

func TestLoadGoogleUsesPublicBaseURLWhenRedirectMissing(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "client-secret")

	cfg, err := LoadGoogle("https://oauth.example.com/")
	if err != nil {
		t.Fatalf("LoadGoogle returned error: %v", err)
	}
	want := "https://oauth.example.com/api/oauth/google/callback"
	if cfg.OAuth.RedirectURL != want {
		t.Fatalf("redirect URL = %q, want %q", cfg.OAuth.RedirectURL, want)
	}
}

func TestLoadGoogleUsesCustomScopes(t *testing.T) {
	t.Setenv("GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "client-secret")
	t.Setenv("GOOGLE_SCOPES", "scope-a, scope-b")

	cfg, err := LoadGoogle("https://oauth.example.com")
	if err != nil {
		t.Fatalf("LoadGoogle returned error: %v", err)
	}
	if len(cfg.OAuth.Scopes) != 2 || cfg.OAuth.Scopes[0] != "scope-a" || cfg.OAuth.Scopes[1] != "scope-b" {
		t.Fatalf("scopes = %#v", cfg.OAuth.Scopes)
	}
}

func TestLoadGoogleRequiresClientCredentials(t *testing.T) {
	_, err := LoadGoogle("https://oauth.example.com")
	if err == nil {
		t.Fatal("expected missing client credentials error")
	}
}

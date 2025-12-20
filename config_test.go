package main

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	const key = "CV_TEST_GETENV"
	t.Setenv(key, "value")
	if got := getEnv(key, "default"); got != "value" {
		t.Fatalf("expected env value, got %q", got)
	}
	if got := getEnv("CV_TEST_GETENV_MISSING", "default"); got != "default" {
		t.Fatalf("expected default value, got %q", got)
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		value  string
		expect bool
	}{
		{"1", true},
		{"true", true},
		{"yes", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Setenv("CV_TEST_BOOL", tt.value)
		if got := getEnvBool("CV_TEST_BOOL", true); got != tt.expect {
			t.Fatalf("value %q expected %t got %t", tt.value, tt.expect, got)
		}
	}
	if got := getEnvBool("CV_TEST_BOOL_DEFAULT", false); got != false {
		t.Fatalf("expected default false, got %t", got)
	}
}

func TestLoadLDAPConfigDefaultSkipVerify(t *testing.T) {
	unsetEnv(t, "LDAP_SKIP_TLS_VERIFY")
	cfg := loadLDAPConfig()
	if !cfg.SkipTLSVerify {
		t.Fatalf("expected SkipTLSVerify default true")
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	val, ok := os.LookupEnv(key)
	if ok {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset env: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Setenv(key, val)
		})
		return
	}
	t.Cleanup(func() {
		_ = os.Unsetenv(key)
	})
}

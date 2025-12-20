package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureTLSCertCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "registry.crt")
	keyPath := filepath.Join(dir, "registry.key")

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected cert file, got %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file, got %v", err)
	}

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert again: %v", err)
	}
}

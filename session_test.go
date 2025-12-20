package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNamespacesFromAccess(t *testing.T) {
	access := []Access{
		{Namespace: "team1"},
		{Namespace: "team2"},
		{Namespace: "team1"},
	}
	got := namespacesFromAccess(access)
	if len(got) != 2 || got[0] != "team1" || got[1] != "team2" {
		t.Fatalf("unexpected namespaces: %#v", got)
	}
}

func TestGetSessionValid(t *testing.T) {
	resetSessions(t)
	token := "token-valid"
	sessionMu.Lock()
	sessions[token] = sessionData{
		User:      &User{Name: "tester"},
		CreatedAt: time.Now(),
	}
	sessionMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	if _, ok := getSession(req); !ok {
		t.Fatalf("expected session to be valid")
	}
}

func TestGetSessionExpired(t *testing.T) {
	resetSessions(t)
	token := "token-expired"
	sessionMu.Lock()
	sessions[token] = sessionData{
		User:      &User{Name: "tester"},
		CreatedAt: time.Now().Add(-sessionTTL - time.Minute),
	}
	sessionMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	if _, ok := getSession(req); ok {
		t.Fatalf("expected session to be expired")
	}

	sessionMu.Lock()
	_, exists := sessions[token]
	sessionMu.Unlock()
	if exists {
		t.Fatalf("expected expired session to be removed")
	}
}

func resetSessions(t *testing.T) {
	t.Helper()
	sessionMu.Lock()
	sessions = map[string]sessionData{}
	sessionMu.Unlock()
	t.Cleanup(func() {
		sessionMu.Lock()
		sessions = map[string]sessionData{}
		sessionMu.Unlock()
	})
}

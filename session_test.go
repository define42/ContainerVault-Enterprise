package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestCreateSessionStoresData(t *testing.T) {
	resetSessions(t)
	user := &User{Name: "alice"}
	access := []Access{
		{Namespace: "team1"},
		{Namespace: "team2"},
		{Namespace: "team1"},
	}

	start := time.Now()
	token := createSession(user, access)
	end := time.Now()

	if token == "" {
		t.Fatalf("expected token to be set")
	}

	sessionMu.Lock()
	sess, ok := sessions[token]
	sessionMu.Unlock()
	if !ok {
		t.Fatalf("expected session to be stored")
	}
	if sess.User == nil || sess.User.Name != "alice" {
		t.Fatalf("unexpected user: %#v", sess.User)
	}
	expectedNamespaces := []string{"team1", "team2"}
	if !reflect.DeepEqual(sess.Namespaces, expectedNamespaces) {
		t.Fatalf("unexpected namespaces: %#v", sess.Namespaces)
	}
	if sess.CreatedAt.Before(start) || sess.CreatedAt.After(end) {
		t.Fatalf("unexpected CreatedAt: %v", sess.CreatedAt)
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

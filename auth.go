package main

import (
	"net/http"
	"strings"
)

var ldapAuth = ldapAuthenticateAccess

func authenticate(w http.ResponseWriter, r *http.Request) (*User, []Access, bool) {
	username, password, ok := r.BasicAuth()
	if !ok || password == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return nil, nil, false
	}

	u, access, err := ldapAuth(username, password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil, nil, false
	}

	return u, access, true
}

func authorize(access []Access, r *http.Request) bool {
	if !isSafeRequestPath(r) {
		return false
	}

	// Allow registry ping after authentication
	if r.URL.Path == "/v2/" {
		return true
	}

	// Path must be /v2/<namespace>/...
	if !strings.HasPrefix(r.URL.Path, "/v2/") {
		return false
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v2/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 || parts[0] == "" {
		return false
	}
	namespace := parts[0]
	pullOnly, deleteAllowed, ok := namespacePermissions(access, namespace)
	if !ok {
		return false
	}

	// Pull-only enforcement
	if pullOnly {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return true
		case http.MethodDelete:
			return deleteAllowed
		default:
			return false
		}
	}

	if r.Method == http.MethodDelete {
		return deleteAllowed
	}

	return true
}

func namespacePermissions(access []Access, namespace string) (pullOnly bool, deleteAllowed bool, ok bool) {
	pullOnly = true
	for _, entry := range access {
		if entry.Namespace == "" || entry.Namespace != namespace {
			continue
		}
		ok = true
		if !entry.PullOnly {
			pullOnly = false
		}
		if entry.DeleteAllowed {
			deleteAllowed = true
		}
	}
	return pullOnly, deleteAllowed, ok
}

func isSafeRequestPath(r *http.Request) bool {
	raw := r.URL.RawPath
	if raw == "" {
		raw = r.URL.EscapedPath()
	}
	rawLower := strings.ToLower(raw)
	if strings.Contains(rawLower, "%2f") || strings.Contains(rawLower, "%5c") {
		return false
	}
	parts := strings.Split(r.URL.Path, "/")
	for _, part := range parts {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

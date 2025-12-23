package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

func extractCredentials(r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username, password, ok, err := extractCredentials(r)
	if err != nil {
		serveLogin(w, "Invalid form submission.")
		return
	}
	if !ok {
		serveLogin(w, "Missing credentials.")
		return
	}

	user, access, err := ldapAuthenticateAccess(username, password)
	if err != nil {
		log.Printf("ldap auth failed for %s: %v", username, err)
		serveLogin(w, "Invalid credentials.")
		return
	}

	token := createSession(user, access)
	http.SetCookie(w, &http.Cookie{
		Name:     "cv_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
}

func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	serveLogin(w, "")
}

func serveLogin(w http.ResponseWriter, message string) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if message != "" {
		errorHTML = `<div class="error">` + html.EscapeString(message) + `</div>`
	}
	fmt.Fprint(w, strings.Replace(loginHTML, "{{ERROR}}", errorHTML, 1))
}

func renderDashboardHTML(sess sessionData) ([]byte, error) {
	bootstrapJSON, err := json.Marshal(map[string]any{
		"namespaces": sess.Namespaces,
	})
	if err != nil {
		return nil, err
	}

	page := strings.Replace(dashboardHTML, "{{USERNAME}}", html.EscapeString(sess.User.Name), 1)
	page = strings.Replace(page, "{{BOOTSTRAP}}", string(bootstrapJSON), 1)
	return []byte(page), nil
}

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
)

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("cv_session")
	if err == nil && cookie.Value != "" {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
		sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "cv_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func namespaceAllowed(allowed []string, namespace string) bool {
	for _, ns := range allowed {
		if ns == namespace {
			return true
		}
	}
	return false
}

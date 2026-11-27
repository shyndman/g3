package httpd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"g3/internal/auth"
	"g3/internal/config"
	"g3/internal/store"
)

func TestChangePasswordRevokesPriorSessionsAndRotatesCookie(t *testing.T) {
	st, err := store.Open(t.TempDir(), "admin@g3.local", "oldpass123")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	user, err := st.UserByEmail("admin@g3.local")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}

	// Create two active sessions: the caller's session and another device's session.
	tokCurrent, hashCurrent := auth.NewSessionToken()
	_, hashOther := auth.NewSessionToken()
	exp := time.Now().Add(time.Hour)

	if err := st.CreateSession(user.ID, hashCurrent, "browser-a", "127.0.0.1", exp); err != nil {
		t.Fatalf("CreateSession current: %v", err)
	}
	if err := st.CreateSession(user.ID, hashOther, "browser-b", "127.0.0.1", exp); err != nil {
		t.Fatalf("CreateSession other: %v", err)
	}

	a := &api{store: st, cfg: config.Config{DevMode: true}}

	payload, _ := json.Marshal(changePasswordBody{
		Current: "oldpass123",
		Next:    "newpass456",
		Confirm: "newpass456",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/account/password", bytes.NewReader(payload))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tokCurrent})
	rec := httptest.NewRecorder()

	a.changePassword(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Both prior session tokens must now be invalid.
	if _, err := st.UserBySessionToken(hashCurrent); err == nil {
		t.Fatal("expected old current session token to be invalidated")
	}
	if _, err := st.UserBySessionToken(hashOther); err == nil {
		t.Fatal("expected other session token to be invalidated")
	}

	// Response must issue a fresh, valid session cookie.
	var newToken string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			newToken = c.Value
		}
	}
	if newToken == "" || newToken == tokCurrent {
		t.Fatalf("expected rotated session cookie, got %q", newToken)
	}
	if _, err := st.UserBySessionToken(auth.HashToken(newToken)); err != nil {
		t.Fatalf("expected new session token to be valid: %v", err)
	}
}

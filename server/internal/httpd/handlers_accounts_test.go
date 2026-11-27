package httpd

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"g3/internal/auth"
	"g3/internal/config"
	"g3/internal/crypto"
	"g3/internal/drive"
	"g3/internal/store"
)

func TestDeleteDriveAccountRevokesTokenAndDeletesRow(t *testing.T) {
	var revokedToken string
	revokeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		revokedToken = r.PostForm.Get("token")
		w.WriteHeader(http.StatusOK)
	}))
	defer revokeSrv.Close()

	dir := t.TempDir()
	st, err := store.Open(dir, "admin@g3.local", "secret-pass-123")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer st.Close()

	key, err := crypto.LoadOrCreateKey("", dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	cph, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	encToken, err := cph.Encrypt("google-refresh-xyz")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	accID, err := st.UpsertDriveAccount("drive@example.com", encToken, "folder-1", 1000, 100)
	if err != nil {
		t.Fatalf("UpsertDriveAccount: %v", err)
	}

	user, err := st.UserByEmail("admin@g3.local")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	tok, hash := auth.NewSessionToken()
	if err := st.CreateSession(user.ID, hash, "test", "127.0.0.1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	mgr := drive.New("cid", "csec", "http://localhost/cb")
	mgr.SetRevokeEndpoint(revokeSrv.URL)

	a := &api{store: st, cfg: config.Config{DevMode: true}, cipher: cph, drive: mgr}

	req := httptest.NewRequest(http.MethodDelete, "/api/accounts/"+accID, nil)
	req.SetPathValue("id", accID)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rec := httptest.NewRecorder()

	a.deleteDriveAccount(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if revokedToken != "google-refresh-xyz" {
		t.Fatalf("expected revoked token google-refresh-xyz, got %q", revokedToken)
	}
	if _, err := st.DriveAccountByID(accID); err == nil {
		t.Fatal("expected Drive account row to be deleted")
	}
}

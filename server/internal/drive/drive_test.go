package drive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevokePostsTokenForm(t *testing.T) {
	var gotMethod, gotContentType, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		gotToken = r.PostForm.Get("token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	mgr := New("cid", "csec", "http://localhost/cb")
	mgr.SetRevokeEndpoint(srv.URL)

	if err := mgr.Revoke(context.Background(), "refresh-tok-123"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("expected form content-type, got %q", gotContentType)
	}
	if gotToken != "refresh-tok-123" {
		t.Fatalf("expected token refresh-tok-123, got %q", gotToken)
	}
}

func TestRevokeReturnsErrorOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	mgr := New("cid", "csec", "http://localhost/cb")
	mgr.SetRevokeEndpoint(srv.URL)

	if err := mgr.Revoke(context.Background(), "already-revoked"); err == nil {
		t.Fatal("expected error on 400 status")
	}
}

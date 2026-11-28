package httpd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"g3/internal/auth"
	"g3/internal/config"
	"g3/internal/s3"
	"g3/internal/store"
)

func TestMetricsScrape(t *testing.T) {
	st, err := store.Open(t.TempDir(), "admin@g3.local", "secret-pass-123")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first, err := st.UpsertDriveAccount("first@example.com", "unused", "folder-1", 1000, 250)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.UpsertDriveAccount("second@example.com", "unused", "folder-2", 2000, 700)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateDriveQuota(second, 2000, 700, "disconnected"); err != nil {
		t.Fatal(err)
	}
	bucket, err := st.CreateBucket("metrics-fixtures")
	if err != nil {
		t.Fatal(err)
	}

	if err := st.PutObject(store.ObjectWrite{
		BucketID: bucket, Key: "single", Size: 12, AccountID: first, DriveFileID: "file-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutObject(store.ObjectWrite{
		BucketID: bucket, Key: "multipart", Size: 20,
		PartsJSON: fmt.Sprintf(`[{"a":%q,"f":"file-2","s":5},{"a":%q,"f":"file-3","s":15}]`, first, second),
	}); err != nil {
		t.Fatal(err)
	}
	uploadID, err := st.CreateMultipart(bucket, "in-progress", "application/octet-stream", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutPart(uploadID, 1, second, "file-4", 9, "etag"); err != nil {
		t.Fatal(err)
	}

	// Completion publishes the manifest before removing the staged reference.
	finalizing, err := st.CreateMultipart(bucket, "multipart", "application/octet-stream", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutPart(finalizing, 2, second, "file-3", 15, "etag"); err != nil {
		t.Fatal(err)
	}

	// No Drive client or cipher: a scrape must use only local metadata.
	engine := s3.New(st, nil, nil)
	panel, err := New(config.Config{}, st, nil, nil, engine)
	if err != nil {
		t.Fatal(err)
	}
	scrape := func(handler http.Handler) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec
	}

	rec := scrape(panel.Handler)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("scrape Content-Type = %q", got)
	}
	for _, sample := range []string{
		"g3_buckets 1",
		"g3_objects 2",
		"g3_object_bytes 32",
		"g3_drive_accounts 2",
		"g3_drive_connected_accounts 1",
		"g3_drive_usage_bytes 950",
		"g3_drive_quota_bytes 3000",
		fmt.Sprintf(`g3_drive_account_g3_bytes{account_id=%q} 17`, first),
		fmt.Sprintf(`g3_drive_account_g3_bytes{account_id=%q} 24`, second),
	} {
		if !strings.Contains("\n"+rec.Body.String(), "\n"+sample+"\n") {
			t.Errorf("missing exact sample %q in:\n%s", sample, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "@example.com") {
		t.Error("scrape exposed an account email")
	}
	if got := scrape(engine).Code; got != http.StatusForbidden {
		t.Errorf("S3 GET /metrics status = %d, want S3 authentication failure", got)
	}

	if err := st.PutObject(store.ObjectWrite{
		BucketID: bucket, Key: "corrupt", Size: 4, PartsJSON: "[",
	}); err != nil {
		t.Fatal(err)
	}
	rec = scrape(panel.Handler)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "g3_") {
		t.Errorf("failed scrape returned status %d with body %q; want 500 without samples", rec.Code, rec.Body.String())
	}

	user, err := st.UserByEmail("admin@g3.local")
	if err != nil {
		t.Fatal(err)
	}
	token, hash := auth.NewSessionToken()
	if err := st.CreateSession(user.ID, hash, "test", "127.0.0.1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/accounts", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec = httptest.NewRecorder()
	panel.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"g3Usage":24`) {
		t.Errorf("account listing with an unreadable manifest returned %d: %s", rec.Code, rec.Body.String())
	}
}

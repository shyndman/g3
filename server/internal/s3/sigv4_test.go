package s3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"g3/internal/crypto"
	"g3/internal/store"
)

func signHeaderRequest(r *http.Request, accessKey, secret, payloadHash string, ts time.Time) {
	amzDate := ts.UTC().Format(amzDateFormat)
	shortDate := ts.UTC().Format("20060102")
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonReq := canonicalRequest(r, signed, payloadHash, canonicalQuery(r.URL.RawQuery, ""))
	scope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", shortDate)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hashHex([]byte(canonReq)),
	}, "\n")

	signingKey := deriveKey(secret, shortDate, "us-east-1", "s3")
	sig := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, strings.Join(signed, ";"), sig,
	))
}

func TestVerifyV4ClockSkew(t *testing.T) {
	const (
		ak     = "G3TESTKEY"
		secret = "test-secret-value"
	)
	now := time.Date(2026, 11, 27, 16, 0, 0, 0, time.UTC)

	cases := []struct {
		name       string
		offset     time.Duration
		wantOK     bool
		wantSkewed bool
	}{
		{"fresh", -5 * time.Minute, true, false},
		{"too old", -16 * time.Minute, false, true},
		{"too far in future", 16 * time.Minute, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://s3.local/", nil)
			signHeaderRequest(req, ak, secret, hashHex(nil), now.Add(tc.offset))

			cred, err := parseAuthorization(req.Header.Get("Authorization"))
			if err != nil {
				t.Fatalf("parseAuthorization: %v", err)
			}

			ok, skewed := verifyV4(req, cred, secret, now)
			if ok != tc.wantOK || skewed != tc.wantSkewed {
				t.Fatalf("got (ok=%v, skewed=%v), want (ok=%v, skewed=%v)",
					ok, skewed, tc.wantOK, tc.wantSkewed)
			}
		})
	}

	t.Run("missing or malformed date is rejected", func(t *testing.T) {
		if !isRequestTimeSkewed("", now) {
			t.Fatal("expected empty X-Amz-Date to be rejected")
		}
		if !isRequestTimeSkewed("not-a-timestamp", now) {
			t.Fatal("expected malformed X-Amz-Date to be rejected")
		}
	})
}

func TestVerifyingBody(t *testing.T) {
	body := []byte("hello world")
	goodHash := hashHex(body)
	badHash := hashHex([]byte("tampered"))

	t.Run("matching digest succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://s3.local/b/k", bytes.NewReader(body))
		req.Header.Set("X-Amz-Content-Sha256", goodHash)

		got, err := io.ReadAll(verifyingBody(req))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("got %q, want %q", got, body)
		}
	})

	t.Run("mismatched digest fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://s3.local/b/k", bytes.NewReader(body))
		req.Header.Set("X-Amz-Content-Sha256", badHash)

		_, err := io.ReadAll(verifyingBody(req))
		if !errors.Is(err, errPayloadHashMismatch) {
			t.Fatalf("expected errPayloadHashMismatch, got %v", err)
		}
	})

	t.Run("unsigned payload bypasses digest check", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://s3.local/b/k", bytes.NewReader(body))
		req.Header.Set("X-Amz-Content-Sha256", payloadUnsigned)

		got, err := io.ReadAll(verifyingBody(req))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("got %q, want %q", got, body)
		}
	})
}

func newTestS3Server(t *testing.T) (*Server, *store.Store, string, string) {
	t.Helper()
	dir := t.TempDir()

	st, err := store.Open(dir, "admin@g3.local", "test-pass-123")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	key, err := crypto.LoadOrCreateKey("", dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	cph, err := crypto.New(key)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}

	const (
		ak     = "G3TESTACCESSKEY12345"
		secret = "test-secret-key-0123456789"
	)
	enc, err := cph.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := st.CreateAccessKey(ak, enc, "test"); err != nil {
		t.Fatalf("CreateAccessKey: %v", err)
	}

	return New(st, nil, cph), st, ak, secret
}

func TestDeleteObjectsRejectsTamperedPayload(t *testing.T) {
	srv, st, ak, secret := newTestS3Server(t)

	bucketID, err := st.CreateBucket("backups")
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := st.PutObject(store.ObjectWrite{
		BucketID: bucketID, Key: "keep.txt", Size: 5, ETag: "abc", ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	signedBody := []byte(`<Delete><Object><Key>other.txt</Key></Object></Delete>`)
	tamperedBody := []byte(`<Delete><Object><Key>keep.txt</Key></Object></Delete>`)

	req := httptest.NewRequest(http.MethodPost, "http://s3.local/backups?delete=", bytes.NewReader(tamperedBody))
	signHeaderRequest(req, ak, secret, hashHex(signedBody), time.Now())
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "XAmzContentSHA256Mismatch") {
		t.Fatalf("expected XAmzContentSHA256Mismatch in body, got %s", rec.Body.String())
	}
	if _, err := st.ObjectByKey(bucketID, "keep.txt"); err != nil {
		t.Fatalf("expected keep.txt to remain intact, got err: %v", err)
	}
}

func TestServeHTTPRejectsSkewedTimestamp(t *testing.T) {
	srv, _, ak, secret := newTestS3Server(t)

	req := httptest.NewRequest(http.MethodGet, "http://s3.local/", nil)
	signHeaderRequest(req, ak, secret, hashHex(nil), time.Now().Add(-30*time.Minute))
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "RequestTimeTooSkewed") {
		t.Fatalf("expected RequestTimeTooSkewed, got %s", rec.Body.String())
	}
}

func TestDeleteObjectsRejectsOversizedAndStreamingBodies(t *testing.T) {
	srv, st, ak, secret := newTestS3Server(t)

	bucketID, err := st.CreateBucket("backups")
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if err := st.PutObject(store.ObjectWrite{
		BucketID: bucketID, Key: "keep.txt", Size: 5, ETag: "abc", ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	t.Run("oversized padded body cannot bypass digest check", func(t *testing.T) {
		xmlPrefix := []byte(`<Delete><Object><Key>keep.txt</Key></Object></Delete>`)
		padded := append(xmlPrefix, bytes.Repeat([]byte(" "), int(maxDeleteBodyBytes))...)

		req := httptest.NewRequest(http.MethodPost, "http://s3.local/backups?delete=", bytes.NewReader(padded))
		signHeaderRequest(req, ak, secret, hashHex([]byte("other")), time.Now())
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "MaxMessageLengthExceeded") {
			t.Fatalf("expected MaxMessageLengthExceeded, got %s", rec.Body.String())
		}
		if _, err := st.ObjectByKey(bucketID, "keep.txt"); err != nil {
			t.Fatalf("expected keep.txt to remain intact: %v", err)
		}
	})

	t.Run("streaming payload mode is rejected for batch delete", func(t *testing.T) {
		body := []byte("36;chunk-signature=deadbeef\r\n<Delete><Object><Key>keep.txt</Key></Object></Delete>\r\n0;chunk-signature=deadbeef\r\n\r\n")
		req := httptest.NewRequest(http.MethodPost, "http://s3.local/backups?delete=", bytes.NewReader(body))
		signHeaderRequest(req, ak, secret, payloadStreaming, time.Now())
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "InvalidArgument") {
			t.Fatalf("expected InvalidArgument, got %s", rec.Body.String())
		}
		if _, err := st.ObjectByKey(bucketID, "keep.txt"); err != nil {
			t.Fatalf("expected keep.txt to remain intact: %v", err)
		}
	})
}

type failingReader struct {
	prefix []byte
	sent   bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		n := copy(p, f.prefix)
		return n, nil
	}
	return 0, errors.New("connection reset")
}

func TestPutPolicyRejectsReadErrorAndOversizedBody(t *testing.T) {
	srv, st, ak, secret := newTestS3Server(t)

	bucketID, err := st.CreateBucket("docs")
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	const originalPolicy = `{"Version":"2012-10-17"}`
	if err := st.SetBucketPolicy(bucketID, originalPolicy); err != nil {
		t.Fatalf("SetBucketPolicy: %v", err)
	}

	t.Run("transport read error does not overwrite stored policy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://s3.local/docs?policy=", &failingReader{prefix: []byte(`{"bad":`)})
		signHeaderRequest(req, ak, secret, payloadUnsigned, time.Now())
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		got, ok := st.BucketPolicy(bucketID)
		if !ok || got != originalPolicy {
			t.Fatalf("expected original policy intact, got %q (ok=%v)", got, ok)
		}
	})

	t.Run("oversized policy is rejected", func(t *testing.T) {
		big := bytes.Repeat([]byte("a"), int(maxPolicyBodySize)+10)
		req := httptest.NewRequest(http.MethodPut, "http://s3.local/docs?policy=", bytes.NewReader(big))
		signHeaderRequest(req, ak, secret, payloadUnsigned, time.Now())
		rec := httptest.NewRecorder()

		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "MaxMessageLengthExceeded") {
			t.Fatalf("expected MaxMessageLengthExceeded, got %s", rec.Body.String())
		}
		got, ok := st.BucketPolicy(bucketID)
		if !ok || got != originalPolicy {
			t.Fatalf("expected original policy intact, got %q (ok=%v)", got, ok)
		}
	})
}

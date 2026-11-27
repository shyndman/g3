package store

import (
	"errors"
	"testing"
)

func TestOpenRequiresAdminPasswordOnFreshDB(t *testing.T) {
	for _, bad := range []string{"", "   ", retiredDefaultAdminPassword} {
		_, err := Open(t.TempDir(), "admin@g3.local", bad)
		if !errors.Is(err, ErrMissingAdminPassword) {
			t.Fatalf("password=%q: expected ErrMissingAdminPassword, got %v", bad, err)
		}
	}
}

func TestOpenSeedsAdminWithoutForcedPasswordChange(t *testing.T) {
	dir := t.TempDir()

	st, err := Open(dir, "admin@g3.local", "secret-pass-123")
	if err != nil {
		t.Fatalf("Open fresh DB: %v", err)
	}
	defer st.Close()

	u, err := st.UserByEmail("admin@g3.local")
	if err != nil {
		t.Fatalf("UserByEmail: %v", err)
	}
	if u.MustChangePassword {
		t.Fatal("expected seeded admin MustChangePassword to be false")
	}

	// Subsequent opens on an already-initialized DB succeed without G3_ADMIN_PASSWORD.
	st.Close()
	st2, err := Open(dir, "admin@g3.local", "")
	if err != nil {
		t.Fatalf("re-open existing DB without password: %v", err)
	}
	st2.Close()
}

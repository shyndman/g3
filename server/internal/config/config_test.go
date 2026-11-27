package config

import (
	"os"
	"testing"
)

func TestLoadLoopbackDefaultsAndEmptyAdminPassword(t *testing.T) {
	for _, k := range []string{"G3_ADDR", "G3_S3_ADDR", "G3_ADMIN_PASSWORD"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("Unsetenv %s: %v", k, err)
		}
	}

	t.Chdir(t.TempDir())
	cfg := Load()

	if cfg.Addr != DefaultAddr {
		t.Fatalf("expected %q, got %q", DefaultAddr, cfg.Addr)
	}
	if cfg.S3Addr != DefaultS3Addr {
		t.Fatalf("expected %q, got %q", DefaultS3Addr, cfg.S3Addr)
	}
	if cfg.AdminPassword != "" {
		t.Fatalf("expected empty AdminPassword when unset, got %q", cfg.AdminPassword)
	}
}

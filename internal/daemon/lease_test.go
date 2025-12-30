package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLeaseManager_Grant(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// Grant a lease
	lease, err := lm.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 1*time.Hour)
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	if lease.ProjectDir != "/project/foo" {
		t.Errorf("ProjectDir = %q, want %q", lease.ProjectDir, "/project/foo")
	}
	if lease.ProjectName != "myproject" {
		t.Errorf("ProjectName = %q, want %q", lease.ProjectName, "myproject")
	}
	if lease.Environment != "prod" {
		t.Errorf("Environment = %q, want %q", lease.Environment, "prod")
	}
	if lease.IsExpired() {
		t.Error("Lease should not be expired immediately after grant")
	}

	// Verify lease was persisted
	if _, err := os.Stat(leasesFile); err != nil {
		t.Errorf("Leases file not created: %v", err)
	}
}

func TestLeaseManager_Get(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// No lease initially
	lease := lm.Get("/project/foo", "prod")
	if lease != nil {
		t.Error("Expected nil lease before grant")
	}

	// Grant a lease
	_, err := lm.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 1*time.Hour)
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	// Now should find it
	lease = lm.Get("/project/foo", "prod")
	if lease == nil {
		t.Error("Expected to find lease after grant")
	}

	// Different env should not find it
	lease = lm.Get("/project/foo", "dev")
	if lease != nil {
		t.Error("Should not find lease for different env")
	}
}

func TestLeaseManager_Revoke(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	// Create a fake .env file to verify cleanup
	projectDir := filepath.Join(tmpDir, "project")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	dotEnvPath := filepath.Join(projectDir, ".env")
	if err := os.WriteFile(dotEnvPath, []byte("SECRET=value\n"), 0600); err != nil {
		t.Fatalf("write .env failed: %v", err)
	}

	lm := NewLeaseManager(leasesFile, nil)

	// Grant a lease
	_, err := lm.Grant(projectDir, "myproject", "prod", dotEnvPath, 1*time.Hour)
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	// Verify lease exists
	if lm.Get(projectDir, "prod") == nil {
		t.Error("Lease should exist before revoke")
	}

	// Revoke
	if err := lm.Revoke(projectDir, "prod"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Verify lease is gone
	if lm.Get(projectDir, "prod") != nil {
		t.Error("Lease should be gone after revoke")
	}

	// Verify .env was removed
	if _, err := os.Stat(dotEnvPath); !os.IsNotExist(err) {
		t.Error(".env file should have been removed on revoke")
	}
}

func TestLeaseManager_Extend(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// Grant with short TTL
	lease, err := lm.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 1*time.Minute)
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	oldExpiry := lease.ExpiresAt

	// Extend by 1 hour
	extended, err := lm.Extend("/project/foo", "prod", 1*time.Hour)
	if err != nil {
		t.Fatalf("Extend failed: %v", err)
	}

	if !extended.ExpiresAt.After(oldExpiry) {
		t.Error("Extended lease should have later expiry")
	}

	// Extension should be roughly 1 hour from now
	expectedExpiry := time.Now().Add(1 * time.Hour)
	diff := extended.ExpiresAt.Sub(expectedExpiry)
	if diff < -5*time.Second || diff > 5*time.Second {
		t.Errorf("Extended expiry is off by %v", diff)
	}
}

func TestLeaseManager_ExtendNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// Try to extend non-existent lease
	_, err := lm.Extend("/project/foo", "prod", 1*time.Hour)
	if err == nil {
		t.Error("Expected error when extending non-existent lease")
	}
}

func TestLeaseManager_List(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// Initially empty
	leases := lm.List()
	if len(leases) != 0 {
		t.Errorf("Expected 0 leases, got %d", len(leases))
	}

	// Grant multiple leases
	lm.Grant("/project/a", "proja", "prod", "/project/a/.env", 1*time.Hour)
	lm.Grant("/project/b", "projb", "dev", "/project/b/.env", 1*time.Hour)
	lm.Grant("/project/a", "proja", "dev", "/project/a/.env", 1*time.Hour)

	leases = lm.List()
	if len(leases) != 3 {
		t.Errorf("Expected 3 leases, got %d", len(leases))
	}
}

func TestLeaseManager_ReplaceExisting(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	lm := NewLeaseManager(leasesFile, nil)

	// Grant first lease
	lease1, _ := lm.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 30*time.Minute)

	// Grant again with longer TTL (should replace)
	lease2, _ := lm.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 2*time.Hour)

	// Should only have one lease
	if lm.Count() != 1 {
		t.Errorf("Expected 1 lease, got %d", lm.Count())
	}

	// New lease should have later expiry
	if !lease2.ExpiresAt.After(lease1.ExpiresAt) {
		t.Error("Replaced lease should have later expiry")
	}
}

func TestLeaseManager_Persistence(t *testing.T) {
	tmpDir := t.TempDir()
	leasesFile := filepath.Join(tmpDir, "leases.json")

	// Create manager and grant lease
	lm1 := NewLeaseManager(leasesFile, nil)
	_, err := lm1.Grant("/project/foo", "myproject", "prod", "/project/foo/.env", 1*time.Hour)
	if err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	// Create new manager and load
	lm2 := NewLeaseManager(leasesFile, nil)
	if err := lm2.load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should find the lease
	lease := lm2.Get("/project/foo", "prod")
	if lease == nil {
		t.Error("Lease should persist across manager instances")
	}
	if lease.ProjectName != "myproject" {
		t.Errorf("ProjectName = %q, want %q", lease.ProjectName, "myproject")
	}
}

func TestLease_IsExpired(t *testing.T) {
	now := time.Now()

	// Not expired
	lease := &Lease{
		ExpiresAt: now.Add(1 * time.Hour),
	}
	if lease.IsExpired() {
		t.Error("Lease with future expiry should not be expired")
	}

	// Expired
	lease = &Lease{
		ExpiresAt: now.Add(-1 * time.Minute),
	}
	if !lease.IsExpired() {
		t.Error("Lease with past expiry should be expired")
	}
}

func TestLease_Remaining(t *testing.T) {
	now := time.Now()

	// Has remaining time
	lease := &Lease{
		ExpiresAt: now.Add(30 * time.Minute),
	}
	remaining := lease.Remaining()
	if remaining < 29*time.Minute || remaining > 31*time.Minute {
		t.Errorf("Remaining = %v, expected ~30m", remaining)
	}

	// Already expired
	lease = &Lease{
		ExpiresAt: now.Add(-1 * time.Minute),
	}
	remaining = lease.Remaining()
	if remaining != 0 {
		t.Errorf("Remaining = %v, expected 0 for expired lease", remaining)
	}
}

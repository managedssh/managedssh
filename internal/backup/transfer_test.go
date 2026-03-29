package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mylovelytools/managedssh/internal/vault"
)

func TestExportImportRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Ensure XDG_CONFIG_HOME is not set to use the fallback path
	t.Setenv("XDG_CONFIG_HOME", "")

	configDir := filepath.Join(home, ".config", "managedssh")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	originalVault := []byte(`{"salt":"abc","nonce":"def","verifier":"ghi"}`)
	originalHosts := []byte(`{"hosts":[{"id":"1","alias":"demo"}]}`)
	if err := os.WriteFile(filepath.Join(configDir, "vault.json"), originalVault, 0600); err != nil {
		t.Fatalf("write vault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.json"), originalHosts, 0600); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	bundlePath, err := DefaultPath()
	if err != nil {
		t.Fatalf("default path: %v", err)
	}

	if err := Export(bundlePath); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "vault.json"), []byte(`{"corrupt":true}`), 0600); err != nil {
		t.Fatalf("overwrite vault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.json"), []byte(`{"hosts":[]}`), 0600); err != nil {
		t.Fatalf("overwrite hosts: %v", err)
	}

	if err := Import(bundlePath); err != nil {
		t.Fatalf("import failed: %v", err)
	}

	gotVault, err := os.ReadFile(filepath.Join(configDir, "vault.json"))
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	if !jsonEqual(originalVault, gotVault) {
		t.Fatalf("vault mismatch\nwant: %s\ngot:  %s", originalVault, gotVault)
	}

	gotHosts, err := os.ReadFile(filepath.Join(configDir, "hosts.json"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	if !jsonEqual(originalHosts, gotHosts) {
		t.Fatalf("hosts mismatch\nwant: %s\ngot:  %s", originalHosts, gotHosts)
	}

	if err := VerifyMasterPassword(bundlePath, "backup-master-key"); err == nil {
		t.Fatalf("expected verification to fail with wrong password")
	}
}

func TestVerifyMasterPassword(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Ensure XDG_CONFIG_HOME is not set to use the fallback path
	t.Setenv("XDG_CONFIG_HOME", "")

	configDir := filepath.Join(home, ".config", "managedssh")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	master := "correct horse battery staple"
	if _, err := vault.Create(master); err != nil {
		t.Fatalf("create vault: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "hosts.json"), []byte(`{"hosts":[]}`), 0600); err != nil {
		t.Fatalf("write hosts: %v", err)
	}

	bundlePath, err := DefaultPath()
	if err != nil {
		t.Fatalf("default path: %v", err)
	}
	if err := Export(bundlePath); err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if err := VerifyMasterPassword(bundlePath, master); err != nil {
		t.Fatalf("expected verification success: %v", err)
	}
	if err := VerifyMasterPassword(bundlePath, "wrong-password"); err == nil {
		t.Fatalf("expected wrong password failure")
	}
}

func TestXDGConfigHome(t *testing.T) {
	home := t.TempDir()
	xdgConfig := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdgConfig)

	// Create config dir in XDG_CONFIG_HOME
	configDir := filepath.Join(xdgConfig, "managedssh")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}

	// vault.Dir() should return XDG_CONFIG_HOME path
	dir, err := vault.Dir()
	if err != nil {
		t.Fatalf("vault.Dir: %v", err)
	}
	if dir != configDir {
		t.Fatalf("expected %s, got %s", configDir, dir)
	}
}

func jsonEqual(a, b []byte) bool {
	var va any
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	var vb any
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

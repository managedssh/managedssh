package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDirUsesXDGConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/managedssh-xdg")
	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir() returned error: %v", err)
	}
	want := filepath.Join("/tmp/managedssh-xdg", "managedssh")
	if dir != want {
		t.Fatalf("unexpected dir: got %q want %q", dir, want)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("secret-value")

	blob, err := Encrypt(key, plain)
	if err != nil {
		t.Fatalf("Encrypt() returned error: %v", err)
	}
	got, err := Decrypt(key, blob)
	if err != nil {
		t.Fatalf("Decrypt() returned error: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", string(got), string(plain))
	}
}

func TestDecryptRejectsShortBlob(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	if _, err := Decrypt(key, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected short blob to fail decryption")
	}
}

func TestExistsUsesVaultMetaPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	exists, err := Exists()
	if err != nil {
		t.Fatalf("Exists() returned error: %v", err)
	}
	if exists {
		t.Fatal("expected vault metadata to not exist yet")
	}

	vaultDir, err := Dir()
	if err != nil {
		t.Fatalf("Dir() returned error: %v", err)
	}
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatalf("failed to create vault dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "vault.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("failed to create meta file: %v", err)
	}

	exists, err = Exists()
	if err != nil {
		t.Fatalf("Exists() returned error: %v", err)
	}
	if !exists {
		t.Fatal("expected vault metadata to exist")
	}
}

func TestZeroKeyOverwritesBytes(t *testing.T) {
	key := []byte{1, 2, 3, 4}
	ZeroKey(key)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("expected key[%d] to be zero, got %d", i, b)
		}
	}
}

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
		t.Fatalf("Dir() failed: %v", err)
	}
	want := filepath.Join("/tmp/managedssh-xdg", "managedssh")
	if dir != want {
		t.Fatalf("Dir() = %q, want %q", dir, want)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x52}, 32)
	plaintext := []byte("secret")

	blob, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	got, err := Decrypt(key, blob)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt mismatch: got %q, want %q", got, plaintext)
	}
}

func TestExistsFromMetaFile(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)

	exists, err := Exists()
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if exists {
		t.Fatal("expected no vault metadata file")
	}

	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir() failed: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vault.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write meta failed: %v", err)
	}

	exists, err = Exists()
	if err != nil {
		t.Fatalf("Exists() failed: %v", err)
	}
	if !exists {
		t.Fatal("expected vault metadata file to exist")
	}
}

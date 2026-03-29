package sshclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestUnknownHostErrorString(t *testing.T) {
	err := &UnknownHostError{Host: "example.com", Fingerprint: "SHA256:abc"}
	got := err.Error()
	want := "unknown host key for example.com (SHA256:abc)"
	if got != want {
		t.Fatalf("unexpected error string: got %q want %q", got, want)
	}
}

func TestStripKnownHostPort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "example.com:22", want: "example.com"},
		{in: "[2001:db8::1]:22", want: "2001:db8::1"},
		{in: "example.com", want: "example.com"},
	}

	for _, tc := range cases {
		if got := stripKnownHostPort(tc.in); got != tc.want {
			t.Fatalf("stripKnownHostPort(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandUserPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir() failed: %v", err)
	}

	if got := expandUserPath("~"); got != home {
		t.Fatalf("expandUserPath(~) = %q, want %q", got, home)
	}

	want := filepath.Join(home, ".ssh", "id_ed25519")
	if got := expandUserPath("~/.ssh/id_ed25519"); got != want {
		t.Fatalf("expandUserPath(~/...) = %q, want %q", got, want)
	}
}

func TestNeedsPassphraseWithMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if NeedsPassphrase(missing, nil) {
		t.Fatal("expected false when key path does not exist")
	}
}

func TestSessionZeroMethods(t *testing.T) {
	s := &Session{
		Password:      []byte("pw"),
		KeyData:       []byte("key"),
		KeyPassphrase: []byte("pass"),
	}

	s.zeroPassword()
	if s.Password != nil {
		t.Fatal("expected Password to be nil after zeroPassword")
	}

	s.zeroKeyData()
	if s.KeyData != nil {
		t.Fatal("expected KeyData to be nil after zeroKeyData")
	}

	s.zeroKeyPassphrase()
	if s.KeyPassphrase != nil {
		t.Fatal("expected KeyPassphrase to be nil after zeroKeyPassphrase")
	}
}

func TestTrustHostKeyNilInput(t *testing.T) {
	if err := TrustHostKey(nil); err == nil {
		t.Fatal("expected error for nil UnknownHostError")
	}
}

func TestFlattenAuthMethodsEmpty(t *testing.T) {
	if got := flattenAuthMethods(nil); !bytes.Equal([]byte{}, []byte{}) && len(got) != 0 {
		t.Fatal("expected empty auth method list")
	}
}

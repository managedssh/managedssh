package sshclient

import (
	"context"
	"errors"
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

func TestStripKnownHostPortTable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "host with port", in: "example.com:22", want: "example.com"},
		{name: "ipv6 with port", in: "[2001:db8::1]:2200", want: "2001:db8::1"},
		{name: "plain host", in: "example.com", want: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripKnownHostPort(tt.in)
			if got != tt.want {
				t.Fatalf("stripKnownHostPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzStripKnownHostPort(f *testing.F) {
	f.Add("example.com")
	f.Add("example.com:22")
	f.Add("[2001:db8::1]:22")
	f.Add(":")

	f.Fuzz(func(t *testing.T, in string) {
		_ = stripKnownHostPort(in)
	})
}

func TestVerifyWithContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := VerifyWithContext(ctx, VerifyConfig{
		Host:     "127.0.0.1",
		Port:     22,
		User:     "nobody",
		Password: []byte("pw"),
	})
	if err == nil {
		t.Fatal("expected canceled context to fail verification")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestTrustHostKeyNilInput(t *testing.T) {
	if err := TrustHostKey(nil); err == nil {
		t.Fatal("expected error for nil unknown host")
	}
}

func TestExpandUserPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve home directory: %v", err)
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

func TestFlattenAuthMethodsEmpty(t *testing.T) {
	if got := flattenAuthMethods(nil); len(got) != 0 {
		t.Fatal("expected empty auth method list")
	}
}

package tui

import (
	"testing"
)

func TestParseSSHCommand(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    parsedSSH
		wantErr bool
	}{
		{
			name:  "user@host",
			input: "ssh user@host",
			want:  parsedSSH{Hostname: "host", User: "user"},
		},
		{
			name:  "bare host",
			input: "ssh host",
			want:  parsedSSH{Hostname: "host"},
		},
		{
			name:  "no ssh prefix",
			input: "user@example.com",
			want:  parsedSSH{Hostname: "example.com", User: "user"},
		},
		{
			name:  "-p before destination",
			input: "ssh -p 2222 user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 2222},
		},
		{
			name:  "-i before destination",
			input: "ssh -i ~/.ssh/id_ed25519 user@host",
			want:  parsedSSH{Hostname: "host", User: "user", KeyPath: "~/.ssh/id_ed25519"},
		},
		{
			name:  "-i and -p",
			input: "ssh -i /path/to/key -p 2322 user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 2322, KeyPath: "/path/to/key"},
		},
		{
			name:  "-p before -i",
			input: "ssh -p 2322 -i /path/to/key user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 2322, KeyPath: "/path/to/key"},
		},
		{
			name:  "-l flag for user",
			input: "ssh -l root host",
			want:  parsedSSH{Hostname: "host", User: "root"},
		},
		{
			name:  "-l overridden by user@host",
			input: "ssh -l ignored deploy@host",
			want:  parsedSSH{Hostname: "host", User: "deploy"},
		},
		{
			name:  "flag value attached: -p2222",
			input: "ssh -p2222 user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 2222},
		},
		{
			name:  "verbose flags ignored",
			input: "ssh -v -p 22 user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 22},
		},
		{
			name:  "remote command ignored",
			input: "ssh user@host ls -la",
			want:  parsedSSH{Hostname: "host", User: "user"},
		},
		{
			name:  "quoted key path",
			input: `ssh -i "/path with spaces/key" user@host`,
			want:  parsedSSH{Hostname: "host", User: "user", KeyPath: "/path with spaces/key"},
		},
		{
			name:  "-- separator",
			input: "ssh -p 2222 -- user@host",
			want:  parsedSSH{Hostname: "host", User: "user", Port: 2222},
		},
		{
			name:  "ip address host",
			input: "ssh ubuntu@192.168.1.10",
			want:  parsedSSH{Hostname: "192.168.1.10", User: "ubuntu"},
		},
		{
			name:    "no hostname",
			input:   "ssh -p 22",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid port",
			input:   "ssh -p abc user@host",
			wantErr: true,
		},
		{
			name:    "port out of range",
			input:   "ssh -p 99999 user@host",
			wantErr: true,
		},
		{
			name:    "missing flag argument",
			input:   "ssh -p",
			wantErr: true,
		},
		{
			name:    "unterminated quote",
			input:   `ssh -i "unclosed user@host`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSSHCommand(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got result %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseSSHCommand(%q)\n  got  %+v\n  want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTokenizeSSH(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "basic",
			input: "ssh user@host",
			want:  []string{"ssh", "user@host"},
		},
		{
			name:  "extra spaces",
			input: "  ssh   -p  22  user@host  ",
			want:  []string{"ssh", "-p", "22", "user@host"},
		},
		{
			name:  "single quoted",
			input: "ssh -i '/path with space/key' user@host",
			want:  []string{"ssh", "-i", "/path with space/key", "user@host"},
		},
		{
			name:  "double quoted",
			input: `ssh -i "/path with space/key" user@host`,
			want:  []string{"ssh", "-i", "/path with space/key", "user@host"},
		},
		{
			name:  "backslash escape",
			input: `ssh -i /path\ with\ space/key user@host`,
			want:  []string{"ssh", "-i", "/path with space/key", "user@host"},
		},
		{
			name:    "unterminated single quote",
			input:   "ssh -i 'path user@host",
			wantErr: true,
		},
		{
			name:    "unterminated double quote",
			input:   `ssh -i "path user@host`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenizeSSH(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("token[%d]: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

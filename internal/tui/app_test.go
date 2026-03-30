package tui

import "testing"

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3}
	zeroBytes(data)
	for i, v := range data {
		if v != 0 {
			t.Fatalf("expected data[%d] to be zero, got %d", i, v)
		}
	}
}

func TestNewSearchInputDefaults(t *testing.T) {
	input := newSearchInput()
	if input.Placeholder == "" {
		t.Fatal("expected placeholder to be set")
	}
	if input.CharLimit != 64 {
		t.Fatalf("expected char limit 64, got %d", input.CharLimit)
	}
}

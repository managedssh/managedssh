package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCmdRejectsPositionalArgs(t *testing.T) {
	err := rootCmd.Args(rootCmd, []string{"extra"})
	if err == nil {
		t.Fatal("expected positional args to be rejected")
	}
}

func TestRootCmdHelpIncludesInterfaceControls(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected help to render without error: %v", err)
	}

	help := out.String()
	if !strings.Contains(help, "Interface Controls:") {
		t.Fatal("expected help output to include interface controls header")
	}
	if !strings.Contains(help, "change master key") {
		t.Fatal("expected help output to include at least one dashboard control")
	}
}

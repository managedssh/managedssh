package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpIncludesInterfaceControls(t *testing.T) {
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--help"})

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute help command: %v", err)
	}

	help := out.String()
	if !strings.Contains(help, "Interface Controls:") {
		t.Fatal("expected help output to include interface controls section")
	}
	if !strings.Contains(help, "change master key") {
		t.Fatal("expected help output to include at least one dashboard control")
	}
}

func TestRootRejectsPositionalArguments(t *testing.T) {
	if err := rootCmd.Args(rootCmd, []string{"extra"}); err == nil {
		t.Fatal("expected positional arguments to be rejected")
	}
}

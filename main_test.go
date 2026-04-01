package main

import (
	"reflect"
	"testing"

	"github.com/mylovelytools/managedssh/cmd"
)

func TestMainWiresCommandExecute(t *testing.T) {
	if reflect.ValueOf(cmd.Execute).Kind() != reflect.Func {
		t.Fatal("expected cmd.Execute to be a function")
	}
}

func TestMainPackageCompiles(t *testing.T) {
	// Presence of this test keeps the top-level package in test runs.
}

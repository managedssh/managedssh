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

package main

import (
	"strings"
	"testing"
)

// The program is read back from the task as Windows keeps it.
func TestTaskCommand(t *testing.T) {
	exe := `C:\Users\Имя\OneDrive\Рабочий стол\TurnVK & co.exe`
	cmd, ok := taskCommand(utf16File(taskXML(`PC\user`, exe)))
	if !ok || cmd != exe {
		t.Fatalf("%q, %v", cmd, ok)
	}
	if _, ok := taskCommand([]byte(strings.Repeat("x", 10))); ok {
		t.Fatal("a command in no task")
	}
}

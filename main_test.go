package main

import (
	"bytes"
	"errors"
	"testing"
)

func TestRunReportsExecutionErrors(t *testing.T) {
	var stderr bytes.Buffer
	if got := run(func() error { return errors.New("profile not found") }, &stderr); got != 1 {
		t.Fatalf("exit code = %d, want 1", got)
	}
	if got := stderr.String(); got != "error: profile not found\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestRunDoesNotWriteOnSuccess(t *testing.T) {
	var stderr bytes.Buffer
	if got := run(func() error { return nil }, &stderr); got != 0 {
		t.Fatalf("exit code = %d, want 0", got)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q", got)
	}
}

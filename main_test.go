package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProcessHelper(t *testing.T) {
	if os.Getenv("MCPEEK_TEST_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing helper argument delimiter")
}

func TestProcessExitCodes(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		args     []string
		input    string
		code     int
		contains string
	}{
		{"clean", []string{"-"}, `{"mcpServers":{}}`, 0, ""},
		{"finding", []string{"-"}, `{"mcpServers":{"docs":{"url":"http://example.com"}}}`, 1, "warning remote-http"},
		{"incomplete", []string{"--format=json", "-"}, `{"mcpServers":{"docs":{"command":"sh"}}}`, 2, `"complete":false`},
		{"arguments", nil, "", 2, "invalid arguments"},
		{"version", []string{"--version"}, "", 0, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestProcessHelper$", "--"}, tc.args...)
			cmd := exec.Command(binary, args...)
			cmd.Env = append(os.Environ(), "MCPEEK_TEST_PROCESS=1")
			cmd.Stdin = strings.NewReader(tc.input)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			err := cmd.Run()
			if err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					t.Fatal(err)
				}
			}
			if cmd.ProcessState.ExitCode() != tc.code || !strings.Contains(out.String(), tc.contains) {
				t.Fatalf("got exit %d, output %q", cmd.ProcessState.ExitCode(), out.String())
			}
		})
	}
}

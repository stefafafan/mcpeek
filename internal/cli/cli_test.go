package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(args []string, input string) (int, string, string) {
	var out, err bytes.Buffer
	code := Run(args, strings.NewReader(input), &out, &err, "test-version")
	return code, out.String(), err.String()
}

const remoteInput = `{"mcpServers":{"docs":{"url":"http://example.com"}}}`

func TestThresholdsAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		input string
		code  int
	}{
		{"warning", []string{"-"}, remoteInput, 1},
		{"threshold", []string{"--fail-on=error", "-"}, remoteInput, 0},
		{"error", []string{"--fail-on=error", "-"}, `{"mcpServers":{"docs":{"command":"docker","args":["run","--privileged","mcp"]}}}`, 1},
		{"override", []string{"--ignore", "remote-http:docs", "-"}, remoteInput, 0},
		{"wrong server", []string{"--ignore", "remote-http:other", "-"}, remoteInput, 1},
		{"unknown rule", []string{"--ignore", "made-up:docs", "-"}, remoteInput, 2},
		{"empty server", []string{"--ignore", "remote-http:", "-"}, remoteInput, 2},
		{"missing colon", []string{"--ignore", "remote-http", "-"}, remoteInput, 2},
		{"incomplete precedence", []string{"--ignore", "secret-literal:docs", "-"}, `{"mcpServers":{"docs":{"command":"sh","env":{"TOKEN":"secret"}}}}`, 2},
		{"repeated override", []string{"--ignore", "remote-http:docs", "--ignore", "secret-literal:docs", "-"}, `{"mcpServers":{"docs":{"url":"http://example.com","headers":{"Authorization":"secret"}}}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, err := invoke(tc.args, tc.input)
			if code != tc.code {
				t.Fatalf("got %d %s %s", code, out, err)
			}
		})
	}
	code, out, err := invoke([]string{"--format=json", "--ignore=remote-http:docs", "-"}, remoteInput)
	if code != 0 || err != "" || !strings.Contains(out, `"source":"command-line"`) || !strings.Contains(out, `"rule":"remote-http"`) {
		t.Fatalf("missing suppression: %d %s %s", code, out, err)
	}
	_, out, _ = invoke([]string{"--ignore=remote-http:docs", "-"}, remoteInput)
	if out != "" {
		t.Fatalf("suppressed text finding: %s", out)
	}
}

func TestConfigExceptions(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.json")
	other := filepath.Join(dir, "other.json")
	config := filepath.Join(dir, "mcpeek.jsonc")
	for _, file := range []string{input, other} {
		if err := os.WriteFile(file, []byte(remoteInput), 0600); err != nil {
			t.Fatal(err)
		}
	}
	content := `{
 // scoped exception
 "ignore": [ /* block comment */ {"rule":"remote-http","file":"input.json","server":"docs","reason":"Local test at http://example.com /* literal */"}]
 }`
	if err := os.WriteFile(config, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file string
		code int
	}{{input, 0}, {other, 1}, {"-", 1}} {
		code, out, stderr := invoke([]string{"--format=json", "--config", config, tc.file}, remoteInput)
		if code != tc.code {
			t.Fatalf("got %d %s %s", code, out, stderr)
		}
		if tc.code == 0 && (!strings.Contains(out, `"source":"config"`) || !strings.Contains(out, "Local test")) {
			t.Fatalf("missing provenance: %s", out)
		}
	}
	for _, bad := range []string{
		`null`, `[]`, `{"unknown":[]}`, `{"ignore":null}`, `{"ignore":[null]}`,
		`{"ignore":[{"rule":"remote-http","file":"input.json","server":"docs","reason":" "}]}`,
		`{"ignore":[{"rule":"unknown","file":"input.json","server":"docs","reason":"test"}]}`,
		`{"ignore":[{"rule":"remote-http","file":"input.json","server":"docs","reason":"test","extra":true}]}`,
		`{"ignore":[{"rule":"remote-http","file":"input.json","server":"docs"}]}`,
		`{"ignore":[],}`, `{"ignore":[],"ignore":[]}`, `{/* unterminated`,
	} {
		if err := os.WriteFile(config, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		code, out, stderr := invoke([]string{"--config", config, input}, "")
		if code != 2 {
			t.Fatalf("accepted %s: %d %s %s", bad, code, out, stderr)
		}
	}
	code, _, _ := invoke([]string{"--config", filepath.Join(dir, "missing"), input}, "")
	if code != 2 {
		t.Fatal("accepted missing config")
	}
}

func TestJSONIncompleteAndRedaction(t *testing.T) {
	code, out, stderr := invoke([]string{"--format=json", "-"}, `{"mcpServers":{"docs":{"command":"sh","env":{"TOKEN":"DO-NOT-PRINT"}}}}`)
	if code != 2 || stderr != "" || !strings.Contains(out, `"complete":false`) || !strings.Contains(out, `"code":"unassessed"`) || strings.Contains(out, "DO-NOT-PRINT") {
		t.Fatalf("bad report: %d %s %s", code, out, stderr)
	}
	code, out, stderr = invoke([]string{"--format=json", "-"}, `{"mcpServers": DO-NOT-PRINT}`)
	if code != 2 || strings.Contains(out+stderr, "DO-NOT-PRINT") {
		t.Fatalf("parse error leaked input: %s %s", out, stderr)
	}
}

func TestCLIContract(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		input    string
		code     int
		contains string
	}{
		{"empty", []string{"-"}, `{"mcpServers":{}}`, 0, ""},
		{"missing file", nil, "", 2, ""},
		{"two files", []string{"a", "b"}, "", 2, ""},
		{"bad format", []string{"--format", "yaml", "-"}, "", 2, ""},
		{"bad threshold", []string{"--fail-on", "info", "-"}, "", 2, ""},
		{"unknown option", []string{"--wat", "-"}, "", 2, ""},
		{"help", []string{"--help"}, "", 0, "mcpeek [options] FILE"},
		{"short help", []string{"-h"}, "", 0, "--ignore"},
		{"version", []string{"--version"}, "", 0, "test-version"},
		{"invalid input", []string{"-"}, `{`, 2, ""},
		{"unsupported shape", []string{"-"}, `{"servers":{}}`, 2, ""},
		{"unreadable file", []string{"/nonexistent/mcpeek.json"}, "", 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := invoke(tc.args, tc.input)
			if code != tc.code || !strings.Contains(out, tc.contains) {
				t.Fatalf("got (%d, %q, %q), want code %d containing %q", code, out, stderr, tc.code, tc.contains)
			}
		})
	}
}

func TestJSONEmptyArrays(t *testing.T) {
	code, out, stderr := invoke([]string{"--format=json", "-"}, `{"mcpServers":{}}`)
	var result struct {
		Complete    bool
		Findings    []any
		Diagnostics []any
	}
	if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || !result.Complete || result.Findings == nil || result.Diagnostics == nil {
		t.Fatalf("invalid report: %d %s %s", code, out, stderr)
	}
}

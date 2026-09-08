package check

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func scanServer(server string) Result {
	return Scan([]byte(`{"mcpServers":{"test":`+server+`}}`), "input.json")
}
func rules(r Result) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Rule)
	}
	return out
}
func TestValidation(t *testing.T) {
	for _, input := range []string{
		`null`, `[]`, `{}`, `{"mcpServers":null}`, `{"mcpServers":[]}`,
		`{"mcpServers":{},"mcpServers":{}}`, `{"mcpServers":{}} {}`,
		`{"mcpServers":{"a":null}}`, `{"mcpServers":{"a":{}}}`,
		`{"mcpServers":{"a":{"url":"https://example.com","url":"http://example.com"}}}`,
		`{"mcpServers":{"a":{"command":"npx","args":[1]}}}`,
		`{"mcpServers":{"a":{"url":"https://example.com","headers":{"X":null}}}}`,
		`{"mcpServers":{"a":{"url":"https://example.com","env":null}}}`,
		`{"mcpServers":{"a":{"url":"https://example.com","command":"npx"}}}`,
		`{"mcpServers":{"a":{"command":"sh","args":["-c","npx foo"]}}}`,
		`{"mcpServers":{"a":{"command":"/custom/server"}}}`,
		`{"mcpServers":{"a":{"type":"unknown","url":"https://example.com"}}}`,
		`{"mcpServers":{"a":{"type":"stdio","url":"https://example.com"}}}`,
		`{"mcpServers":{"a":{"url":"https://example.com","extra":true}}}`,
	} {
		t.Run(input, func(t *testing.T) {
			r := Scan([]byte(input), "f")
			if r.Complete || len(r.Diagnostics) == 0 {
				t.Fatalf("expected incomplete: %+v", r)
			}
		})
	}
}

func TestRemote(t *testing.T) {
	for _, tc := range []struct {
		url            string
		complete, warn bool
	}{
		{"https://example.com/mcp", true, false}, {"http://example.com/mcp", true, true},
		{"http://localhost:3000", true, false}, {"http://LOCALHOST./mcp", true, false},
		{"http://127.1.2.3", true, false}, {"http://[::1]:3000", true, false},
		{"http://[::ffff:127.0.0.1]", true, false}, {"http://localhost.evil.test", true, true},
		{"http://0.0.0.0", true, true}, {"http://192.168.1.2", true, true},
		{"ftp://example.com", false, false}, {"not-a-url", false, false}, {"http:///mcp", false, false},
		{"${ENDPOINT}", false, false}, {"https://example.com:${PORT}", false, false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			b, _ := json.Marshal(map[string]string{"url": tc.url})
			r := scanServer(string(b))
			if r.Complete != tc.complete || (len(r.Findings) > 0) != tc.warn {
				t.Fatalf("unexpected: %+v", r)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	for _, tc := range []struct {
		value string
		warn  bool
	}{
		{"literal-super-secret", true}, {"", false}, {"  ", false},
		{"${API_KEY}", false}, {"$API_KEY", false}, {"${env:API_KEY}", false}, {"${input:api-key}", false},
		{"Bearer ${API_KEY}", false}, {"Basic ${env:AUTH}", false},
		{"${API_KEY:-literal-super-secret}", true}, {"${API_KEY}literal-super-secret", true},
	} {
		t.Run(tc.value, func(t *testing.T) {
			b, _ := json.Marshal(map[string]any{"url": "https://example.com", "headers": map[string]string{"Authorization": tc.value}})
			r := scanServer(string(b))
			if !r.Complete || (len(r.Findings) > 0) != tc.warn {
				t.Fatalf("unexpected: %+v", r)
			}
			out, _ := json.Marshal(r)
			if strings.Contains(string(out), "literal-super-secret") {
				t.Fatal("secret leaked")
			}
		})
	}
	r := scanServer(`{"url":"https://example.com","env":{"GITHUB_TOKEN":"secret","AWS_SECRET_ACCESS_KEY":"secret","API_KEY":"secret","PATH":"value","TOKENIZER":"value"},"headers":{"X-Api-Key":"secret","Accept":"text/event-stream"}}`)
	if len(r.Findings) != 4 {
		t.Fatalf("expected four credentials, got %+v", r)
	}
	r = scanServer(`{"url":"https://user:literal-super-secret@example.com/mcp?token=literal-super-secret"}`)
	if !reflect.DeepEqual(rules(r), []string{"secret-literal", "secret-literal"}) {
		t.Fatalf("URL credentials not found: %+v", r)
	}
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), "literal-super-secret") {
		t.Fatal("URL secret leaked")
	}
}

func TestPartialAndDeterministic(t *testing.T) {
	input := []byte(`{"mcpServers":{"z":{"command":"sh","env":{"TOKEN":"secret"}},"a":{"url":"http://example.com"}}}`)
	first := Scan(input, "f")
	if first.Complete || len(first.Findings) != 2 || first.Findings[0].Server != "a" {
		t.Fatalf("unexpected partial analysis: %+v", first)
	}
	for range 20 {
		if !reflect.DeepEqual(first, Scan(input, "f")) {
			t.Fatal("nondeterministic")
		}
	}
	r := Scan([]byte(`{"mcpServers":{"a.b\n":{"url":"http://example.com"}}}`), "f")
	if r.Findings[0].Path != `$.mcpServers["a.b\n"].url` {
		t.Fatalf("invalid JSON path: %q", r.Findings[0].Path)
	}
}

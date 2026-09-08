package check

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTLSVerificationEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
		want             bool
	}{
		{"disabled", "NODE_TLS_REJECT_UNAUTHORIZED", "0", true},
		{"enabled", "NODE_TLS_REJECT_UNAUTHORIZED", "1", false},
		{"empty", "NODE_TLS_REJECT_UNAUTHORIZED", "", false},
		{"false is not zero", "NODE_TLS_REJECT_UNAUTHORIZED", "false", false},
		{"whitespace", "NODE_TLS_REJECT_UNAUTHORIZED", " 0 ", false},
		{"reference", "NODE_TLS_REJECT_UNAUTHORIZED", "${env:TLS_VERIFY}", false},
		{"default expression", "NODE_TLS_REJECT_UNAUTHORIZED", "${TLS_VERIFY:-0}", false},
		{"lowercase name", "node_tls_reject_unauthorized", "0", false},
		{"unrelated name", "EXAMPLE_NODE_TLS_REJECT_UNAUTHORIZED", "0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(map[string]any{
				"command": "npx", "args": []string{"server@1.2.3"},
				"env": map[string]string{tc.key: tc.value},
			})
			if err != nil {
				t.Fatal(err)
			}
			r := scanServer(string(b))
			if !r.Complete || (len(r.Findings) != 0) != tc.want {
				t.Fatalf("unexpected result: %+v", r)
			}
			if tc.want {
				want := Finding{
					Rule: "tls-verification-disabled", Severity: "error", Server: "test",
					Path:    "$.mcpServers.test.env.NODE_TLS_REJECT_UNAUTHORIZED",
					Message: "TLS certificate verification is explicitly disabled",
				}
				if !reflect.DeepEqual(r.Findings, []Finding{want}) {
					t.Fatalf("unexpected finding: %+v", r.Findings)
				}
			}
		})
	}
}

func TestTLSVerificationBoundaries(t *testing.T) {
	for _, server := range []string{
		`{"command":"npx","args":["server@1.2.3","NODE_TLS_REJECT_UNAUTHORIZED=0"]}`,
		`{"url":"https://example.com","headers":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}`,
		`{"url":"https://example.com?NODE_TLS_REJECT_UNAUTHORIZED=0"}`,
		`{"url":"https://example.com","env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}`,
	} {
		r := scanServer(server)
		if !r.Complete || len(r.Findings) != 0 {
			t.Fatalf("unrelated value triggered: %+v", r)
		}
	}
	r := scanServer(`{"command":"sh","args":["-c","example"],"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}`)
	if r.Complete || !reflect.DeepEqual(rules(r), []string{"tls-verification-disabled"}) {
		t.Fatalf("known finding lost during incomplete analysis: %+v", r)
	}
}

func TestTLSVerificationDocker(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           []string
		complete, want bool
	}{
		{"separate", []string{"run", "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"attached", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"equals", []string{"run", "--env=NODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"short equals", []string{"run", "-e=NODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"long separate", []string{"container", "run", "--env", "NODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"enabled", []string{"run", "-e", "NODE_TLS_REJECT_UNAUTHORIZED=1", pinnedImage}, true, false},
		{"inherited", []string{"run", "-e", "NODE_TLS_REJECT_UNAUTHORIZED", pinnedImage}, true, false},
		{"reference", []string{"run", "-e", "NODE_TLS_REJECT_UNAUTHORIZED=${VERIFY}", pinnedImage}, true, false},
		{"label", []string{"run", "--label", "NODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, false},
		{"container argument", []string{"run", pinnedImage, "-e", "NODE_TLS_REJECT_UNAUTHORIZED=0"}, true, false},
		{"overridden", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", "-eNODE_TLS_REJECT_UNAUTHORIZED=1", pinnedImage}, true, false},
		{"last disables", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=1", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"last inherits", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", "-eNODE_TLS_REJECT_UNAUTHORIZED", pinnedImage}, true, false},
		{"duplicate", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", pinnedImage}, true, true},
		{"incomplete", []string{"run", "-eNODE_TLS_REJECT_UNAUTHORIZED=0", "--unknown", pinnedImage}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := launch("docker", tc.args...)
			if r.Complete != tc.complete || (len(r.Findings) != 0) != tc.want {
				t.Fatalf("unexpected result: %+v", r)
			}
			if tc.want && (len(r.Findings) != 1 || r.Findings[0].Rule != "tls-verification-disabled" || r.Findings[0].Path != "$.mcpServers.test.args") {
				t.Fatalf("unexpected finding: %+v", r.Findings)
			}
		})
	}
}

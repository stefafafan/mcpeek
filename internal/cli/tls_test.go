package cli

import (
	"strings"
	"testing"
)

const tlsInput = `{"mcpServers":{"docs":{"command":"npx","args":["server@1.2.3"],"env":{"NODE_TLS_REJECT_UNAUTHORIZED":"0"}}}}`

func TestTLSVerificationRuleCLI(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"default", []string{"-"}, 1},
		{"error threshold", []string{"--fail-on=error", "-"}, 1},
		{"suppressed", []string{"--ignore=tls-verification-disabled:docs", "-"}, 0},
		{"wrong server", []string{"--ignore=tls-verification-disabled:other", "-"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, stderr := invoke(tc.args, tlsInput)
			if code != tc.code || stderr != "" {
				t.Fatalf("unexpected result: %d %s %s", code, out, stderr)
			}
			if code == 0 && out != "" {
				t.Fatalf("suppressed finding in text: %s", out)
			}
		})
	}
	code, out, stderr := invoke([]string{"--format=json", "--ignore=tls-verification-disabled:docs", "-"}, tlsInput)
	if code != 0 || stderr != "" || !strings.Contains(out, `"rule":"tls-verification-disabled"`) || !strings.Contains(out, `"source":"command-line"`) {
		t.Fatalf("missing suppression: %d %s %s", code, out, stderr)
	}
}

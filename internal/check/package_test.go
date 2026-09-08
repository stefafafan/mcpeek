package check

import (
	"encoding/json"
	"testing"
)

func launch(command string, args ...string) Result {
	b, _ := json.Marshal(map[string]any{"command": command, "args": args})
	return scanServer(string(b))
}
func TestPackages(t *testing.T) {
	for _, tc := range []struct {
		name, command string
		args          []string
		complete      bool
		warnings      int
	}{
		{"npx absent", "npx", []string{"server"}, true, 1},
		{"npx pin", "npx", []string{"-y", "@scope/server@1.2.3"}, true, 0},
		{"npx prerelease", "/usr/local/bin/npx", []string{"--yes", "server@1.2.3-rc.1+build.2"}, true, 0},
		{"npx latest", "npx", []string{"server@latest"}, true, 1},
		{"npx range", "npx", []string{"server@^1.2.3"}, true, 1},
		{"npx major", "npx", []string{"server@1"}, true, 1},
		{"npx wildcard", "npx", []string{"server@1.2.x"}, true, 1},
		{"npx arguments", "npx", []string{"server@1.2.3", "--package", "other", "--privileged"}, true, 0},
		{"npx package", "npx", []string{"--package", "server@1.2.3", "server"}, true, 0},
		{"npx packages", "npx", []string{"-p", "one@1.2.3", "--package=two@latest", "one"}, true, 1},
		{"npx short attached", "npx", []string{"-pone@1.2.3", "one"}, true, 0},
		{"npx delimiter", "npx", []string{"--", "one@1.2.3"}, true, 0},
		{"npx git", "npx", []string{"github:org/repo"}, false, 0},
		{"npx URL", "npx", []string{"https://example.com/package.tgz"}, false, 0},
		{"npx path", "npx", []string{"./server"}, false, 0},
		{"npx shell", "npx", []string{"-c", "server"}, false, 0},
		{"npx unknown", "npx", []string{"--mystery", "server"}, false, 0},
		{"npx missing package", "npx", []string{"-p"}, false, 0},
		{"npx missing command", "npx", []string{"-p", "one@1.2.3"}, false, 0},
		{"uvx absent", "uvx", []string{"server"}, true, 1},
		{"uvx pin", "uvx", []string{"server==1.2.3"}, true, 0},
		{"uvx at pin", "uvx", []string{"server@1.2.3"}, true, 0},
		{"uvx latest", "uvx", []string{"server@latest"}, true, 1},
		{"uvx range", "uvx", []string{"server>=1.2"}, true, 1},
		{"uvx wildcard", "uvx", []string{"server==1.*"}, true, 1},
		{"uvx extras", "uvx", []string{"server[cli]==1.2.3rc1"}, true, 0},
		{"uvx from", "uvx", []string{"--from", "package==1.2.3", "server", "--privileged"}, true, 0},
		{"uvx from equals", "uvx", []string{"--from=package", "server"}, true, 1},
		{"uvx with", "uvx", []string{"--with", "dep>=1", "server==1.2"}, true, 1},
		{"uvx git", "uvx", []string{"--from", "git+https://example.com/repo", "server"}, false, 0},
		{"uvx unknown", "uvx", []string{"--mystery", "server"}, false, 0},
		{"uvx missing value", "uvx", []string{"--from"}, false, 0},
		{"wrapper", "env", []string{"npx", "server"}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := launch(tc.command, tc.args...)
			if r.Complete != tc.complete || len(r.Findings) != tc.warnings {
				t.Fatalf("unexpected report: %+v", r)
			}
			for _, f := range r.Findings {
				if f.Rule != "package-unpinned" || f.Path != "$.mcpServers.test.args" {
					t.Fatalf("unexpected finding: %+v", f)
				}
			}
		})
	}
}

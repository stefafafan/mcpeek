package check

import (
	"encoding/json"
	"strings"
	"testing"
)

const gitCommit = "0123456789abcdef0123456789abcdef01234567"

func TestFullCommitGitPackages(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		args    []string
	}{
		{"npm https", "npx", []string{"git+https://github.com/org/repo.git#" + gitCommit}},
		{"npm ssh", "npx", []string{"git+ssh://git@github.com/org/repo.git#" + gitCommit}},
		{"npm git protocol", "npx", []string{"git://example.com/org/repo.git#" + gitCommit}},
		{"npm git http", "npx", []string{"git+http://example.com/org/repo.git#" + gitCommit}},
		{"npm plain git URL", "npx", []string{"https://github.com/org/repo.git#" + gitCommit}},
		{"npm github shorthand", "npx", []string{"github:org/repo#" + gitCommit}},
		{"npm short github", "npx", []string{"org/repo#" + gitCommit}},
		{"npm selector", "npx", []string{"-y", "--package=github:org/repo#" + gitCommit, "server", "--privileged"}},
		{"uv https", "uvx", []string{"--from", "git+https://github.com/org/repo.git@" + gitCommit, "server"}},
		{"uv ssh", "uvx", []string{"--from=git+ssh://git@github.com/org/repo.git@" + gitCommit, "server"}},
		{"uv named requirement", "uvx", []string{"--from", "server[cli] @ git+https://github.com/org/repo.git@" + gitCommit, "server"}},
		{"uv subdirectory", "uvx", []string{"--from", "git+https://github.com/org/repo.git@" + gitCommit + "#subdirectory=packages/server", "server"}},
		{"uv with", "uvx", []string{"--with", "git+https://github.com/org/dep@" + gitCommit, "server==1.2.3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := launch(tc.command, tc.args...)
			if !r.Complete || len(r.Findings) != 0 {
				t.Fatalf("full commit was not treated as pinned: %+v", r)
			}
		})
	}
}

func TestUnsupportedGitReferences(t *testing.T) {
	for _, tc := range []struct{ command, spec string }{
		{"npx", "github:org/repo#main"},
		{"npx", "github:org/repo#v1.2.3"},
		{"npx", "github:org/repo#0123456"},
		{"npx", "github:org/repo#" + gitCommit + "0"},
		{"npx", "github:org/repo#" + strings.Repeat("g", 40)},
		{"npx", "github:org/repo#" + gitCommit + "::path:other"},
		{"npx", "github:/repo#" + gitCommit},
		{"npx", "git+https:///repo.git#" + gitCommit},
		{"npx", "git+https://example.com/#" + gitCommit},
		{"npx", "git+https://${HOST}/repo.git#" + gitCommit},
		{"npx", "git+https://example.com/repo.git?rev=main#" + gitCommit},
		{"npx", "https://example.com/package.tgz#" + gitCommit},
		{"npx", "https://example.com/repo.git#" + gitCommit},
		{"npx", "https://github.com.evil.test/org/repo.git#" + gitCommit},
		{"npx", "git+https://github.com/org/repo/tree/main#" + gitCommit},
		{"npx", "git+ssh://git@github.com/org/repo/tree/main#" + gitCommit},
		{"npx", "git+https://www.github.com/org/repo/tree/main#" + gitCommit},
		{"npx", "git+https://GITHUB.COM:443/org/repo/tree/main#" + gitCommit},
		{"npx", "git+file:///repo.git#" + gitCommit},
		{"uvx", "git+https://github.com/org/repo.git@main"},
		{"uvx", "git+https://github.com/org/repo.git@0123456"},
		{"uvx", "git+ssh://" + gitCommit + "@github.com/org/repo.git"},
		{"uvx", "git+https://github.com/org/repo.git#" + gitCommit},
		{"uvx", "git+https://github.com/org/repo.git@" + gitCommit + "#unknown=value"},
		{"uvx", "git+https://github.com/org/repo.git@" + gitCommit + "#subdirectory=../outside"},
		{"uvx", "git+https://github.com/org/repo.git@" + gitCommit + "#subdirectory="},
		{"uvx", "git+https://github.com/org/repo.git%40" + gitCommit},
		{"uvx", "server @ git+https://github.com/org/repo.git@" + gitCommit + " ; python_version > '3.12'"},
	} {
		t.Run(tc.spec, func(t *testing.T) {
			args := []string{tc.spec}
			if tc.command == "uvx" {
				args = []string{"--from", tc.spec, "server"}
			}
			r := launch(tc.command, args...)
			if r.Complete || len(r.Findings) != 0 {
				t.Fatalf("unsupported reference must remain unassessed: %+v", r)
			}
		})
	}
}

func TestGitPinDoesNotHideOtherPackages(t *testing.T) {
	r := launch("npx", "-p", "github:org/repo#"+gitCommit, "-p", "other@latest", "server")
	if !r.Complete || len(r.Findings) != 1 || r.Findings[0].Rule != "package-unpinned" {
		t.Fatalf("expected mutable registry package warning: %+v", r)
	}
	r = launch("npx", "server@"+gitCommit)
	if !r.Complete || len(r.Findings) != 1 {
		t.Fatalf("registry tag must not be treated as Git commit: %+v", r)
	}
}

func TestUVPositionalGitSource(t *testing.T) {
	r := launch("uvx", "git+https://example.com/repo.git@"+gitCommit)
	if !r.Complete || len(r.Findings) != 0 {
		t.Fatalf("positional Git source must count as pinned: %+v", r)
	}
}

func TestGitDiagnosticsDoNotExposeCredentials(t *testing.T) {
	r := launch("uvx", "--from", "git+https://user:DO-NOT-PRINT@example.com/repo.git@short", "server")
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || strings.Contains(string(data), "DO-NOT-PRINT") {
		t.Fatalf("unexpected report: %s", data)
	}
}

func FuzzGitPackages(f *testing.F) {
	for _, spec := range []string{
		"github:org/repo#" + gitCommit,
		"git+ssh://git@github.com/org/repo.git@" + gitCommit,
		"server @ git+https://example.com/repo@" + gitCommit + "#subdirectory=src",
		"https://example.com/repo.git#" + gitCommit,
	} {
		f.Add(spec)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		for _, kind := range []string{"npx", "uvx"} {
			result := launch(kind, "--package", spec, "server")
			if kind == "uvx" {
				result = launch(kind, "--from", spec, "server")
			}
			if fullCommitGitReference(spec, kind) && (!result.Complete || len(result.Findings) != 0) {
				t.Fatalf("Git pin classification disagrees with launch analysis: %+v", result)
			}
		}
	})
}

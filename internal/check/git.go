package check

import (
	"net/url"
	"regexp"
	"strings"
)

var fullGitCommit = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
var githubRepository = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
var pythonRequirementName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?$`)
var gitSubdirectory = regexp.MustCompile(`^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)

// Recognize only explicit full commits. Never resolve revisions or inspect a
// repository, and never interpret a registry tag as a Git revision.
func fullCommitGitReference(spec, kind string) bool {
	if kind == "uvx" && !strings.HasPrefix(spec, "git+") {
		name, source, ok := strings.Cut(spec, "@")
		if !ok || !pythonRequirementName.MatchString(strings.TrimSpace(name)) {
			return false
		}
		spec = strings.TrimSpace(source)
	}
	if strings.ContainsAny(spec, " \t\r\n${}\\") {
		return false
	}
	if kind == "npx" {
		repository, revision, ok := strings.Cut(spec, "#")
		if !ok || !fullGitCommit.MatchString(revision) {
			return false
		}
		if githubRepository.MatchString(strings.TrimPrefix(repository, "github:")) {
			return true
		}
	}

	u, err := url.Parse(spec)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.RawFragment != "" {
		return false
	}
	if kind == "npx" && strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.") == "github.com" {
		// npm's hosted Git parser can prefer /tree/BRANCH over a SHA fragment.
		if !githubRepository.MatchString(strings.TrimPrefix(u.Path, "/")) {
			return false
		}
	}
	switch u.Scheme {
	case "git+https", "git+http", "git+ssh":
	case "git", "https", "http":
		if kind != "npx" {
			return false
		}
		if u.Scheme != "git" {
			// Generic HTTP URLs may be tarballs even when their path ends in .git.
			if u.Host != "github.com" || !strings.HasSuffix(u.Path, ".git") ||
				!githubRepository.MatchString(strings.TrimPrefix(u.Path, "/")) {
				return false
			}
		}
	default:
		return false
	}

	repository := u.Path
	revision := u.Fragment
	if kind == "uvx" {
		// Split the URL path, not the raw URL: an SSH username also uses @.
		i := strings.LastIndex(repository, "@")
		if i < 0 {
			return false
		}
		revision = repository[i+1:]
		repository = repository[:i]
		if u.Fragment != "" {
			directory, ok := strings.CutPrefix(u.Fragment, "subdirectory=")
			if !ok || !gitSubdirectory.MatchString(directory) {
				return false
			}
			for part := range strings.SplitSeq(directory, "/") {
				if part == "." || part == ".." {
					return false
				}
			}
		}
	}
	return strings.HasPrefix(repository, "/") && strings.Trim(repository, "/") != "" &&
		!strings.Contains(repository, "@") && fullGitCommit.MatchString(revision)
}

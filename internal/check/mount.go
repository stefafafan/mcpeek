package check

import (
	"encoding/csv"
	"io"
	"path"
	"regexp"
	"strings"
)

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:/`)
var volumeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// Colons in client variable references and Windows drive letters are not volume
// separators. No variables are expanded and no host filesystem is inspected.
func volumeParts(value string) []string {
	var parts []string
	start, depth := 0, 0
	for i, c := range value {
		if c == '{' {
			depth++
		}
		if c == '}' {
			depth--
		}
		if c == ':' && depth == 0 {
			if i == start+1 && i+1 < len(value) && ((value[start] >= 'A' && value[start] <= 'Z') || (value[start] >= 'a' && value[start] <= 'z')) && (value[i+1] == '/' || value[i+1] == '\\') {
				continue
			}
			parts = append(parts, value[start:i])
			start = i + 1
		}
	}
	return append(parts, value[start:])
}
func (r *Result) volume(server, p, value string) {
	bad := func() { r.Problem(p, server, "unassessed", "unsupported Docker volume syntax") }
	parts := volumeParts(value)
	if len(parts) > 3 || len(parts) == 0 {
		bad()
		return
	}
	if len(parts) == 1 {
		if !absolutePath(parts[0]) {
			bad()
		}
		return
	}
	if parts[0] == "" || !absolutePath(parts[1]) {
		bad()
		return
	}
	if len(parts) == 3 {
		for opt := range strings.SplitSeq(parts[2], ",") {
			switch opt {
			case "ro", "rw", "z", "Z", "cached", "delegated", "consistent", "private", "rprivate", "shared", "rshared", "slave", "rslave", "nocopy":
			default:
				bad()
				return
			}
		}
	}
	if volumeName.MatchString(parts[0]) {
		return
	}
	r.mountSource(server, p, parts[0])
}
func (r *Result) mount(server, p, value string) {
	bad := func() { r.Problem(p, server, "unassessed", "unsupported Docker mount syntax") }
	reader := csv.NewReader(strings.NewReader(value))
	row, err := reader.Read()
	if err != nil {
		bad()
		return
	}
	if _, err := reader.Read(); err != io.EOF {
		bad()
		return
	}
	fields := map[string]string{}
	for _, item := range row {
		key, val, equals := strings.Cut(item, "=")
		switch key {
		case "src":
			key = "source"
		case "dst", "destination":
			key = "target"
		case "ro":
			key = "readonly"
		}
		if _, exists := fields[key]; exists {
			bad()
			return
		}
		switch key {
		case "type", "source", "target", "bind-propagation":
			if !equals || val == "" {
				bad()
				return
			}
		case "readonly":
			if !equals {
				val = "true"
			}
			if val != "true" && val != "false" {
				bad()
				return
			}
		default:
			bad()
			return
		}
		fields[key] = val
	}
	if !absolutePath(fields["target"]) {
		bad()
		return
	}
	typ := fields["type"]
	if typ == "" {
		typ = "volume"
	}
	switch typ {
	case "bind":
		if fields["source"] == "" {
			bad()
			return
		}
		r.mountSource(server, p, fields["source"])
	case "volume":
		if fields["source"] != "" && !volumeName.MatchString(fields["source"]) {
			bad()
		}
	case "tmpfs":
		if fields["source"] != "" {
			bad()
		}
	default:
		bad()
	}
}
func absolutePath(s string) bool {
	s = strings.ReplaceAll(s, `\`, "/")
	return strings.HasPrefix(s, "/") || windowsDrive.MatchString(s)
}
func (r *Result) mountSource(server, p, source string) {
	source = strings.ReplaceAll(source, `\`, "/")
	for _, home := range []string{"${env:USERPROFILE}", "${env:HOME}", "${USERPROFILE}", "${HOME}", "$USERPROFILE", "$HOME", "~"} {
		if source == home || strings.HasPrefix(source, home+"/") {
			source = "/home/mcpeek-user" + strings.TrimPrefix(source, home)
			break
		}
	}
	if !absolutePath(source) || strings.ContainsAny(source, "${}%~") {
		r.Problem(p, server, "unassessed", "mount source cannot be assessed statically")
		return
	}
	if windowsDrive.MatchString(source) {
		source = source[:2] + path.Clean(source[2:])
	} else {
		source = path.Clean(source)
	}
	lower := strings.ToLower(source)
	if path.Base(lower) == "docker.sock" || lower == "//./pipe/docker_engine" || lower == "/pipe/docker_engine" {
		r.finding(server, p, "docker-socket", "host Docker socket is mounted")
	}
	sensitive := source == "/" || lower == "/root" || (len(source) == 3 && windowsDrive.MatchString(source))
	parts := strings.Split(strings.Trim(source, "/"), "/")
	if len(parts) == 2 && (parts[0] == "home" || parts[0] == "Users") {
		sensitive = true
	}
	if len(parts) == 3 && strings.EqualFold(parts[1], "Users") && windowsDrive.MatchString(source) {
		sensitive = true
	}
	for _, part := range parts {
		switch strings.ToLower(part) {
		case ".ssh", ".aws", ".kube", ".docker", ".gnupg":
			sensitive = true
		}
	}
	if strings.Contains(lower, "/.config/gcloud/") || strings.HasSuffix(lower, "/.config/gcloud") {
		sensitive = true
	}
	if sensitive {
		r.finding(server, p, "sensitive-mount", "sensitive host path is mounted")
	}
}

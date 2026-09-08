package check

import (
	"regexp"
	"strings"
)

var npmSpec = regexp.MustCompile(`^((?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9_-][a-zA-Z0-9._-]*)(?:@([^\s/:]+))?$`)
var npmExact = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var pythonSpec = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?)(.*)$`)
var pythonExact = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?$`)
var pythonRange = regexp.MustCompile(`^(?:==|!=|>=|<=|~=|>|<)[A-Za-z0-9.*+!_-]+(?:\.[A-Za-z0-9.*+!_-]+)*(?:,(?:==|!=|>=|<=|~=|>|<)[A-Za-z0-9.*+!_-]+(?:\.[A-Za-z0-9.*+!_-]+)*)*$`)

func packagePin(spec, kind string) (supported, pinned bool) {
	if kind == "npx" {
		m := npmSpec.FindStringSubmatch(spec)
		if m == nil {
			return false, false
		}
		return true, npmExact.MatchString(m[2])
	}
	m := pythonSpec.FindStringSubmatch(spec)
	if m == nil {
		return false, false
	}
	version := m[2]
	if version == "" {
		return true, false
	}
	if after, ok := strings.CutPrefix(version, "@"); ok {
		v := after
		return v == "latest" || pythonExact.MatchString(v), pythonExact.MatchString(v)
	}
	if !pythonRange.MatchString(version) {
		return false, false
	}
	return true, strings.HasPrefix(version, "==") && pythonExact.MatchString(strings.TrimPrefix(version, "=="))
}

func (r *Result) packages(server, path string, args []string, kind string) {
	problem := func() { r.Problem(path, server, "unassessed", "unsupported package launch syntax") }
	var specs []string
	explicit := false
	fromSeen := false
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			i++
			break
		}
		if !strings.HasPrefix(arg, "-") {
			break
		}
		key, value, equals := strings.Cut(arg, "=")
		if kind == "npx" && (key == "-y" || key == "--yes") && (!equals || value == "true" || value == "false") {
			i++
			continue
		}
		takesValue := (kind == "npx" && (key == "-p" || key == "--package")) || (kind == "uvx" && (key == "--from" || key == "--with"))
		if kind == "npx" && strings.HasPrefix(arg, "-p") && !strings.HasPrefix(arg, "--") && len(arg) > 2 && !equals {
			key = "-p"
			value = arg[2:]
			equals = true
			takesValue = true
		}
		if !takesValue {
			problem()
			return
		}
		if !equals {
			i++
			if i >= len(args) {
				problem()
				return
			}
			value = args[i]
		}
		if value == "" || strings.HasPrefix(value, "-") {
			problem()
			return
		}
		if key == "--from" {
			if fromSeen {
				problem()
				return
			}
			fromSeen = true
		}
		if key != "--with" {
			explicit = true
		}
		specs = append(specs, value)
		i++
	}
	if i >= len(args) || args[i] == "" || strings.HasPrefix(args[i], "-") {
		problem()
		return
	}
	if !explicit {
		specs = append(specs, args[i])
	}
	for _, spec := range specs {
		supported, pinned := packagePin(spec, kind)
		if !supported {
			problem()
			continue
		}
		if !pinned {
			r.finding(server, path, "package-unpinned", "package version is not pinned")
		}
	}
}

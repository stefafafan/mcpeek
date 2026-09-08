package check

import (
	"regexp"
	"strconv"
	"strings"
)

var imageName = regexp.MustCompile(`^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/)*[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`)
var sha256Digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (r *Result) docker(server, path string, args []string) {
	problem := func() { r.Problem(path, server, "unassessed", "unsupported Docker launch syntax") }
	if len(args) > 0 && args[0] == "container" {
		args = args[1:]
	}
	if len(args) == 0 || args[0] != "run" {
		problem()
		return
	}
	privileged := false
	namespaces := map[string]string{}
	// Scalar Docker options use their final value; mounts and env options repeat.
	defer func() {
		if privileged {
			r.finding(server, path, "docker-privileged", "Docker launch enables privileged mode")
		}
		for _, key := range sortedKeys(namespaces) {
			if namespaces[key] == "host" {
				r.finding(server, path, "host-namespace", "Docker shares the host "+key+" namespace")
			}
		}
	}()
	i := 1
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
		if !equals && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 2 && strings.Trim(arg[1:], "itd") == "" {
			i++
			continue
		}
		switch key {
		case "--privileged", "--rm", "--interactive", "--tty", "--detach", "--read-only", "--init", "-i", "-t", "-d":
			enabled := true
			if equals {
				var err error
				enabled, err = strconv.ParseBool(value)
				if err != nil {
					problem()
					return
				}
			}
			if key == "--privileged" {
				privileged = enabled
			}
			i++
			continue
		}
		if !strings.HasPrefix(arg, "--") && len(arg) > 2 && strings.ContainsRune("vepluw", rune(arg[1])) {
			key = arg[:2]
			value = arg[2:]
			equals = true
			value = strings.TrimPrefix(value, "=")
		}
		switch key {
		case "-v", "--volume", "--mount", "-e", "--env", "--network", "--net", "--pid", "--ipc",
			"--name", "--user", "-u", "--workdir", "-w", "--entrypoint", "--label", "-l", "--publish", "-p", "--platform", "--pull":
		default:
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
		if value == "" {
			problem()
			return
		}
		if (key == "--network" || key == "--net" || key == "--pid" || key == "--ipc") && strings.ContainsAny(value, "${}%") {
			problem()
			return
		}
		switch key {
		case "-v", "--volume":
			r.volume(server, path, value)
		case "--mount":
			r.mount(server, path, value)
		case "-e", "--env":
			k, v, ok := strings.Cut(value, "=")
			if ok {
				r.credential(server, path, k, v)
			}
		case "--network", "--net":
			namespaces["network"] = value
		case "--pid":
			namespaces["PID"] = value
		case "--ipc":
			namespaces["IPC"] = value
		}
		i++
	}
	if i >= len(args) {
		problem()
		return
	}
	name, digest, hasDigest := strings.Cut(args[i], "@")
	if !imageName.MatchString(name) || (hasDigest && !sha256Digest.MatchString(digest)) {
		problem()
		return
	}
	if !hasDigest {
		r.finding(server, path, "image-unpinned", "Docker image is not pinned by digest")
	}
}

package check

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

var pinnedImage = "registry.example.com/mcp@sha256:" + strings.Repeat("a", 64)

func TestDocker(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		complete bool
		rules    []string
	}{
		{"digest", []string{"run", "-i", "--rm", pinnedImage}, true, nil},
		{"container run", []string{"container", "run", "-it", pinnedImage}, true, nil},
		{"tag", []string{"run", "mcp:1.2.3"}, true, []string{"image-unpinned"}},
		{"no tag", []string{"run", "mcp"}, true, []string{"image-unpinned"}},
		{"privileged", []string{"run", "--privileged", pinnedImage}, true, []string{"docker-privileged"}},
		{"true", []string{"run", "--privileged=true", pinnedImage}, true, []string{"docker-privileged"}},
		{"false", []string{"run", "--privileged=false", pinnedImage}, true, nil},
		{"override", []string{"run", "--privileged", "--privileged=false", pinnedImage}, true, nil},
		{"option value", []string{"run", "--label", "--privileged", pinnedImage}, true, nil},
		{"server args", []string{"run", pinnedImage, "--privileged", "-v", "/:/host"}, true, nil},
		{"socket volume", []string{"run", "-v", "/var/run/docker.sock:/socket:ro", pinnedImage}, true, []string{"docker-socket"}},
		{"socket attached", []string{"run", "-v/run/docker.sock:/socket", pinnedImage}, true, []string{"docker-socket"}},
		{"socket equals", []string{"run", "--volume=/var/run/docker.sock:/socket", pinnedImage}, true, []string{"docker-socket"}},
		{"socket mount", []string{"run", "--mount", "type=bind,source=/var/run/docker.sock,target=/socket,readonly", pinnedImage}, true, []string{"docker-socket"}},
		{"mount aliases", []string{"run", "--mount=src=/home/alice/.ssh,dst=/keys,type=bind,ro=true", pinnedImage}, true, []string{"sensitive-mount"}},
		{"root", []string{"run", "-v", "/:/host", pinnedImage}, true, []string{"sensitive-mount"}},
		{"home", []string{"run", "-v", "/Users/alice:/home", pinnedImage}, true, []string{"sensitive-mount"}},
		{"home variable", []string{"run", "-v", "${env:HOME}:/home", pinnedImage}, true, []string{"sensitive-mount"}},
		{"tilde ssh", []string{"run", "-v", "~/.ssh:/keys", pinnedImage}, true, []string{"sensitive-mount"}},
		{"aws", []string{"run", "-v", "/home/alice/.aws/credentials:/keys", pinnedImage}, true, []string{"sensitive-mount"}},
		{"normal mount", []string{"run", "-v", "/workspace:/work", pinnedImage}, true, nil},
		{"named volume", []string{"run", "-v", "data:/work", pinnedImage}, true, nil},
		{"anonymous volume", []string{"run", "-v", "/data", pinnedImage}, true, nil},
		{"volume mount", []string{"run", "--mount", "type=volume,source=data,target=/work", pinnedImage}, true, nil},
		{"host namespaces", []string{"run", "--network=host", "--pid", "host", "--ipc=host", pinnedImage}, true, []string{"host-namespace", "host-namespace", "host-namespace"}},
		{"bridge", []string{"run", "--net=bridge", pinnedImage}, true, nil},
		{"env secret", []string{"run", "-e", "API_KEY=literal-secret", pinnedImage}, true, []string{"secret-literal"}},
		{"env ref", []string{"run", "--env=API_KEY=${API_KEY}", pinnedImage}, true, nil},
		{"env inherited", []string{"run", "-eAPI_KEY", pinnedImage}, true, nil},
		{"unknown flag", []string{"run", "--unknown", "value", pinnedImage}, false, nil},
		{"env file", []string{"run", "--env-file", "secrets", pinnedImage}, false, nil},
		{"global options", []string{"--context", "remote", "run", pinnedImage}, false, nil},
		{"compose", []string{"compose", "up"}, false, nil},
		{"missing image", []string{"run", "--privileged"}, false, []string{"docker-privileged"}},
		{"missing option value", []string{"run", "-v"}, false, nil},
		{"bad bool", []string{"run", "--privileged=maybe", pinnedImage}, false, nil},
		{"variable image", []string{"run", "${IMAGE}"}, false, nil},
		{"bad digest", []string{"run", "mcp@sha256:abc"}, false, nil},
		{"bad mount", []string{"run", "--mount", "type=bind,source=/,target", pinnedImage}, false, nil},
		{"duplicate mount key", []string{"run", "--mount", "type=bind,source=/,source=/workspace,target=/data", pinnedImage}, false, nil},
		{"unknown source variable", []string{"run", "-v", "${CUSTOM}:/data", pinnedImage}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := launch("docker", tc.args...)
			got := rules(r)
			sort.Strings(got)
			sort.Strings(tc.rules)
			if r.Complete != tc.complete || !reflect.DeepEqual(got, tc.rules) {
				t.Fatalf("expected complete=%v rules=%v; got %+v", tc.complete, tc.rules, r)
			}
		})
	}
}

func TestWindowsDriveRoots(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--mount", "type=bind,source=C:/,target=C:/host", pinnedImage},
		{"run", "-v", `C:\:C:\host`, pinnedImage},
		{"run", "-v", "C:/workspace/..:C:/host", pinnedImage},
	} {
		r := launch("docker", args...)
		if !r.Complete || !reflect.DeepEqual(rules(r), []string{"sensitive-mount"}) {
			t.Fatalf("drive root missed: %+v", r)
		}
	}
}

func TestDynamicNamespacesAreUnassessed(t *testing.T) {
	for _, option := range []string{"--network=${NETWORK}", "--pid=$PID_MODE", "--ipc=${env:IPC_MODE}"} {
		r := launch("docker", "run", option, pinnedImage)
		if r.Complete {
			t.Fatalf("dynamic namespace reported complete: %+v", r)
		}
	}
}

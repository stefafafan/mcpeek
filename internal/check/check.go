package check

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

type Suppression struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
}
type Finding struct {
	Rule        string       `json:"rule"`
	Severity    string       `json:"severity"`
	Server      string       `json:"server"`
	Path        string       `json:"path"`
	Message     string       `json:"message"`
	Suppression *Suppression `json:"suppression,omitempty"`
}
type Diagnostic struct {
	Code    string `json:"code"`
	Server  string `json:"server,omitempty"`
	Path    string `json:"path"`
	Message string `json:"message"`
}
type Result struct {
	File        string       `json:"file"`
	Complete    bool         `json:"complete"`
	Findings    []Finding    `json:"findings"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func NewResult(file string) Result {
	return Result{File: file, Complete: true, Findings: []Finding{}, Diagnostics: []Diagnostic{}}
}
func (r *Result) Problem(path, server, code, message string) {
	r.Complete = false
	r.Diagnostics = append(r.Diagnostics, Diagnostic{code, server, path, message})
}
func Scan(data []byte, file string) Result {
	r := NewResult(file)
	var root map[string]json.RawMessage
	if DecodeJSON(data, &root) != nil || root == nil {
		r.Problem("$", "", "input-error", "input must be an unambiguous JSON object")
		return r
	}
	var servers map[string]json.RawMessage
	if json.Unmarshal(root["mcpServers"], &servers) != nil || servers == nil {
		r.Problem("$.mcpServers", "", "unassessed", "expected an mcpServers object")
		return r
	}
	for _, name := range sortedKeys(servers) {
		r.server(name, servers[name])
	}
	return r
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func field(base, key string) string {
	if identifier.MatchString(key) {
		return base + "." + key
	}
	b, _ := json.Marshal(key)
	return base + "[" + string(b) + "]"
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var Severities = map[string]string{"secret-literal": "warning", "package-unpinned": "warning", "image-unpinned": "warning", "docker-privileged": "error", "docker-socket": "error", "sensitive-mount": "warning", "host-namespace": "warning", "remote-http": "warning"}

func (r *Result) finding(server, path, rule, message string) {
	r.Findings = append(r.Findings, Finding{Rule: rule, Severity: Severities[rule], Server: server, Path: path, Message: message})
}

func (r *Result) server(name string, raw json.RawMessage) {
	p := field("$.mcpServers", name)
	problem := func(message string) { r.Problem(p, name, "unassessed", message) }
	var s map[string]json.RawMessage
	if json.Unmarshal(raw, &s) != nil || s == nil {
		problem("server must be an object")
		return
	}
	for _, key := range sortedKeys(s) {
		switch key {
		case "command", "args", "env", "url", "headers", "type":
		default:
			problem("unsupported server field")
		}
	}
	for _, key := range []string{"env", "headers"} {
		if raw, ok := s[key]; ok {
			var entries map[string]any
			if json.Unmarshal(raw, &entries) != nil || entries == nil {
				problem("credential map must contain strings")
				continue
			}
			for _, k := range sortedKeys(entries) {
				v, ok := entries[k].(string)
				if !ok {
					problem("credential map must contain strings")
					continue
				}
				r.credential(name, field(field(p, key), k), k, v)
			}
		}
	}
	getString := func(key string) (string, bool) {
		raw, ok := s[key]
		if !ok {
			return "", false
		}
		var v any
		if json.Unmarshal(raw, &v) != nil {
			return "", false
		}
		str, ok := v.(string)
		return str, ok
	}
	command, hasCommand := getString("command")
	endpoint, hasURL := getString("url")
	typ, validType := getString("type")
	if _, exists := s["type"]; exists && (!validType || (typ != "stdio" && typ != "http" && typ != "sse" && typ != "streamable-http")) {
		problem("unsupported transport type")
	}
	if hasURL && !hasCommand && s["command"] == nil {
		if (typ != "" && typ != "http" && typ != "sse" && typ != "streamable-http") || s["args"] != nil {
			problem("remote transport has incompatible fields")
		}
		r.remote(name, field(p, "url"), endpoint)
		return
	}
	if !hasCommand || strings.TrimSpace(command) == "" || s["url"] != nil {
		problem("expected exactly one command or URL")
		return
	}
	if typ != "" && typ != "stdio" {
		problem("command transport must be stdio")
	}
	if s["headers"] != nil {
		problem("headers on command transports are unsupported")
	}
	var args []string
	if raw, ok := s["args"]; ok {
		var values []any
		if json.Unmarshal(raw, &values) != nil || values == nil {
			problem("args must be an array of strings")
			return
		}
		for _, v := range values {
			str, ok := v.(string)
			if !ok {
				problem("args must be an array of strings")
				return
			}
			args = append(args, str)
		}
	}
	switch path.Base(strings.ReplaceAll(command, `\`, "/")) {
	case "npx", "npx.cmd":
		r.packages(name, field(p, "args"), args, "npx")
		return
	case "uvx", "uvx.exe":
		r.packages(name, field(p, "args"), args, "uvx")
		return
	case "docker", "docker.exe":
		r.docker(name, field(p, "args"), args)
		return
	}
	problem("unsupported command or launch syntax")
}

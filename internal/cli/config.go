package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/stefafafan/mcpeek/internal/check"
)

type exception struct {
	Rule   string `json:"rule"`
	File   string `json:"file"`
	Server string `json:"server"`
	Reason string `json:"reason"`
	source string
}

func loadExceptions(config string, overrides []string) ([]exception, error) {
	invalid := errors.New("invalid exception config; expected known rule, file, server, and nonempty reason")
	var result []exception
	for _, override := range overrides {
		rule, server, ok := strings.Cut(override, ":")
		if !ok || check.Severities[rule] == "" || strings.TrimSpace(server) == "" {
			return nil, errors.New("invalid --ignore; expected known RULE:SERVER")
		}
		result = append(result, exception{Rule: rule, Server: server, Reason: "command-line override", source: "command-line"})
	}
	if config == "" {
		return result, nil
	}
	data, err := os.ReadFile(config)
	if err != nil {
		return nil, errors.New("cannot read exception config")
	}
	data, err = stripComments(data)
	if err != nil {
		return nil, invalid
	}
	var root map[string]json.RawMessage
	if check.DecodeJSON(data, &root) != nil || root == nil {
		return nil, invalid
	}
	for key := range root {
		if key != "ignore" {
			return nil, invalid
		}
	}
	raw, ok := root["ignore"]
	if !ok {
		return result, nil
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || entries == nil {
		return nil, invalid
	}
	configPath, err := filepath.Abs(config)
	if err != nil {
		return nil, errors.New("cannot resolve exception config path")
	}
	for _, entry := range entries {
		if len(entry) != 4 {
			return nil, invalid
		}
		var ex exception
		for key, target := range map[string]*string{"rule": &ex.Rule, "file": &ex.File, "server": &ex.Server, "reason": &ex.Reason} {
			var value any
			if json.Unmarshal(entry[key], &value) != nil {
				return nil, invalid
			}
			str, ok := value.(string)
			if !ok || strings.TrimSpace(str) == "" {
				return nil, invalid
			}
			*target = str
		}
		if check.Severities[ex.Rule] == "" {
			return nil, invalid
		}
		if !filepath.IsAbs(ex.File) {
			ex.File = filepath.Join(filepath.Dir(configPath), ex.File)
		}
		ex.File = filepath.Clean(ex.File)
		ex.source = "config"
		result = append(result, ex)
	}
	return result, nil
}

func suppress(result *check.Result, exceptions []exception) error {
	if len(exceptions) == 0 {
		return nil
	}
	file := ""
	if result.File != "-" {
		var err error
		file, err = filepath.Abs(result.File)
		if err != nil {
			return err
		}
	}
	for i := range result.Findings {
		finding := &result.Findings[i]
		for _, ex := range exceptions {
			if finding.Rule == ex.Rule && finding.Server == ex.Server && (ex.source == "command-line" || (file != "" && file == ex.File)) {
				finding.Suppression = &check.Suppression{Source: ex.source, Reason: ex.Reason}
				break
			}
		}
	}
	return nil
}

// Replace comments with whitespace, preserving strings and token boundaries.
// encoding/json handles the JSON grammar and rejects trailing commas afterward.
func stripComments(data []byte) ([]byte, error) {
	out := append([]byte(nil), data...)
	inString, escaped := false, false
	for i := 0; i < len(data); i++ {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch data[i] {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		if data[i] == '"' {
			inString = true
			continue
		}
		if data[i] != '/' || i+1 >= len(data) {
			continue
		}
		switch data[i+1] {
		case '/':
			out[i] = ' '
			i++
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				out[i] = ' '
				i++
			}
			i--
		case '*':
			out[i] = ' '
			out[i+1] = ' '
			i += 2
			closed := false
			for i < len(data) {
				if data[i] == '*' && i+1 < len(data) && data[i+1] == '/' {
					out[i] = ' '
					out[i+1] = ' '
					i++
					closed = true
					break
				}
				if data[i] != '\n' && data[i] != '\r' {
					out[i] = ' '
				}
				i++
			}
			if !closed {
				return nil, errors.New("unterminated comment")
			}
		}
	}
	return out, nil
}

package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeJSON rejects duplicate object keys before decoding into the target type.
// Errors are intentionally value-free because the input can contain credentials.
func DecodeJSON(data []byte, target any) error {
	invalid := errors.New("invalid or ambiguous JSON")
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 100 {
			return invalid
		}
		t, err := d.Token()
		if err != nil {
			return invalid
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return invalid
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return invalid
				}
				seen[key] = true
				if value(depth+1) != nil {
					return invalid
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return invalid
			}
		case '[':
			for d.More() {
				if value(depth+1) != nil {
					return invalid
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return invalid
			}
		default:
			return invalid
		}
		return nil
	}
	if value(0) != nil {
		return invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid
	}
	if json.Unmarshal(data, target) != nil {
		return invalid
	}
	return nil
}

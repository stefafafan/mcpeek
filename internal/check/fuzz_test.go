package check

import (
	"bytes"
	"reflect"
	"testing"
)

func FuzzScan(f *testing.F) {
	for _, seed := range []string{`{}`, `{"mcpServers":{}}`, `{"mcpServers":{"a":{"url":"http://example.com"}}}`, `{"mcpServers":{"a":{"command":"docker","args":["run","-v","${env:HOME}:/data","mcp"]}}}`, `{"mcpServers":{"a":{"env":{"TOKEN":"secret"},"command":"npx","args":["package@1.2.3"]}}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		before := append([]byte(nil), data...)
		first := Scan(data, "f")
		if !bytes.Equal(data, before) {
			t.Fatal("scan mutated its input")
		}
		if !reflect.DeepEqual(first, Scan(data, "f")) {
			t.Fatal("scan is nondeterministic")
		}
		if first.Complete != (len(first.Diagnostics) == 0) {
			t.Fatal("completeness disagrees with diagnostics")
		}
	})
}

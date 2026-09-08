package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type brokenIO struct{}

func (brokenIO) Read([]byte) (int, error)  { return 0, errors.New("private reader details") }
func (brokenIO) Write([]byte) (int, error) { return 0, errors.New("private writer details") }

func TestIOFailures(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := Run([]string{"--format=json", "-"}, brokenIO{}, &out, &stderr, "dev"); code != 2 || strings.Contains(out.String()+stderr.String(), "private reader details") {
		t.Fatalf("bad read error: %d %s %s", code, &out, &stderr)
	}
	for _, args := range [][]string{{"--help"}, {"--version"}, {"--format=json", "-"}, {"-"}} {
		if code := Run(args, strings.NewReader(remoteInput), brokenIO{}, &stderr, "dev"); code != 2 {
			t.Fatalf("write failure exit %d", code)
		}
	}
	if code := Run([]string{"-"}, strings.NewReader(`{`), &out, brokenIO{}, "dev"); code != 2 {
		t.Fatalf("stderr failure exit %d", code)
	}
}

func FuzzComments(f *testing.F) {
	for _, s := range []string{`{"ignore":[]}`, "// comment\n{}", `{/* comment */}`, `{"reason":"escaped\"//value"}`, `/**/null`, "/*"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		before := append([]byte(nil), data...)
		result, err := stripComments(data)
		if !bytes.Equal(before, data) {
			t.Fatal("comment parser mutated input")
		}
		if err == nil && len(result) != len(data) {
			t.Fatal("comment parser changed offsets")
		}
	})
}

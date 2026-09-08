package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/stefafafan/mcpeek/internal/check"
)

const usage = `mcpeek [options] FILE

  --format text|json       Output format (default text)
  --config PATH            Explicit JSONC exception file
  --ignore RULE:SERVER     Suppress a rule for one server (repeatable)
  --fail-on warning|error  Failure threshold (default warning)
  -h, --help               Print usage
  --version                Print version

Use - for standard input. Options must precede FILE.
`

type stringsFlag []string

func (s *stringsFlag) String() string     { return "" }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	fs := flag.NewFlagSet("mcpeek", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "text", "")
	config := fs.String("config", "", "")
	threshold := fs.String("fail-on", "warning", "")
	help := fs.Bool("help", false, "")
	shortHelp := fs.Bool("h", false, "")
	showVersion := fs.Bool("version", false, "")
	var ignores stringsFlag
	fs.Var(&ignores, "ignore", "")
	if fs.Parse(args) != nil {
		_, _ = fmt.Fprintln(stderr, "mcpeek: invalid arguments; use --help")
		return 2
	}
	if *help || *shortHelp {
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 2
		}
		return 0
	}
	if *showVersion {
		if _, err := fmt.Fprintln(stdout, version); err != nil {
			return 2
		}
		return 0
	}
	if fs.NArg() != 1 || (*format != "text" && *format != "json") || (*threshold != "warning" && *threshold != "error") {
		_, _ = fmt.Fprintln(stderr, "mcpeek: invalid arguments; use --help")
		return 2
	}
	file := fs.Arg(0)
	exceptions, configErr := loadExceptions(*config, ignores)
	if configErr != nil {
		result := check.NewResult(file)
		result.Problem("$", "", "config-error", configErr.Error())
		return render(result, *format, *threshold, stdout, stderr)
	}
	var data []byte
	var err error
	if file == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	result := check.NewResult(file)
	if err != nil {
		result.Problem("$", "", "input-error", "cannot read input")
	} else {
		result = check.Scan(data, file)
	}
	if err := suppress(&result, exceptions); err != nil {
		result.Problem("$", "", "config-error", "cannot resolve input path for exceptions")
	}
	return render(result, *format, *threshold, stdout, stderr)
}

func render(result check.Result, format, threshold string, stdout, stderr io.Writer) int {
	code := 0
	for _, f := range result.Findings {
		if f.Suppression == nil && (threshold == "warning" || f.Severity == "error") {
			code = 1
		}
	}
	if !result.Complete {
		code = 2
	}
	if format == "json" {
		if json.NewEncoder(stdout).Encode(result) != nil {
			_, _ = fmt.Fprintln(stderr, "mcpeek: cannot write output")
			return 2
		}
	} else {
		for _, f := range result.Findings {
			if f.Suppression == nil {
				if _, err := fmt.Fprintf(stdout, "%s:%s: %s %s: %s\n", display(result.File), f.Path, f.Severity, f.Rule, f.Message); err != nil {
					return 2
				}
			}
		}
		for _, d := range result.Diagnostics {
			if _, err := fmt.Fprintf(stderr, "%s:%s: error %s: %s\n", display(result.File), d.Path, d.Code, d.Message); err != nil {
				return 2
			}
		}
	}
	return code
}

func display(s string) string { b, _ := json.Marshal(s); return string(b[1 : len(b)-1]) }

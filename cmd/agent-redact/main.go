// Command agent-redact removes secrets from text or JSON read from files or standard input.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	redact "github.com/baditaflorin/agent-redact"
)

const version = "0.1.0"

const (
	exitOK    = 0
	exitError = 1
	exitFound = 3 // -check: something would have been redacted
)

const maxLineBytes = 8 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agent-redact", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: agent-redact [-mode text|json|ndjson] [-check] [-report] [FILE...]")
		fmt.Fprintln(fs.Output(), "       reads standard input when no FILE is given; writes the redacted text to standard output")
		fs.PrintDefaults()
	}
	mode := fs.String("mode", "text", "text: whole input as text; json: one JSON document; ndjson: one JSON document per line (a line that is not JSON is redacted as text)")
	check := fs.Bool("check", false, "write nothing; exit 3 when anything would have been redacted")
	report := fs.Bool("report", false, "print the per-rule counts as JSON on standard error")
	list := fs.Bool("list", false, "print the rule names and exit")
	maxBytes := fs.Int64("maxBytes", 64<<20, "largest input read in text and json mode, per file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	r := redact.Default()
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if *list {
		for _, n := range r.RuleNames() {
			fmt.Fprintln(stdout, n)
		}
		return exitOK
	}
	if *mode != "text" && *mode != "json" && *mode != "ndjson" {
		fmt.Fprintf(stderr, "agent-redact: unknown -mode %q\n", *mode)
		return exitError
	}

	out := stdout
	if *check {
		out = io.Discard
	}
	var hits redact.Hits
	fallback := 0
	process := func(in io.Reader, name string) error {
		switch *mode {
		case "ndjson":
			h, fb, err := ndjson(r, in, out)
			hits = hits.Merge(h)
			fallback += fb
			return err
		default:
			b, err := io.ReadAll(io.LimitReader(in, *maxBytes+1))
			if err != nil {
				return err
			}
			if int64(len(b)) > *maxBytes {
				return fmt.Errorf("%s is larger than -maxBytes (%d)", name, *maxBytes)
			}
			if *mode == "json" {
				red, h, err := r.JSON(b)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				hits = hits.Merge(h)
				_, err = out.Write(append(red, '\n'))
				return err
			}
			red, h := r.String(string(b))
			hits = hits.Merge(h)
			_, err = io.WriteString(out, red)
			return err
		}
	}

	files := fs.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	for _, f := range files {
		var err error
		if f == "-" {
			err = process(stdin, "standard input")
		} else {
			err = processFile(f, process)
		}
		if err != nil {
			fmt.Fprintf(stderr, "agent-redact: %v\n", err)
			return exitError
		}
	}
	if *report {
		counts := map[string]int(hits)
		if counts == nil {
			counts = map[string]int{}
		}
		b, _ := json.Marshal(map[string]any{"redactions": counts, "total": hits.Total(), "fallback_lines": fallback})
		fmt.Fprintln(stderr, string(b))
	}
	if *check && hits.Total() > 0 {
		return exitFound
	}
	return exitOK
}

func processFile(path string, process func(io.Reader, string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return process(f, path)
}

// ndjson redacts one line at a time. A line that is not valid JSON is redacted as text rather than
// dropped or passed through, and counted in the second result.
func ndjson(r *redact.Redactor, in io.Reader, out io.Writer) (redact.Hits, int, error) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var hits redact.Hits
	fallback := 0
	w := bufio.NewWriter(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		red, h, err := r.JSON(line)
		if err != nil {
			s, th := r.String(string(line))
			red, h = []byte(s), th
			fallback++
		}
		hits = hits.Merge(h)
		w.Write(red)
		w.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return hits, fallback, err
	}
	return hits, fallback, w.Flush()
}

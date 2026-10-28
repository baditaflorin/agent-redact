package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/baditaflorin/agent-redact/canary"
)

func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func fake(t *testing.T, rule string) canary.Fake {
	t.Helper()
	for _, f := range canary.Fakes() {
		if f.Rule == rule {
			return f
		}
	}
	t.Fatalf("no canary for %s", rule)
	return canary.Fake{}
}

func TestVersionMatchesTheVersionFile(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != version {
		t.Fatalf("VERSION file %q, binary %q", b, version)
	}
	if code, out, _ := runCLI(t, "", "-version"); code != 0 || strings.TrimSpace(out) != version {
		t.Fatalf("-version: %d %q", code, out)
	}
}

func TestTextFromStdin(t *testing.T) {
	f := fake(t, "xai-key")
	code, out, _ := runCLI(t, "before "+f.Secret+" after\nsecond line\n")
	if code != 0 || strings.Contains(out, f.Secret) || out != "before [REDACTED:xai-key] after\nsecond line\n" {
		t.Fatalf("%d %q", code, out)
	}
}

func TestCheckModeWritesNothingAndSaysSoByExitCode(t *testing.T) {
	f := fake(t, "stripe-key")
	code, out, _ := runCLI(t, "x "+f.Secret, "-check")
	if code != exitFound || out != "" {
		t.Fatalf("dirty input: %d %q", code, out)
	}
	code, out, _ = runCLI(t, "nothing to see", "-check")
	if code != exitOK || out != "" {
		t.Fatalf("clean input: %d %q", code, out)
	}
}

func TestReportIsJSONOnStderr(t *testing.T) {
	f := fake(t, "xai-key")
	_, out, errOut := runCLI(t, f.Secret+"\n"+f.Secret, "-report")
	if strings.Contains(out, f.Secret) {
		t.Fatal("secret on stdout")
	}
	if !strings.Contains(errOut, `"total":2`) || !strings.Contains(errOut, `"xai-key":2`) {
		t.Fatalf("report %q", errOut)
	}
}

func TestJSONModeNeverEchoesInputItCannotParse(t *testing.T) {
	f := fake(t, "xai-key")
	code, out, errOut := runCLI(t, "{not json "+f.Secret, "-mode", "json")
	if code != exitError || out != "" || strings.Contains(errOut, f.Secret) {
		t.Fatalf("%d out %q err %q", code, out, errOut)
	}
}

func TestNDJSONFallsBackToTextForABadLine(t *testing.T) {
	f := fake(t, "xai-key")
	in := `{"a":"` + f.Secret + `"}` + "\n" + "plain " + f.Secret + "\n\n" + `{"b":2}` + "\n"
	code, out, errOut := runCLI(t, in, "-mode", "ndjson", "-report")
	if code != 0 || strings.Contains(out, f.Secret) {
		t.Fatalf("%d %q", code, out)
	}
	want := `{"a":"[REDACTED:xai-key]"}` + "\n" + "plain [REDACTED:xai-key]\n" + `{"b":2}` + "\n"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
	if !strings.Contains(errOut, `"fallback_lines":1`) {
		t.Fatalf("report %q", errOut)
	}
}

func TestFilesAreRedactedOneByOne(t *testing.T) {
	f := fake(t, "xai-key")
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	if err := os.WriteFile(a, []byte("a "+f.Secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "", a, b)
	if code != 0 || out != "a [REDACTED:xai-key]\nb clean\n" {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errOut := runCLI(t, "", filepath.Join(dir, "missing")); code != exitError || errOut == "" {
		t.Fatalf("a missing file must fail: %d %q", code, errOut)
	}
}

func TestMaxBytes(t *testing.T) {
	code, out, errOut := runCLI(t, strings.Repeat("a", 100), "-maxBytes", "10")
	if code != exitError || out != "" || !strings.Contains(errOut, "-maxBytes") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
}

func TestListAndBadMode(t *testing.T) {
	code, out, _ := runCLI(t, "", "-list")
	if code != 0 || !strings.Contains(out, "anthropic-key\n") || !strings.Contains(out, "key-name\n") {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, errOut := runCLI(t, "", "-mode", "yaml"); code != exitError || !strings.Contains(errOut, "unknown -mode") {
		t.Fatalf("%d %q", code, errOut)
	}
}

// a tool call stored as a document inside a string: both JSON modes read it, and text mode finds its escaped quotes
func TestDocumentsHeldInStringsAndEscapedQuotes(t *testing.T) {
	f := fake(t, "env-secret") // DB_PASSWORD=...: unquoted, so the quoted one is picked by its text
	for _, c := range canary.Fakes() {
		if strings.Contains(c.Text, "STRIPE_WEBHOOK_SECRET") {
			f = c
		}
	}
	inner := `{"cmd":"` + strings.NewReplacer(`"`, `\"`).Replace(f.Text) + `"}`
	record := `{"arguments":"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(inner) + `"}`
	for _, mode := range []string{"json", "ndjson"} {
		code, out, _ := runCLI(t, record+"\n", "-mode", mode)
		if code != 0 || strings.Contains(out, f.Secret) || !strings.Contains(out, "[REDACTED:env-secret]") {
			t.Errorf("-mode %s: %d %q", mode, code, out)
		}
	}
	code, out, _ := runCLI(t, inner, "-mode", "text")
	if code != 0 || strings.Contains(out, f.Secret) || !strings.Contains(out, "[REDACTED:env-secret]") {
		t.Errorf("-mode text: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, record, "-mode", "json", "-check"); code != exitFound {
		t.Errorf("-check on a nested record exits %d, want %d", code, exitFound)
	}
}

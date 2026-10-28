package redact_test

import (
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
	"github.com/baditaflorin/agent-redact/canary"
)

func TestJSONKeepsOrderNumbersAndShape(t *testing.T) {
	r := redact.Default()
	in := `{ "z": 1, "a": "x", "m": {"b": [1, "two", null, true, 1e3, 1.50, -0.0]},  "e": {}, "l": [] }`
	want := `{"z":1,"a":"x","m":{"b":[1,"two",null,true,1e3,1.50,-0.0]},"e":{},"l":[]}`
	out, hits, err := r.JSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != want || hits != nil {
		t.Fatalf("got  %s\nwant %s\nhits %v", out, want, hits)
	}
}

func TestJSONTopLevelValues(t *testing.T) {
	r := redact.Default()
	for _, in := range []string{`123`, `null`, `true`, `"plain"`, `[]`, `{}`, `[[],[[]]]`} {
		out, _, err := r.JSON([]byte(in))
		if err != nil || string(out) != in {
			t.Errorf("%s -> %s (%v)", in, out, err)
		}
	}
	var key canary.Fake
	for _, f := range canary.Fakes() {
		if f.Rule == "xai-key" {
			key = f
		}
	}
	out, hits, err := r.JSON([]byte(`"` + key.Secret + `"`))
	if err != nil || strings.Contains(string(out), key.Secret) || hits["xai-key"] != 1 {
		t.Errorf("a top-level string secret: %s %v %v", out, hits, err)
	}
}

func TestJSONKeyNames(t *testing.T) {
	r := redact.Default()
	in := `{"password":"hunter2hunter2","input_tokens":5,"headers":{"Authorization":"Bearer abcdefghijkl","apiKey":"k1"},` +
		`"tokens":["a","b"],"tokenizer":"gpt","session_token":"s3","note":"fine","empty_password":""}`
	out, hits, err := r.JSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leaked := range []string{"hunter2hunter2", "abcdefghijkl", `"k1"`, `"s3"`} {
		if strings.Contains(s, leaked) {
			t.Errorf("%q survived: %s", leaked, s)
		}
	}
	for _, kept := range []string{`"input_tokens":5`, `"tokens":["a","b"]`, `"tokenizer":"gpt"`, `"note":"fine"`, `"empty_password":""`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%q was changed: %s", kept, s)
		}
	}
	if hits[redact.KeyNameRuleName] != 4 {
		t.Errorf("hits = %v, want four key-name redactions (password, Authorization, apiKey, session_token)", hits)
	}
}

func TestJSONStringHoldingJSONText(t *testing.T) {
	r := redact.Default()
	in := `{"content":"{\"password\": \"hunter2hunter2\", \"user\": \"ann\"}"}`
	out, hits, err := r.JSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2hunter2") || hits["env-secret"] != 1 {
		t.Fatalf("%s %v", out, hits)
	}
}

func TestJSONDoesNotEscapeHTML(t *testing.T) {
	r := redact.Default()
	out, _, err := r.JSON([]byte(`{"cmd":"a && b < c > d"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"cmd":"a && b < c > d"}` {
		t.Fatalf("%s", out)
	}
}

func TestJSONRejectsWhatIsNotOneDocument(t *testing.T) {
	r := redact.Default()
	for _, in := range []string{"", "   ", "{", `{"a":`, `[1,2`, `{"a":1} {"b":2}`, `1 2`, "not json", `{"a" 1}`} {
		out, hits, err := r.JSON([]byte(in))
		if err == nil || out != nil || hits != nil {
			t.Errorf("%q: out %q hits %v err %v", in, out, hits, err)
		}
	}
}

func TestJSONKeepsEveryCanaryOutOfTheOutput(t *testing.T) {
	r := redact.Default()
	for _, f := range canary.Fakes() {
		doc := `{"event":{"detail":[{"text":` + quote(f.Text) + `}]}}`
		if f.JSON {
			doc = `{"event":` + f.Text + `}`
		}
		out, _, err := r.JSON([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", f.Rule, err)
		}
		if strings.Contains(string(out), f.Secret) {
			t.Errorf("%s: secret survived inside nested JSON: %s", f.Rule, out)
		}
	}
}

// quote is a JSON string literal for s, for building documents in tests.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

package redact_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
	"github.com/baditaflorin/agent-redact/canary"
)

// Text that has been through JSON escaping (a shell command that shows its own quotes, a document stored as text,
// a document inside a document) spells a quote as \" and, a level deeper, as \\\". The rules read those like
// plain quotes. Raw strings below: every backslash is a backslash in the text.

var escapedQuoteLeaks = []struct {
	name   string
	text   string
	secret string
	want   string // the whole output, when the structure around the secret matters; "" to skip
}{
	{"shell string", `echo "STRIPE_WEBHOOK_SECRET=\"my long secret phrase\"" >> .env`, "my long secret phrase",
		`echo "STRIPE_WEBHOOK_SECRET=\"[REDACTED:env-secret]\"" >> .env`},
	{"name and value", `APP_TOKEN=\"a value with spaces\"`, "a value with spaces", `APP_TOKEN=\"[REDACTED:env-secret]\"`},
	{"one word value", `APP_TOKEN=\"abcdefgh\"`, "abcdefgh", `APP_TOKEN=\"[REDACTED:env-secret]\"`},
	{"json pair", `{\"api_key\": \"hunter2hunter2\"}`, "hunter2hunter2", `{\"api_key\": \"[REDACTED:env-secret]\"}`},
	{"json pair, compact", `{\"user\":\"ann\",\"access_token\":\"abcdefghijklmnop\"}`, "abcdefghijklmnop",
		`{\"user\":\"ann\",\"access_token\":\"[REDACTED:env-secret]\"}`},
	{"two levels", `{\\\"api_key\\\": \\\"hunter2hunter2\\\"}`, "hunter2hunter2", `{\\\"api_key\\\": \\\"[REDACTED:env-secret]\\\"}`},
	{"four levels", `{\\\\\\\"api_key\\\\\\\": \\\\\\\"hunter2hunter2\\\\\\\"}`, "hunter2hunter2",
		`{\\\\\\\"api_key\\\\\\\": \\\\\\\"[REDACTED:env-secret]\\\\\\\"}`},
	{"single quotes", `DB_PASSWORD=\'my long secret phrase\'`, "my long secret phrase", `DB_PASSWORD=\'[REDACTED:env-secret]\'`},
	{"single quoted key", `{\'password\': \'hunter2hunter2\'}`, "hunter2hunter2", `{\'password\': \'[REDACTED:env-secret]\'}`},
	{"mixed", `{\"db_password\": \'hunter2hunter2\'}`, "hunter2hunter2", `{\"db_password\": \'[REDACTED:env-secret]\'}`},
	{"escaped open, plain close", `SECRET_TOKEN=\"hunter2hunter2"`, "hunter2hunter2", ""},
	{"plain open, escaped close", `SECRET_TOKEN="hunter2hunter2\"`, "hunter2hunter2", ""},
	{"unquoted key, escaped value", `api_key: \"hunter2hunter2\"`, "hunter2hunter2", `api_key: \"[REDACTED:env-secret]\"`},
	{"escaped key, bare value", `{\"api_key\": hunter2hunter2}`, "hunter2hunter2", ""},
	{"authorization header", `{\"Authorization\": \"Bearer Tk9xR3pWb1Tk9xR3pWb1\"}`, "Tk9xR3pWb1Tk9xR3pWb1",
		`{\"Authorization\": \"Bearer [REDACTED:auth-header]\"}`},
	{"authorization header, two levels", `{\\\"Authorization\\\": \\\"Bearer Tk9xR3pWb1Tk9xR3pWb1\\\"}`, "Tk9xR3pWb1Tk9xR3pWb1",
		`{\\\"Authorization\\\": \\\"Bearer [REDACTED:auth-header]\\\"}`},
	{"authorization flag", `curl -H \"Authorization: Bearer Tk9xR3pWb1Tk9xR3pWb1\" https://example.invalid`, "Tk9xR3pWb1Tk9xR3pWb1",
		`curl -H \"Authorization: Bearer [REDACTED:auth-header]\" https://example.invalid`},
	{"flag with an escaped quote", `mysql --password \"hunter2flag99\" -h db`, "hunter2flag99", ""},
	{"flag with equals", `mysql --password=\"hunter2flag99\" -h db`, "hunter2flag99", `mysql --password=\"[REDACTED:env-secret]\" -h db`},
	{"newline in the way", "export MY_SECRET=\\\"hunter2hunter2\\\"\nnext", "hunter2hunter2", "export MY_SECRET=\\\"[REDACTED:env-secret]\\\"\nnext"},
	{"two on one line", `A_TOKEN=\"first secret one\" B_TOKEN=\"second secret two\"`, "second secret two",
		`A_TOKEN=\"[REDACTED:env-secret]\" B_TOKEN=\"[REDACTED:env-secret]\"`},
	{"longest quoted value", `K_TOKEN=\"` + strings.Repeat("a", 300) + `\"`, strings.Repeat("a", 300), `K_TOKEN=\"[REDACTED:env-secret]\"`},
}

func TestEscapedQuotesInPlainTextAreRedacted(t *testing.T) {
	r := redact.Default()
	for _, c := range escapedQuoteLeaks {
		out, hits := r.String(c.text)
		if strings.Contains(out, c.secret) || hits.Total() == 0 {
			t.Errorf("%s: the secret survived\n in  %s\n out %s %v", c.name, c.text, out, hits)
			continue
		}
		if c.want != "" && out != c.want {
			t.Errorf("%s:\n in   %s\n out  %s\n want %s", c.name, c.text, out, c.want)
		}
		if again, h := r.String(out); again != out || h.Total() != 0 {
			t.Errorf("%s: not idempotent\n once  %s\n twice %s %v", c.name, out, again, h)
		}
	}
}

// A quoted value is at least 4 characters and has no upper limit (the 300 of v0.1.0 to v0.1.2 let a long credential
// through); plain or escaped, the backslashes of an escaped quote are not part of it.
func TestQuotedValueLengthLimits(t *testing.T) {
	r := redact.Default()
	for _, q := range []struct{ name, open, close string }{
		{"plain", `"`, `"`}, {"single", `'`, `'`}, {"escaped", `\"`, `\"`}, {"escaped single", `\'`, `\'`},
		{"two levels", `\\\"`, `\\\"`}, {"escaped open, plain close", `\"`, `"`}, {"plain open, escaped close", `"`, `\"`},
	} {
		for _, c := range []struct {
			n    int
			want bool
		}{{3, false}, {4, true}, {5, true}, {300, true}, {301, true}, {5000, true}} {
			in := "K_TOKEN=" + q.open + strings.Repeat("v", c.n) + q.close + " rest"
			out, hits := r.String(in)
			if redacted := hits.Total() == 1 && strings.Contains(out, "[REDACTED:env-secret]"); redacted != c.want {
				t.Errorf("%s quotes, %d characters: redacted=%v, want %v\n in  %s\n out %s", q.name, c.n, redacted, c.want, in, out)
			}
			if c.want && strings.Contains(out, "vvvv") || !c.want && out != in {
				t.Errorf("%s quotes, %d characters: wrong output\n in  %s\n out %s", q.name, c.n, in, out)
			}
		}
	}
}

func TestEscapedQuotesInPlainTextThatIsNotASecretStayAsTheyAre(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		`APP_TOKEN=\"ab\"`,                                   // under 4 characters
		`{\"input_tokens\": \"123456789\"}`,                  // the name does not end in a sensitive word
		`{\"max_tokens\": \"4096\", \"tokenizer\": \"gpt\"}`, //
		`TOKEN_LIMIT=\"1000000\"`,
		`{\"note\": \"set the token in the form\"}`,
		`the pattern is password\"[=:]\"`,
		`re.compile(\"api_key\\\\s*=\\\\s*(\\\\S+)\")`,
		`--token-limit \"100000\"`,
		`path C:\\temp\\token`,
		`\"\"`,
		`\\\\\\`,
	} {
		out, hits := r.String(s)
		if out != s || hits.Total() != 0 {
			t.Errorf("changed %q to %q (%v)", s, out, hits)
		}
	}
}

// A canary line that is stored as text in a document (every quote escaped, once or twice) must not leak, and the
// document must still be valid JSON afterwards: the rules keep the backslashes that belong to a closing quote.
func TestCanariesInDocumentsStoredAsText(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		for _, sh := range []struct {
			name string
			doc  string
		}{
			{"one level", cmdDoc(f.Text)},
			{"two levels", `{"arguments":` + jstr(cmdDoc(f.Text)) + `}`},
			{"three levels", `{"arguments":` + jstr(`{"input":`+jstr(cmdDoc(f.Text))+`}`) + `}`},
			{"array", `["x",` + jstr(f.Text) + `]`},
		} {
			out, hits := r.String(sh.doc)
			label := fmt.Sprintf("%s/%s#%d", sh.name, f.Rule, i)
			if strings.Contains(out, f.Secret) {
				t.Errorf("%s: the secret survived\n out %s", label, out)
			}
			if hits.Total() == 0 {
				t.Errorf("%s: nothing was redacted", label)
			}
			if !json.Valid([]byte(out)) {
				t.Errorf("%s: the document is no longer valid JSON\n out %s", label, out)
			}
		}
	}
}

// A run of backslashes is the escape of a quote, never a value: an unquoted-value rule that meets one (after a key whose
// quote was escaped several times) leaves it alone, and so does a rule that meets one after it redacted the value.
func TestARunOfBackslashesIsNotAValue(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		`{\\\\\\\"api_key\\\\\\\": \\\\\\\"ab\\\\\\\"}`,
		`{\\\\\\\"api_key\\\\\\\": \\\\\\\\\\"}`,
		`APP_TOKEN=\\\\\\\\\\`,
		`--token \\\\\\\\\\ x`,
	} {
		if out, hits := r.String(s); out != s || hits.Total() != 0 {
			t.Errorf("changed %q to %q (%v)", s, out, hits)
		}
	}
}

// The escaped forms are found in plain text, so String does not need to parse a document to redact it: what a parse would
// add is the key-name rule, a value of 1 to 3 characters under a secret key.
func TestStringOnADocumentMissesOnlyWhatNeedsTheKeyNameRule(t *testing.T) {
	r := redact.Default()
	doc := `{"cookie":"sessionid=abcdef123456","password":"abc","user":"ann"}`
	out, hits := r.String(doc)
	if want := `{"cookie":"[REDACTED:cookie-header]","password":"abc","user":"ann"}`; out != want || hits.Total() != 1 {
		t.Fatalf("String is text rules only: %s %v", out, hits)
	}
	red, h, err := r.JSON([]byte(doc))
	if err != nil || strings.Contains(string(red), "abcdef123456") || strings.Contains(string(red), `"abc"`) || h[redact.KeyNameRuleName] != 2 {
		t.Fatalf("JSON does: %s %v %v", red, h, err)
	}
}

// The value of an unquoted assignment or flag stops before the backslashes that belong to an escaped closing quote
// (but a backslash that is the value's own, with no quote after it, stays inside).
func TestUnquotedValuesKeepTheBackslashOfAnEscapedClosingQuote(t *testing.T) {
	r := redact.Default()
	for _, c := range []struct{ name, in, want string }{
		{"bare, escaped double quote", `echo \"API_KEY=abcdefghijk\"`, `echo \"API_KEY=[REDACTED:env-secret]\"`},
		{"bare, escaped single quote", `echo \'API_KEY=abcdefghijk\'`, `echo \'API_KEY=[REDACTED:env-secret]\'`},
		{"bare, two levels", `echo \\\"API_KEY=abcdefghijk\\\"`, `echo \\\"API_KEY=[REDACTED:env-secret]\\\"`},
		{"bare, in a document kept as text", `{\"cmd\":\"export DB_PASSWORD=hunter2hunter2\"}`, `{\"cmd\":\"export DB_PASSWORD=[REDACTED:env-secret]\"}`},
		{"bare, plain quote after it", `echo "API_KEY=abcdefghijk"`, `echo "API_KEY=[REDACTED:env-secret]"`},
		{"bare, six characters and a backslash", `T_TOKEN=abcde\" x`, `T_TOKEN=[REDACTED:env-secret]\" x`},
		{"bare, the value's own backslash", `PASSWORD=abcdefg\ more`, `PASSWORD=[REDACTED:env-secret] more`},
		{"bare, a backslash and then a quote that is plain", `PASSWORD=abcdefg\\" more`, `PASSWORD=[REDACTED:env-secret]\\" more`},
		{"flag, escaped quotes", `mysql --password \"hunter2flag99\" -h db`, `mysql --password \"[REDACTED:flag-secret]\" -h db`},
		{"flag, escaped quote after a bare value", `mysql --password hunter2flag99\" -h db`, `mysql --password [REDACTED:flag-secret]\" -h db`},
	} {
		out, hits := r.String(c.in)
		if out != c.want || hits.Total() != 1 {
			t.Errorf("%s:\n in   %s\n out  %s %v\n want %s", c.name, c.in, out, hits, c.want)
		}
		if again, h := r.String(out); again != out || h.Total() != 0 {
			t.Errorf("%s: not idempotent\n once  %s\n twice %s %v", c.name, out, again, h)
		}
	}
}

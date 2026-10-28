package redact_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
	"github.com/baditaflorin/agent-redact/canary"
)

// Coding agents record a tool call as a JSON document held inside a JSON string (a Codex function_call has
// "arguments": "{\"cmd\": ...}"). Every quote in there is escaped, so the text rules that look for
// NAME="a value" or "api_key": "v" cannot see them unless JSON() reads the string as JSON again.

// jstr is s as a JSON string literal, the way a record writer would store it.
func jstr(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

func cmdDoc(text string) string { return `{"cmd":` + jstr(text) + `}` }

// nest wraps doc in n more levels of "a document inside a string of a document".
func nest(doc string, n int) string {
	for i := 0; i < n; i++ {
		doc = `{"arguments":` + jstr(doc) + `}`
	}
	return doc
}

var nestedShapes = []struct {
	name  string
	build func(text string) string
}{
	{"arguments", func(t string) string { return `{"arguments":` + jstr(cmdDoc(t)) + `}` }},
	{"one-level-deeper", func(t string) string {
		return `{"arguments":` + jstr(`{"input":`+jstr(cmdDoc(t))+`}`) + `}`
	}},
	{"array-of-strings", func(t string) string {
		return `[` + jstr(cmdDoc(t)) + `,"plain",` + jstr(cmdDoc(t)) + `]`
	}},
	{"array-held-in-string", func(t string) string {
		return `{"arguments":` + jstr(`["sh","-c",`+jstr(t)+`]`) + `}`
	}},
	{"top-level-string", func(t string) string { return jstr(cmdDoc(t)) }},
	{"pretty-printed-inner", func(t string) string {
		return `{"arguments":` + jstr("{\n  \"cmd\": "+jstr(t)+",\n  \"workdir\": \"/src\"\n}\n") + `}`
	}},
	{"event-record", func(t string) string {
		return `{"type":"response_item","payload":{"type":"function_call","name":"shell","arguments":` + jstr(cmdDoc(t)) + `,"call_id":"c1"}}`
	}},
}

// keys the key-name rule does not know: the document is redacted because of what is in it.
var unknownKeys = []string{"arguments", "foo", "raw", "input", "output", "content", "payload", "x", "data", "body", "args", "message", "tokenizer"}

func TestCanarySecretsAreSafeToSearchForRaw(t *testing.T) {
	// the tests look for a Secret in the JSON text of the output: that is exact only while a Secret has nothing a JSON writer escapes
	for _, f := range canary.Fakes() {
		for _, c := range []byte(f.Secret) {
			if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
				t.Fatalf("secret of %s holds a byte that JSON escapes: %q", f.Rule, f.Secret)
			}
		}
	}
}

func checkNested(t *testing.T, r *redact.Redactor, f canary.Fake, label, doc string) {
	t.Helper()
	out, hits, err := r.JSON([]byte(doc))
	if err != nil {
		t.Errorf("%s: %v\n input %s", label, err, doc)
		return
	}
	if strings.Contains(string(out), f.Secret) {
		t.Errorf("%s: the secret of %s survived\n out %s", label, f.Rule, out)
		return
	}
	if !json.Valid(out) {
		t.Errorf("%s: the output is not valid JSON: %s", label, out)
	}
	if hits[f.Rule] == 0 {
		t.Errorf("%s: rule %s did not fire; hits %v\n out %s", label, f.Rule, hits, out)
	}
	if !strings.Contains(string(out), "[REDACTED:"+f.Rule+"]") {
		t.Errorf("%s: no %s placeholder in %s", label, f.Rule, out)
	}
	again, hits2, err := r.JSON(out)
	if err != nil || !bytes.Equal(again, out) || hits2.Total() != 0 {
		t.Errorf("%s: redacting the output again changed it (err %v, hits %v)\n once  %s\n twice %s", label, err, hits2, out, again)
	}
}

func TestJSONRedactsDocumentsHeldInStrings(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		for _, sh := range nestedShapes {
			checkNested(t, r, f, fmt.Sprintf("%s/%s#%d", sh.name, f.Rule, i), sh.build(f.Text))
		}
	}
}

func TestJSONRedactsADocumentUnderAnyUnknownKey(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		for _, key := range unknownKeys {
			checkNested(t, r, f, fmt.Sprintf("key %s/%s#%d", key, f.Rule, i), `{"`+key+`":`+jstr(cmdDoc(f.Text))+`}`)
			checkNested(t, r, f, fmt.Sprintf("deep key %s/%s#%d", key, f.Rule, i),
				`{"a":{"b":[{"`+key+`":`+jstr(cmdDoc(f.Text))+`}]}}`)
		}
	}
}

func TestJSONRedactsDocumentsNestedUpToTheBound(t *testing.T) {
	r := redact.Default()
	for _, f := range canary.Fakes() {
		if f.Rule == "key-name" {
			continue
		}
		for n := 1; n <= 4; n++ {
			checkNested(t, r, f, fmt.Sprintf("%d levels/%s", n, f.Rule), nest(cmdDoc(f.Text), n))
		}
	}
}

// Past the bound a document is plain text to the rules, which read escaped quotes at any depth: every canary is still
// found, and the output is valid JSON. (Every level doubles the backslashes, so 12 levels is already some 400 KB.)
func TestJSONDeepNestingIsBoundedAndStillRedactsQuotedSecrets(t *testing.T) {
	r := redact.Default()
	for _, f := range canary.Fakes() {
		for _, n := range []int{5, 6, 8} {
			out, _, err := r.JSON([]byte(nest(cmdDoc(f.Text), n)))
			if err != nil || !json.Valid(out) {
				t.Fatalf("%d levels/%s: err %v, valid %v", n, f.Rule, err, json.Valid(out))
			}
			if strings.Contains(string(out), f.Secret) {
				t.Errorf("%d levels/%s: the secret survived past the bound", n, f.Rule)
			}
		}
	}
	out, _, err := r.JSON([]byte(nest(cmdDoc(canary.Fakes()[14].Text), 12)))
	if err != nil || !json.Valid(out) {
		t.Fatalf("12 levels: err %v, valid %v", err, json.Valid(out))
	}
}

// The bound is observable with a secret only the key-name rule knows: at the depth JSON follows it is replaced, one
// level further down the document is plain text to the text rules, and the "signing_key" key means nothing to them.
// This test states the limit the README names: change it with maxNesting.
func TestJSONFollowsDocumentsInStringsToExactlyFourLevels(t *testing.T) {
	r := redact.Default()
	for n := 1; n <= 6; n++ {
		doc := `{"signing_key":"abcdef123456","user":"ann"}`
		for i := 1; i < n; i++ {
			doc = `{"arguments":` + jstr(doc) + `}`
		}
		doc = `{"arguments":` + jstr(doc) + `}`
		out, hits, err := r.JSON([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		followed := !strings.Contains(string(out), "abcdef123456")
		if followed != (n <= 4) || (followed && hits[redact.KeyNameRuleName] != 1) {
			t.Errorf("%d levels: followed=%v hits=%v\n out %s", n, followed, hits, out)
		}
	}
}

// JSON white space (space, tab, line feed, carriage return) around the document does not hide it
func TestJSONNestedDocumentMayHaveWhiteSpaceAround(t *testing.T) {
	r := redact.Default()
	for _, ws := range []string{" ", "\t", "\n", "\r", " \r\n\t "} {
		for _, inner := range []string{`{"signing_key":"abcdef123456"}`, `["x",{"signing_key":"abcdef123456"}]`} {
			out, hits, err := r.JSON([]byte(`{"arguments":` + jstr(ws+inner+ws) + `}`))
			if err != nil || strings.Contains(string(out), "abcdef123456") || hits[redact.KeyNameRuleName] != 1 {
				t.Errorf("%q around %s: %s %v %v", ws, inner, out, hits, err)
			}
		}
	}
}

// A private key cut off before its end line takes the rest of the text with it. Read as a document first, that is the
// rest of one string and the document stays valid; read as text first it would cut the document's own closing.
func TestJSONNestedCutOffPrivateKeyKeepsTheDocumentValid(t *testing.T) {
	r := redact.Default()
	for _, f := range canary.Fakes() {
		if f.Rule != "private-key" {
			continue
		}
		cut := f.Text[:strings.Index(f.Text, "-----END")]
		out, hits, err := r.JSON([]byte(`{"arguments":` + jstr(`{"cmd":`+jstr(cut)+`,"workdir":"/src"}`) + `}`))
		if err != nil || strings.Contains(string(out), f.Secret) || hits["private-key"] != 1 {
			t.Fatalf("%s %v %v", out, hits, err)
		}
		var outer struct{ Arguments string }
		if err := json.Unmarshal(out, &outer); err != nil || !json.Valid([]byte(outer.Arguments)) || !strings.Contains(outer.Arguments, `"workdir":"/src"`) {
			t.Fatalf("the document held in the string was cut: %q (%v)", outer.Arguments, err)
		}
	}
}

// The text rules still run over a document read as JSON, for what only the whole text shows: a secret that is a number
// (the key-name rule is for strings), with or without another secret in the same document.
func TestJSONTextRulesStillRunOverANestedDocument(t *testing.T) {
	r := redact.Default()
	for _, inner := range []string{
		`{"password":123456789012}`,
		`{"cmd":"export DB_PASSWORD=hunter2hunter2","api_key":987654321098}`,
	} {
		out, hits, err := r.JSON([]byte(`{"arguments":` + jstr(inner) + `}`))
		if err != nil || strings.Contains(string(out), "123456789012") || strings.Contains(string(out), "987654321098") ||
			strings.Contains(string(out), "hunter2hunter2") || hits.Total() == 0 {
			t.Errorf("%s -> %s %v %v", inner, out, hits, err)
		}
	}
}

func TestJSONUntouchedNestedStringKeepsItsBytes(t *testing.T) {
	r := redact.Default()
	inner := "{ \"a\" : 1.50,\n  \"b\":\"caf\\u00e9\", \"c\": [1e3, -0.0] }"
	in := `{"arguments": ` + jstr(inner) + `, "n": 1.50}`
	out, hits, err := r.JSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"arguments":` + jstr(inner) + `,"n":1.50}`
	if string(out) != want || hits != nil {
		t.Fatalf("got  %s\nwant %s\nhits %v", out, want, hits)
	}
}

func TestJSONRedactedNestedDocumentKeepsKeyOrderAndNumbers(t *testing.T) {
	r := redact.Default()
	inner := `{"z": 1.50, "a": "API_KEY=abcdefghijkl", "m": {"y": 1e3, "b": [2.0, "ok"]}, "e": []}`
	out, hits, err := r.JSON([]byte(`{"arguments": ` + jstr(inner) + `}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"arguments":` + jstr(`{"z":1.50,"a":"API_KEY=[REDACTED:env-secret]","m":{"y":1e3,"b":[2.0,"ok"]},"e":[]}`) + `}`
	if string(out) != want || hits["env-secret"] != 1 || hits.Total() != 1 {
		t.Fatalf("got  %s\nwant %s\nhits %v", out, want, hits)
	}
}

func TestJSONNestedHitsAreCounted(t *testing.T) {
	r := redact.Default()
	inner := `{"cmd":"export DB_PASSWORD=hunter2hunter2 && echo \"STRIPE_WEBHOOK_SECRET=\\\"my long secret phrase\\\"\"","access_token":"abcdefghijklmnop"}`
	out, hits, err := r.JSON([]byte(`{"arguments":` + jstr(inner) + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if hits["env-secret"] != 2 || hits[redact.KeyNameRuleName] != 1 || hits.Total() != 3 {
		t.Fatalf("hits = %v\n out %s", hits, out)
	}
	for _, s := range []string{"hunter2hunter2", "my long secret phrase", "abcdefghijklmnop"} {
		if strings.Contains(string(out), s) {
			t.Errorf("%q survived: %s", s, out)
		}
	}
}

func TestJSONKeyNameRuleStillWinsOverANestedDocument(t *testing.T) {
	r := redact.Default()
	out, hits, err := r.JSON([]byte(`{"token":` + jstr(cmdDoc("DB_PASSWORD=hunter2hunter2")) + `}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"token":"[REDACTED:key-name]"}` || hits[redact.KeyNameRuleName] != 1 || hits.Total() != 1 {
		t.Fatalf("%s %v", out, hits)
	}
}

func TestJSONStringThatOnlyLooksLikeJSONIsRedactedAsText(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		`{ echo "x"; DB_PASSWORD=hunter2hunter2; }`,
		`[ -f .env ] && export DB_PASSWORD=hunter2hunter2`,
		`{"cmd": "DB_PASSWORD=hunter2hunter2"`, // cut off
		`{"a":1} {"b":"DB_PASSWORD=hunter2hunter2"}`,
		`[1,2,] DB_PASSWORD=hunter2hunter2`,
		"  \t{not json} DB_PASSWORD=hunter2hunter2",
	} {
		out, hits, err := r.JSON([]byte(jstr(s)))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "hunter2hunter2") || hits["env-secret"] != 1 {
			t.Errorf("%q -> %s %v", s, out, hits)
		}
	}
}

func TestJSONLeavesStringsWithNothingInThemAlone(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{"{}", "[]", "[1,2,3]", `{"a":1}`, `{ "list": [ "x", "y" ] }`, "{", "[", `["`, "{ }", " [ ] ", "", " ", "\n\t", "{\n}"} {
		in := `{"v":` + jstr(s) + `}`
		out, hits, err := r.JSON([]byte(in))
		if err != nil || string(out) != in || hits != nil {
			t.Errorf("%q -> %s %v %v", s, out, hits, err)
		}
	}
}

// the common path: a string that is not a document costs nothing extra and changes nothing
func TestJSONPlainStringsAreUnchangedByTheNestedPath(t *testing.T) {
	r := redact.Default()
	in := `{"a":"{plain text, not a doc}","b":"[x] and \"quoted\"","c":"line one\nline two","d":"  {\"k\":\"v\"}  "}`
	out, hits, err := r.JSON([]byte(in))
	if err != nil || string(out) != in || hits != nil {
		t.Fatalf("%s %v %v", out, hits, err)
	}
}

// A string that holds a JSON string literal (the document encoded twice) is what a double-encoding writer
// would store. The quoted-value rules read through the extra escapes, so it is covered without a second parse.
func TestJSONDoubleEncodedDocument(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		doc := `{"arguments":` + jstr(jstr(cmdDoc(f.Text))) + `}`
		out, _, err := r.JSON([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), f.Secret) {
			t.Errorf("double encoded/%s#%d: the secret survived: %s", f.Rule, i, out)
		}
	}
}

// nestedFuzzDoc puts text where a coding agent's records put it, in one of a few shapes.
func nestedFuzzDoc(text string, shape int) string {
	switch shape % 7 {
	case 0:
		return cmdDoc(text)
	case 1:
		return nest(cmdDoc(text), 1)
	case 2:
		return nest(cmdDoc(text), 2)
	case 3:
		return nest(cmdDoc(text), 3)
	case 4:
		return `["x",` + jstr(cmdDoc(text)) + `]`
	case 5:
		return jstr(cmdDoc(text))
	default:
		return `{"arguments":` + jstr(`["sh","-c",`+jstr(text)+`]`) + `}`
	}
}

// FuzzJSONNested: whatever surrounds a canary line, in whichever shape the record holds it, JSON() gives back valid JSON
// without the secret, and redacting that again changes nothing.
func FuzzJSONNested(f *testing.F) {
	fakes := canary.Fakes()
	for i := range fakes {
		for shape := 0; shape < 7; shape++ {
			f.Add("", uint8(i), uint8(shape))
		}
		f.Add("note: {\"a\": \"b\"}", uint8(i), uint8(i%7))
		f.Add("```\n", uint8(i), uint8(1))
	}
	r := redact.Default()
	f.Fuzz(func(t *testing.T, around string, which, shape uint8) {
		fk := fakes[int(which)%len(fakes)]
		doc := nestedFuzzDoc(around+"\n"+fk.Text+"\n"+around, int(shape))
		out, _, err := r.JSON([]byte(doc))
		if err != nil {
			t.Fatalf("a valid document was refused: %v\n input %s", err, doc)
		}
		if !json.Valid(out) {
			t.Fatalf("the output is not valid JSON\n input %s\n out   %s", doc, out)
		}
		if strings.Contains(string(out), fk.Secret) {
			t.Fatalf("the secret of %s survived\n input %s\n out   %s", fk.Rule, doc, out)
		}
		again, hits, err := r.JSON(out)
		if err != nil || !bytes.Equal(again, out) || hits.Total() != 0 {
			t.Fatalf("redacting the output again changed it (err %v, hits %v)\n input %s\n once  %s\n twice %s", err, hits, doc, out, again)
		}
	})
}

// FuzzJSONDocument: any valid JSON document comes back valid, and redacting it a second time changes nothing.
func FuzzJSONDocument(f *testing.F) {
	for _, c := range canary.Fakes() {
		for shape := 0; shape < 7; shape++ {
			f.Add([]byte(nestedFuzzDoc(c.Text, shape)))
		}
	}
	for _, s := range []string{`{"a":"{\"b\":\"[1,\\\"x\\\"]\"}"}`, `"[{}]"`, `["{}", "[]", "{\"k\":\"v\"}"]`, ` {"a":" [ \"x\" ] "} `} {
		f.Add([]byte(s))
	}
	r := redact.Default()
	f.Fuzz(func(t *testing.T, in []byte) {
		if !json.Valid(in) {
			t.Skip()
		}
		out, _, err := r.JSON(in)
		if err != nil {
			t.Fatalf("a valid document was refused: %v\n input %q", err, in)
		}
		if !json.Valid(out) {
			t.Fatalf("the output is not valid JSON\n input %q\n out   %q", in, out)
		}
		again, hits, err := r.JSON(out)
		if err != nil || !bytes.Equal(again, out) || hits.Total() != 0 {
			t.Fatalf("redacting the output again changed it (err %v, hits %v)\n input %q\n once  %q\n twice %q", err, hits, in, out, again)
		}
	})
}

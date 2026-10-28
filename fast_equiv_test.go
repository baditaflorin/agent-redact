package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/baditaflorin/agent-redact/canary"
)

// The fast path must return exactly what the whole-text regular expressions return: same text, same hit
// counts. These tests hold it to that on every kind of input we can build.

var (
	fastR = Default()
	refR  = New(referenceRules())
)

func equalToReference(t *testing.T, s string) bool {
	t.Helper()
	gotS, gotH := fastR.String(s)
	wantS, wantH := refR.String(s)
	if gotS != wantS || !reflect.DeepEqual(gotH, wantH) {
		t.Errorf("fast path differs from the reference\n input %q\n fast  %q %v\n want  %q %v", s, gotS, gotH, wantS, wantH)
		return false
	}
	return true
}

func TestFastPathIsActive(t *testing.T) {
	n := 0
	for _, r := range DefaultRules() {
		if r.fast != nil {
			n++
		}
	}
	if n != 11 { // openai, auth-header, url-credentials, four cookie-header, three env-secret, flag-secret
		t.Fatalf("%d rules have a fast path, want 11", n)
	}
	if got := len(referenceRules()); got != len(DefaultRules()) {
		t.Fatal("reference rules differ in number")
	}
	for _, r := range referenceRules() {
		if r.fast != nil {
			t.Fatal("a reference rule has a fast path")
		}
	}
}

func TestFastEqualsReferenceOnCanaries(t *testing.T) {
	for _, f := range canary.Fakes() {
		equalToReference(t, f.Text)
		equalToReference(t, "before "+f.Text+" after")
		equalToReference(t, f.Text+"\n"+f.Text)
	}
}

func TestFastEqualsReferenceOnTheCorpus(t *testing.T) {
	for seed := int64(1); seed <= 3; seed++ {
		strs, _ := benchCorpus(600<<10, seed)
		for _, s := range strs {
			if !equalToReference(t, s) {
				return
			}
		}
	}
}

// the sequence "\xc5\xbf" is U+017F (long s) and "\xe2\x84\xaa" is U+212A (Kelvin sign): both fold onto ASCII
// letters under Go's case-insensitive matching, which the fast path hands back to the regular expression.
var trickyCases = []string{
	"", "x", "token", "TOKEN=abcdefgh", "token=abcde", "token=abcdef", "token = 'abc def ghi'", `token="abcd"`, `token="abc"`,
	`{"password": "hunter2hunter2", "token": 'x'}`, "TOKEN_SECRET=abcdefgh", "xtoken=abcdefgh", " _token=abcdefgh",
	"tokens=abcdefgh", "token\n=\nabcdefgh", "token :\t \"abcd\"", "token=\"ab\ncd\"", `token="` + strings.Repeat("a", 300) + `"`,
	`token="` + strings.Repeat("a", 301) + `"`, "token=" + strings.Repeat("b", 100000),
	`token="[REDACTED:env-secret]"`, "token=[REDACTED:env-secret]", `token='[REDACTED:env-secret]'`,
	`a_token="x_token='abcd'efgh"`, "token='a' token=\"bbbb\" token=cccccc", "token=abc,def ghijkl=mnopqr",
	"my_api_key: abcdefghij; PASSWORD=hunter2hunter2) secret=abcdefg]", "API_KEY=abcdefgh API-KEY=abcdefgh APIKEY=abcdefgh",
	"ACCESS_KEY=abcdefgh ACCESSKEY=abcdefgh PRIVATE_KEY=abcdefgh PRIVATEKEY=abcdefgh AUTH_KEY=abcdefgh AUTHKEY=abcdefgh",
	"SECRET_KEY=abcdefgh SECRETKEY=abcdefgh credentials=abcdefgh credential=abcdefgh passwd=abcdefgh Passwd: abcdefgh",
	"\xc3\xa9_token=abcdefgh", "token=\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", "\xc8\x99token=abcdefgh", "pâine și sare token parola secret",
	"\xe2\x84\xaa0://0:0@0", "a\xe2\x84\xaa0://0:0@0", "\xc5\xbf0://0:0@0", "\xc5\xbfecret=abcdefgh", "TO\xe2\x84\xaaEN=abcdefgh", "\xc5\xbf token=abcdefgh", "k\xe2\x84\xaa --password abcdefgh",
	" --password hunter2hunter2", "--password hunter2hunter2", "x --db-password 'abc def'", "\t--token abcdefgh", " -token abcdefgh",
	" --api-key abcdefgh", " ---token abcdefgh", " --a--token abcdefgh", " --token-limit 100000", " --apikey abcdefgh --access-key abcdefgh",
	"\n--secret abcdefgh\n--auth-key \"abcdefgh\"", " --password=abcdefgh", " --password\tabcdefgh", " --password \xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9",
	"Authorization: Bearer abcdefgh", "xauthorization: bearer abcdefgh", `AUTHORIZATION="Basic abcdefgh1"`, "authorization: token ab",
	"-H 'Authorization: Bearer abcdefghijklmnop' -H \"Authorization:Bearer zzzzzzzzzz\"", "authorization = bearer\tabcdefgh",
	"https://u:p@h", "ftp://a:b@c", "xhttps://u:p@h", "a.https://u:p@h", "abcdefghijklmnopqrstuvwxyz://u:p@h", "abcdefghijklmnop://u:p@h",
	"abcdefghijklmnopq://u:p@h", "http://user@host", "http://u:p@", "http://u:@h", "http://:p@h", "see http://x.com/a:b@c",
	"'http://u:p@h'", "git@github.com:org/repo.git", "mailto:a@b", "http://u:p:q@h/x", "http://u:p@h http://v:w@i", "x://u:p@h://v:w@i",
	"1http://u:p@h", "-http://u:p@h", "+http://u:p@h", "a+b-c.d://u:p@h", "postgres://app:s3cr3t@db:5432/app?x=y",
	"sk-abcdefghijklmnopqrstuvwx", "xsk-abcdefghijklmnopqrstuvwx", "task-abcdefghijklmnopqrstuvwxyz", "sk-proj-abcdefghijklmnopqrstuvwx",
	"sk-svcacct-abcdefghijklmnopqrstuvwx", "sk-ant-abcdefghijklmnopqrstuvwx", "sk-short", "sk-" + strings.Repeat("a", 5000), "(sk-abcdefghijklmnopqrstuvwx)",
	"export TOKEN=abcdefgh --password hunter2hunter2 https://u:p@h Authorization: Bearer abcdefgh sk-abcdefghijklmnopqrstuvwx",
	"TOKEN=abcdefgh\nPASSWORD='x y z w'\nSECRET=\"p q r s\"\n",
	"token=\"a b c d\" secret='e f g h' password=ijklmnop",
	// escaped quotes: \" as a JSON string or a shell string shows a quote, \\\" one level deeper
	`NAME_TOKEN=\"a value with spaces\"`, `{\"api_key\": \"hunter2hunter2\"}`, `{\\\"api_key\\\": \\\"hunter2hunter2\\\"}`,
	`{\"user\":\"ann\",\"access_token\":\"abcdefghijklmnop\"}`, `DB_PASSWORD=\'my long secret phrase\'`, `{\'password\': \'hunter2hunter2\'}`,
	`APP_TOKEN=\"ab\"`, `APP_TOKEN=\"abcd\"`, `APP_TOKEN=\"abc\"`, `APP_TOKEN=\"abc\\"`, `APP_TOKEN="abc\"`, `APP_TOKEN=\"abc"`, `APP_TOKEN="abcd\\\"`,
	`token=\"` + strings.Repeat("a", 300) + `\"`, `token=\"` + strings.Repeat("a", 301) + `\"`, `token="` + strings.Repeat("a", 299) + `\\"`,
	`token=\"[REDACTED:env-secret]\"`, `token=\'[REDACTED:env-secret]\'`, `{\"token\": \"[REDACTED:env-secret]\"}`,
	`token=\\\\\\\\\"abcdefgh\\\\\\\\\"`, `token=\\\\\\\\\\\\\\\\\"abcd\"`, `token=\\`, `token=\"`, `token=\"\n`, "token=\\\"ab\ncd\\\"",
	"TOKEN\\\"=\\\"abcdefgh\\\"", `"TOKEN"=\"abcdefgh\"`, `\"TOKEN\"\t:\t\"abcdefgh\"`, `\"TOKEN\" : abcdefghi`, `\"token\":\"x\",\"secret\":\"abcdefg\"`,
	`\"Authorization\": \"Bearer abcdefgh1\"`, `\"authorization\":\"basic abcdefgh1\"`, `authorization=\"token abcdefgh1\"`, `authorization\\\"\\\":\\\" bearer abcdefgh1`,
	`\\\"Authorization\\\": \\\"Bearer abcdefgh1\\\"`, `-H \"Authorization: Bearer abcdefghijklmnop\" -H \"X: y\"`,
	`mysql --password \"hunter2flag99\" -h db`, `mysql --password \\\"hunter2flag99\\\" -h db`, ` --token \'abcdefgh\'`, ` --token \\\\abcdefgh`, ` --token \\"abcdefgh`, ` --password=\"hunter2flag99\"`,
	"TO\xe2\x84\xaaEN=\\\"abcdefgh\\\"", "\xc5\xbfecret=\\\"abcdefgh\\\"", "k\xe2\x84\xaa --password \\\"abcdefgh\\\"",
	// cookie headers and pairs, plain and escaped
	"Cookie: a=b", "Cookie: a=b\nHost: x", "Set-Cookie: sid=abc; Path=/", "cookie:a=b", "COOKIE: a=b; c=d", `-H 'Cookie: a=b' x`, `-H "Cookie: a=b" x`,
	`-H \"Cookie: a=b\" x`, `-H \\\"Cookie: a=b\\\" x`, `-H \'Cookie: a=b\' x`, `{"Cookie": "a=b; c=d"}`, `{'Cookie': 'a=b'}`, `{\"cookie\":\"a=b\"}`,
	`document.cookie = "a=b"`, `Cookie: a="x y"; b=c`, `Cookie: a="x`, `Cookie: a=x'y`, "Cookie: none", "Cookie: =", "Cookie: a=", "Cookie: =a", "Cookie:",
	"Cookie: \n a=b", "cookies: a=b", "session_cookie: a=b", "x-cookie: a=b", "Cookie: " + strings.Repeat("a=b; ", 300), `'Cookie: a=b`,
	`'Cookie: a=b' 'Cookie: c=d'`, `\\\'Cookie: abc\\\'`, `'Cookie: `, `"Cookie: a=b\"`, `Cookie: a=b\\"`, `Cookie: a=b\"`, "Cookie: a=b\r\nCookie: c=d",
	`{"h":"Cookie: a=b"}`, `{\"h\":\"Cookie: a=b\"}`, `{\"h\":\"Cookie: a=b\\\\"}`, `cookie: "a=bcd"`, `cookie="a=bcd"`, `cookie: 'a=bcd'`, `Cookie: [REDACTED:cookie-header]`,
	`'Cookie: [REDACTED:cookie-header]'`, `{"cookie": "[REDACTED:cookie-header]"}`, "Cookie: a=b; Cookie: c=d", `'Cookie: a=b'Cookie: c=d'`,
	"Coo\xe2\x84\xaaie: a=b", `{"Coo\xe2\x84\xaaie": "a=bcd"}`, "'Coo\xe2\x84\xaaie: a=bcd'",
	// trailing backslashes of an escaped closing quote
	`echo \"API_KEY=abcdefghijk\"`, `echo \'API_KEY=abcdefghijk\'`, `T_TOKEN=abcde\" x`, `PASSWORD=abcdefg\ more`, `PASSWORD=abcdefg\\" more`, `PASSWORD=abcdefg\\`,
	`PASSWORD=\\\\\\"`, `PASSWORD=abcdef\\\\\\\\"x`, `--password abcdefgh\" x`, `--password \"abcdefgh\" x`, `--password abcdefg\\\\\\\\ x`,
}

func TestFastEqualsReferenceOnTrickyCases(t *testing.T) {
	for _, s := range trickyCases {
		equalToReference(t, s)
		equalToReference(t, "lead "+s)
		equalToReference(t, s+" tail")
		equalToReference(t, strings.ToUpper(s))
	}
}

// generated builds text out of the fragments that make these rules decide something: names, separators,
// values, flags, URLs, quotes, line breaks and non-ASCII neighbours.
func generated(r *rand.Rand) string {
	names := []string{"TOKEN", "token", "Api_Key", "api-key", "apikey", "my_password", "PASSWD", "secret", "SECRET_KEY", "secretkey",
		"credentials", "credential", "x", "tokens", "authorization", "Authorization", "access_key", "AccessKey", "private_key",
		"auth_key", "db_token", "\xc3\xa9token", "\xc8\x99secret", "t0ken", "tokenizer", "my-token", "\xc5\xbfecret", "TO\xe2\x84\xaaEN",
		"cookie", "Cookie", "Set-Cookie", "session_cookie", "COOKIE", "cookies", "x-cookie", "Coo\xe2\x84\xaaie"}
	seps := []string{"=", ": ", " = ", "\": \"", "':'", "=\"", "='", " :\n", "\t=\t", "\":", "'=", "= ", ":", " ",
		`=\"`, `\": \"`, `\":\"`, `=\'`, `\'=\'`, `\\\": \\\"`, `=\\\"`, `\": `, `\"=`, `=\\\\\\"`, `\" :\n\"`}
	values := []string{"abcdefgh", "hunter2hunter2", "abc def ghi", "[REDACTED:env-secret]", "12345", "ab", strings.Repeat("a", 301),
		"\"abcd\"", "'abcd'", "\"ab\"", "a,b;c)d]e", "\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", "Bearer abcdefgh", "basic zzzzzzzz", "token abcdefghi",
		"a=b; c=d", "sid=abc123; Path=/; HttpOnly", `a="b c"; d=e`, "a=x'y", "a=", "=a", `a=b\r\nHost: x`, strings.Repeat("a=b; ", 80),
		`\"abcd\"`, `\"ab cd ef\"`, `\\\"abcd\\\"`, `\'abcd\'`, `\"ab\"`, `\"Bearer abcdefgh\"`, `\"abcd"`, `"abcd\"`, `\"abc def\\"`, strings.Repeat("a", 300) + `\"`, `\"` + strings.Repeat("b", 299) + `\"`}
	flags := []string{" --password ", " --token ", " -secret ", " --db-api-key ", "--token ", " --auth-key ", " --token-x ", "\t--passwd ",
		` --password \"`, ` --token \'`, ` --secret \\\"`}
	urls := []string{"https://u:p@h", "http://example.com/a", "ftp://a:b@c/x", "x://u@h", "abcdefghijklmnopqrstuvwxyz://u:p@h", "a.b-c+d://u:p@h", "http://u:@h", "'http://u:p@h'"}
	keys := []string{"sk-abcdefghijklmnopqrstuvwx", "task-abcdefghijklmnopqrstuvwxyz", "sk-proj-abcdefghijklmnopqrstuvwx", "sk-ant-abcdefghijklmnopqrstuvwx", "sk-x"}
	words := []string{"the", "a", "function", "returns", "error", "\n", " ", "  ", "\t", "\"", "'", "(", ")", "{", "}", "[", "]", ",", ";",
		`\`, `\"`, `\\"`, `\'`, `\n`}
	hdrOpen := []string{"", "-H '", `-H "`, `\"`, `\'`, "\n", "HTTP/1.1 200 OK\r\n", `\\\"`, "'", `"`}
	hdrClose := []string{"", "'", `"`, `\"`, `\'`, "\n", " https://x", `\\\"`, "\r\n"}
	hdrNames := []string{"Cookie: ", "Set-Cookie: ", "cookie:", "COOKIE : ", "session_cookie: ", "cookies: ", "x-cookie:\t"}
	var b strings.Builder
	for i, n := 0, 1+r.Intn(10); i < n; i++ {
		switch r.Intn(8) {
		case 7:
			b.WriteString(hdrOpen[r.Intn(len(hdrOpen))])
			b.WriteString(hdrNames[r.Intn(len(hdrNames))])
			b.WriteString(values[r.Intn(len(values))])
			b.WriteString(hdrClose[r.Intn(len(hdrClose))])
		case 0, 1, 2:
			b.WriteString(names[r.Intn(len(names))])
			b.WriteString(seps[r.Intn(len(seps))])
			b.WriteString(values[r.Intn(len(values))])
		case 3:
			b.WriteString(flags[r.Intn(len(flags))])
			b.WriteString(values[r.Intn(len(values))])
		case 4:
			b.WriteString(urls[r.Intn(len(urls))])
		case 5:
			b.WriteString(keys[r.Intn(len(keys))])
		default:
			b.WriteString(words[r.Intn(len(words))])
		}
		b.WriteString(words[r.Intn(len(words))])
	}
	return b.String()
}

func TestFastEqualsReferenceOnGeneratedText(t *testing.T) {
	cases := 60000
	if testing.Short() {
		cases = 5000
	}
	r := rand.New(rand.NewSource(20261028))
	for i := 0; i < cases; i++ {
		s := generated(r)
		if !equalToReference(t, s) {
			t.Fatalf("stopped at case %d", i)
		}
	}
}

func TestRedactionIsIdempotent(t *testing.T) {
	// both implementations: if only the fast one failed it would be a regression, if both do it is older
	for name, red := range map[string]*Redactor{"fast": fastR, "reference": refR} {
		r := rand.New(rand.NewSource(77))
		bad := 0
		for i := 0; i < 20000; i++ {
			in := generated(r)
			once, _ := red.String(in)
			twice, hits := red.String(once)
			if once != twice || hits.Total() != 0 {
				if bad++; bad <= 3 {
					t.Errorf("%s is not idempotent:\n input %q\n once  %q\n twice %q %v", name, in, once, twice, hits)
				}
			}
		}
		if bad > 0 {
			t.Errorf("%s: %d of 20000 generated texts change when redacted a second time", name, bad)
		}
	}
}

func FuzzRedactionIsIdempotent(f *testing.F) {
	for _, s := range trickyCases {
		f.Add(s)
	}
	r := rand.New(rand.NewSource(6))
	for i := 0; i < 200; i++ {
		f.Add(generated(r))
	}
	f.Fuzz(func(t *testing.T, s string) {
		once, _ := fastR.String(s)
		twice, hits := fastR.String(once)
		if once != twice || hits.Total() != 0 {
			t.Fatalf("not idempotent\n input %q\n once  %q\n twice %q %v", s, once, twice, hits)
		}
	})
}

func FuzzFastEqualsReference(f *testing.F) {
	for _, s := range trickyCases {
		f.Add(s)
	}
	for _, c := range canary.Fakes() {
		f.Add(c.Text)
	}
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 200; i++ {
		f.Add(generated(r))
	}
	f.Fuzz(func(t *testing.T, s string) {
		gotS, gotH := fastR.String(s)
		wantS, wantH := refR.String(s)
		if gotS != wantS || !reflect.DeepEqual(gotH, wantH) {
			t.Fatalf("fast path differs from the reference\n input %q\n fast  %q %v\n want  %q %v", s, gotS, gotH, wantS, wantH)
		}
	})
}

// the rules run in sequence on a changing text: the scratch must not carry a stale lower-case copy.
func TestScratchDoesNotGoStale(t *testing.T) {
	s := "TOKEN=\"abcd\" and then PASSWORD=hunter2hunter2 and --secret zzzzzzzz plus Authorization: Bearer abcdefgh"
	got, hits := fastR.String(s)
	want, wantHits := refR.String(s)
	if got != want || !reflect.DeepEqual(hits, wantHits) {
		t.Fatalf("%q %v vs %q %v", got, hits, want, wantHits)
	}
	if strings.Contains(got, "hunter2hunter2") || strings.Contains(got, "zzzzzzzz") || strings.Contains(got, "abcdefgh") {
		t.Fatalf("a secret survived: %s", got)
	}
}

func BenchmarkFastVersusReference(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	for _, c := range []struct {
		name string
		r    *Redactor
	}{{"fast", fastR}, {"reference", refR}} {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(total))
			for n := 0; n < b.N; n++ {
				for _, s := range strs {
					c.r.String(s)
				}
			}
		})
	}
	_ = fmt.Sprint
}

func TestWriteStringEqualsTheEncoder(t *testing.T) {
	encoder := func(s string) string {
		var tmp bytes.Buffer
		enc := json.NewEncoder(&tmp)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		return strings.TrimRight(tmp.String(), "\n")
	}
	cases := []string{"", "plain", "a < b && c > d", "quote \" inside", "back\\slash", "tab\tnewline\nbell\a", "del\x7f",
		"\xc3\xa9\xc8\x99 ok", "bad \xff utf8", "line sep \xe2\x80\xa8 and \xe2\x80\xa9", "nul\x00", "emoji \xf0\x9f\x8d\x9e", "\xe2\x80\xa7 near"}
	r := rand.New(rand.NewSource(3))
	for i := 0; i < 5000; i++ {
		cases = append(cases, generated(r))
	}
	for _, s := range cases {
		var b bytes.Buffer
		writeString(&b, s)
		if got, want := b.String(), encoder(s); got != want {
			t.Fatalf("writeString(%q) = %s, the encoder writes %s", s, got, want)
		}
	}
}

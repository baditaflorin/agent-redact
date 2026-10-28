package redact_test

import (
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
)

// Cookie and Set-Cookie headers hold session credentials. The cookie-header rule takes the whole value of the header,
// up to the end of its line, up to the quote that closes a header held in quotes, or, for a pair ("Cookie": "..."),
// the quoted value. Raw strings: every backslash is a backslash in the text.

const ck = "s3ss10nValue99" // the secret in every case below

var cookieCases = []struct{ name, text, want string }{
	{"request header", "GET / HTTP/1.1\nHost: example.invalid\nCookie: session=" + ck + "; theme=dark\nAccept: */*",
		"GET / HTTP/1.1\nHost: example.invalid\nCookie: [REDACTED:cookie-header]\nAccept: */*"},
	{"response header with attributes", "Set-Cookie: sid=" + ck + "; Path=/; HttpOnly; Secure", "Set-Cookie: [REDACTED:cookie-header]"},
	{"crlf", "Cookie: a=" + ck + "\r\nHost: x", "Cookie: [REDACTED:cookie-header]\r\nHost: x"},
	{"two headers", "Cookie: a=" + ck + "\nCookie: b=" + ck + "2", "Cookie: [REDACTED:cookie-header]\nCookie: [REDACTED:cookie-header]"},
	{"curl, single quotes", `curl -H 'Cookie: session=` + ck + `; theme=dark' https://example.invalid`,
		`curl -H 'Cookie: [REDACTED:cookie-header]' https://example.invalid`},
	{"curl, double quotes", `curl -H "Cookie: session=` + ck + `" https://example.invalid`, `curl -H "Cookie: [REDACTED:cookie-header]" https://example.invalid`},
	{"curl, escaped double quotes", `curl -H \"Cookie: session=` + ck + `\" https://example.invalid`, `curl -H \"Cookie: [REDACTED:cookie-header]\" https://example.invalid`},
	{"curl, two levels of escape", `curl -H \\\"Cookie: session=` + ck + `\\\" x`, `curl -H \\\"Cookie: [REDACTED:cookie-header]\\\" x`},
	{"curl, escaped single quotes", `-H \'Cookie: session=` + ck + `; a=b\' x`, `-H \'Cookie: [REDACTED:cookie-header]\' x`},
	{"json pair", `{"Cookie": "session=` + ck + `; theme=dark"}`, `{"Cookie": "[REDACTED:cookie-header]"}`},
	{"json pair, compact, lower case", `{"set-cookie":"sid=` + ck + `"}`, `{"set-cookie":"[REDACTED:cookie-header]"}`},
	{"python dict", `{'Cookie': 'session=` + ck + `'}`, `{'Cookie': '[REDACTED:cookie-header]'}`},
	{"escaped json pair", `{\"Cookie\": \"session=` + ck + `\"}`, `{\"Cookie\": \"[REDACTED:cookie-header]\"}`},
	{"assignment", `document.cookie = "session=` + ck + `; path=/"`, `document.cookie = "[REDACTED:cookie-header]"`},
	{"header in a document kept as text", `{"h":"Cookie: session=` + ck + `"}`, `{"h":"Cookie: [REDACTED:cookie-header]"}`},
	{"header in a document kept as text, escaped", `{\"h\":\"Cookie: session=` + ck + `\"}`, `{\"h\":\"Cookie: [REDACTED:cookie-header]\"}`},
	{"command in a document kept as text", `{"cmd":"curl -H 'Cookie: s=` + ck + `' x"}`, `{"cmd":"curl -H 'Cookie: [REDACTED:cookie-header]' x"}`},
	{"quoted cookie value", `Cookie: a="x y"; sid=` + ck, `Cookie: [REDACTED:cookie-header]`},
	{"apostrophe in a value", `Cookie: a=x'y; sid=` + ck, `Cookie: [REDACTED:cookie-header]`},
	{"upper case", "COOKIE: a=" + ck, "COOKIE: [REDACTED:cookie-header]"},
	{"mixed case", "cOoKiE: a=" + ck, "cOoKiE: [REDACTED:cookie-header]"},
	{"name with a prefix", "session_cookie: a=" + ck, "session_cookie: [REDACTED:cookie-header]"},
	{"no space", "Cookie:a=" + ck, "Cookie:[REDACTED:cookie-header]"},
	{"a header of 1200 characters", "Cookie: a=" + strings.Repeat("v", 1200) + "; b=" + ck, "Cookie: [REDACTED:cookie-header]"},
	{"name with a prefix, json pair", `{"session_cookie": "a=` + ck + `"}`, `{"session_cookie": "[REDACTED:cookie-header]"}`},
	{"name with a prefix, assignment", `SESSION_COOKIE="a=` + ck + `"`, `SESSION_COOKIE="[REDACTED:cookie-header]"`},
	{"quoted segment later in the value", `Cookie: a=b; c="x y"; sid=` + ck, `Cookie: [REDACTED:cookie-header]`},
	{"two quoted segments", `Cookie: a="x y"; c="z w"; sid=` + ck + "\nHost: x", "Cookie: [REDACTED:cookie-header]\nHost: x"},
	{"shortest quoted header", `curl -H 'Cookie: a=b' x`, `curl -H 'Cookie: [REDACTED:cookie-header]' x`},
	{"shortest line", "Cookie: a=b", "Cookie: [REDACTED:cookie-header]"},
	{"a quoted pair of 1200 characters", `{"Cookie": "a=` + strings.Repeat("v", 1200) + `; b=` + ck + `"}`, `{"Cookie": "[REDACTED:cookie-header]"}`},
}

func TestCookieHeadersAreRedacted(t *testing.T) {
	r := redact.Default()
	for _, c := range cookieCases {
		out, hits := r.String(c.text)
		if strings.Contains(out, ck) || hits["cookie-header"] == 0 {
			t.Errorf("%s: the secret survived\n in  %s\n out %s %v", c.name, c.text, out, hits)
			continue
		}
		if out != c.want {
			t.Errorf("%s:\n in   %s\n out  %s\n want %s", c.name, c.text, out, c.want)
		}
		if again, h := r.String(out); again != out || h.Total() != 0 {
			t.Errorf("%s: not idempotent\n once  %s\n twice %s %v", c.name, out, again, h)
		}
	}
}

func TestTextThatMentionsCookiesIsLeftAlone(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		"Cookie: none", "Cookie: enabled", "the Cookie: header carries state", "cookies: a=b", "cookie_banner: a=b", "Set-Cookie header", "Cookie",
		`{"cookie": "ab"}`, `{'cookie': 'ab'}`, "cookie-jar: a=b", "cookie policy: accept=all", "Cookie:", "Cookie: \n", "Cookie: =", "Cookie: a=",
		"we set a cookie, then read it", `the "cookie" key`, "Cookies: session=abc", "Cookie:\nfoo=bar", "Cookie: \t\nfoo=bar", "Cookie: =x", "Cookie:  =x", "Cookie:\t=x", `curl -H 'Cookie: ab' x`, "Cookie: a b",
	} {
		out, hits := r.String(s)
		if out != s || hits.Total() != 0 {
			t.Errorf("changed %q to %q (%v)", s, out, hits)
		}
	}
}

func TestCookieRuleIsListed(t *testing.T) {
	var found bool
	for _, n := range redact.Default().RuleNames() {
		found = found || n == "cookie-header"
	}
	if !found {
		t.Fatal("cookie-header is not in RuleNames")
	}
}

// A cookie in a document that is read as JSON is the key-name rule's, and the same canary text is found either way.
func TestCookieInsideJSONStrings(t *testing.T) {
	r := redact.Default()
	for _, doc := range []string{
		`{"headers":"Cookie: a=` + ck + `"}`,
		`{"arguments":` + jstr(`{"cmd":`+jstr("curl -H 'Cookie: a="+ck+"' x")+`}`) + `}`,
		`{"out":` + jstr("HTTP/1.1 200 OK\nSet-Cookie: sid="+ck+"; Path=/\nX: y") + `}`,
		`{"Cookie":"a=` + ck + `"}`,
	} {
		out, hits, err := r.JSON([]byte(doc))
		if err != nil || strings.Contains(string(out), ck) || hits.Total() == 0 {
			t.Errorf("%s -> %s %v %v", doc, out, hits, err)
		}
	}
}

package redact_test

import (
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
)

// Fake values only, assembled at run time.
var (
	hex32    = strings.Repeat("0123456789abcdef", 2)
	hex64    = hex32 + hex32
	fakeAK   = "a" + "k_" + hex32
	fakeSelf = "a" + "k_selftest_" + hex32
	fakeLI   = "l" + "i_" + strings.Repeat("a1b2c3d4e5f6", 2) + "_" + hex64
	fakeFB   = "f" + "b_" + hex32
	fakeFB64 = "f" + "b_" + hex64
)

func TestFleetKeyFormats(t *testing.T) {
	r := redact.Default()
	for _, c := range []struct {
		in, secret, rule string
	}{
		{`curl -H "X-API-Key: ` + fakeAK + `" https://x.example.invalid/`, fakeAK, "fleet-api-key"},
		{`curl -H 'X-API-Key:` + fakeAK + `'`, fakeAK, "fleet-api-key"},
		{"bare " + fakeAK, fakeAK, "fleet-api-key"},
		{fakeAK, fakeAK, "fleet-api-key"},
		{"FLEET_API_KEY=" + fakeAK, fakeAK, "fleet-api-key"},
		{`{"key":"` + fakeAK + `"}`, fakeAK, "fleet-api-key"},
		{`line one\n` + fakeAK + `\tnext`, fakeAK, "fleet-api-key"},
		{"https://x.example.invalid/?u=https%3A%2F%2Fy%3Fapi_key%3D" + fakeAK, fakeAK, "fleet-api-key"},
		{fakeAK + "_suffix", fakeAK, "fleet-api-key"},
		{"_" + fakeAK, fakeAK, "fleet-api-key"},
		{fakeSelf, fakeSelf, "fleet-api-key"},
		{"token " + fakeLI + " ok", fakeLI, "fleet-lease-issuer"},
		{`if ($http_x_api_key = "` + fakeFB + `") { return 200; }`, fakeFB, "fleet-fallback-key"},
		{"FLEET_API_KEY=" + fakeFB64, fakeFB64, "fleet-fallback-key"},
	} {
		out, hits := r.String(c.in)
		if strings.Contains(out, c.secret) {
			t.Errorf("%q: secret survived: %q", c.in, out)
		}
		if hits[c.rule] == 0 {
			t.Errorf("%q: rule %s did not fire (%v): %q", c.in, c.rule, hits, out)
		}
		if again, h := r.String(out); again != out || h.Total() != 0 {
			t.Errorf("%q: not idempotent: %q -> %q", c.in, out, again)
		}
	}
}

func TestFleetKeysKeepTheirSurroundings(t *testing.T) {
	r := redact.Default()
	out, _ := r.String("a " + fakeAK + " b " + fakeAK + "_c")
	if want := "a [REDACTED:fleet-api-key] b [REDACTED:fleet-api-key]_c"; out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestFleetKeyLookalikesPassThrough(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		"leak_detector ak_ prefix fb_page_id li_item ak_test fb_xyz",
		"a" + "k_" + hex32[:31],             // too short
		"a" + "k_" + strings.ToUpper(hex32), // wrong case
		"bleak_" + hex32,                    // ak_ inside a word
		"f" + "b_" + hex32 + "zz",           // longer mixed token
		"a" + "k_" + hex64 + "0",            // longer than any fleet key
		"l" + "i_" + strings.Repeat("a", 24) + "_" + strings.Repeat("b", 63), // secret part too short
		"commit " + hex32 + "01234567",
	} {
		if out, hits := r.String(s); out != s || hits.Total() != 0 {
			t.Errorf("changed %q to %q (%v)", s, out, hits)
		}
	}
}

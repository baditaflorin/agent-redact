package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
)

// A fleet key written as an assignment ($http_x_api_key = "fb_...", FLEET_API_KEY=ak_...) is also what the generic
// env-secret rule matches. The fleet rules run first, so the stored text names the key's own kind; run the other
// way round, the key would still be gone but under [REDACTED:env-secret], and a check that looks for the fleet
// placeholder (the daily canary) reports the case as missing. These tests hold the order, on the plain path and on
// the paths real records take: a JSON string value, and a JSON document held in a string.

var genericRules = map[string]bool{
	"auth-header": true, "url-credentials": true, "cookie-header": true, "env-secret": true, "flag-secret": true,
}

func TestFleetRulesRunBeforeTheGenericOnes(t *testing.T) {
	lastFleet, firstGeneric := -1, -1
	for i, ru := range redact.DefaultRules() {
		switch {
		case strings.HasPrefix(ru.Name, "fleet-"):
			lastFleet = i
		case genericRules[ru.Name] && firstGeneric < 0:
			firstGeneric = i
		}
	}
	if lastFleet < 0 || firstGeneric < 0 {
		t.Fatalf("rules not found: last fleet rule at %d, first generic rule at %d", lastFleet, firstGeneric)
	}
	if lastFleet > firstGeneric {
		t.Fatalf("a fleet rule (position %d) runs after a generic one (position %d): a key in an assignment would be stored under the generic placeholder", lastFleet, firstGeneric)
	}
}

// fleetAssignments are the texts of the three key formats that a generic rule would also match.
var fleetAssignments = []struct {
	name, text, secret, rule string
}{
	{"nginx if, fallback key", `if ($http_x_api_key = "` + fakeFB + `") { return 200; }`, fakeFB, "fleet-fallback-key"},
	{"nginx if, 64 hex", `if ($http_x_api_key = "` + fakeFB64 + `") { return 200; }`, fakeFB64, "fleet-fallback-key"},
	{"env assignment, api key", "FLEET_API_KEY=" + fakeAK + "\nnext line", fakeAK, "fleet-api-key"},
	{"quoted assignment, api key", `export API_KEY="` + fakeAK + `"`, fakeAK, "fleet-api-key"},
	{"env assignment, fallback key", `FLEET_API_KEY='` + fakeFB + `'`, fakeFB, "fleet-fallback-key"},
	{"token assignment, lease issuer", "ISSUER_TOKEN=" + fakeLI, fakeLI, "fleet-lease-issuer"},
}

func TestFleetKeyAssignmentsKeepTheirOwnPlaceholder(t *testing.T) {
	r := redact.Default()
	for _, c := range fleetAssignments {
		own := "[REDACTED:" + c.rule + "]"

		// plain text
		plain, hits := r.String(c.text)
		if !strings.Contains(plain, own) || strings.Contains(plain, c.secret) || hits[c.rule] != 1 || hits["env-secret"] != 0 {
			t.Errorf("%s, plain: want only %s, got %q %v", c.name, own, plain, hits)
			continue
		}

		// one level of JSON: the text is a string value, so its quotes are \" in the document
		doc, err := json.Marshal(map[string]string{"content": c.text, "n": "1"})
		if err != nil {
			t.Fatal(err)
		}
		out, h, err := r.JSON(doc)
		if err != nil {
			t.Errorf("%s, JSON: %v", c.name, err)
			continue
		}
		if strings.Contains(string(out), c.secret) || strings.Contains(string(out), "[REDACTED:env-secret]") ||
			h[c.rule] != 1 || h["env-secret"] != 0 {
			t.Errorf("%s, JSON: want only %s, got %s %v", c.name, own, out, h)
		}
		var got map[string]string
		if err := json.Unmarshal(out, &got); err != nil || got["content"] != plain {
			t.Errorf("%s, JSON: the string value is %q, the plain path gives %q (%v)", c.name, got["content"], plain, err)
		}

		// a document held in a string, inside a document (a tool call whose arguments are JSON text)
		inner, err := json.Marshal(map[string]string{"command": c.text})
		if err != nil {
			t.Fatal(err)
		}
		outer, err := json.Marshal(map[string]string{"arguments": string(inner)})
		if err != nil {
			t.Fatal(err)
		}
		out, h, err = r.JSON(outer)
		if err != nil {
			t.Errorf("%s, nested JSON: %v", c.name, err)
			continue
		}
		if strings.Contains(string(out), c.secret) || strings.Contains(string(out), "[REDACTED:env-secret]") ||
			h[c.rule] != 1 || h["env-secret"] != 0 {
			t.Errorf("%s, nested JSON: want only %s, got %s %v", c.name, own, out, h)
		}

		// the same text with its quotes already escaped, as a shell command or a stored document shows it
		escaped := strings.ReplaceAll(c.text, `"`, `\"`)
		esc, h := r.String(escaped)
		if strings.Contains(esc, c.secret) || strings.Contains(esc, "[REDACTED:env-secret]") || h[c.rule] != 1 || h["env-secret"] != 0 {
			t.Errorf("%s, escaped quotes: want only %s, got %q %v", c.name, own, esc, h)
		}
	}
}

package redact_test

import (
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
	"github.com/baditaflorin/agent-redact/canary"
)

func apply(r *redact.Redactor, f canary.Fake) (string, redact.Hits, error) {
	if f.JSON {
		b, h, err := r.JSON([]byte(f.Text))
		return string(b), h, err
	}
	s, h := r.String(f.Text)
	return s, h, nil
}

func TestEveryRuleHasACanary(t *testing.T) {
	r := redact.Default()
	have := map[string]bool{}
	for _, f := range canary.Fakes() {
		have[f.Rule] = true
	}
	for _, name := range r.RuleNames() {
		if !have[name] {
			t.Errorf("rule %q has no canary", name)
		}
	}
}

func TestCanariesAreRedacted(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		out, hits, err := apply(r, f)
		if err != nil {
			t.Fatalf("canary %d (%s): %v", i, f.Rule, err)
		}
		if strings.Contains(out, f.Secret) {
			t.Errorf("canary %d (%s): the secret survived in %q", i, f.Rule, out)
		}
		if hits[f.Rule] == 0 {
			t.Errorf("canary %d: rule %s did not fire; hits %v; out %q", i, f.Rule, hits, out)
		}
		if !strings.Contains(out, "[REDACTED:"+f.Rule+"]") {
			t.Errorf("canary %d (%s): no placeholder in %q", i, f.Rule, out)
		}
	}
}

func TestRedactingTwiceChangesNothing(t *testing.T) {
	r := redact.Default()
	for i, f := range canary.Fakes() {
		once, _, err := apply(r, f)
		if err != nil {
			t.Fatal(err)
		}
		again := canary.Fake{Text: once, JSON: f.JSON}
		twice, hits, err := apply(r, again)
		if err != nil {
			t.Fatal(err)
		}
		if once != twice || hits.Total() != 0 {
			t.Errorf("canary %d (%s) is not idempotent:\n once  %q\n twice %q\n hits %v", i, f.Rule, once, twice, hits)
		}
	}
}

func TestTextThatIsNotASecretIsUntouched(t *testing.T) {
	r := redact.Default()
	for _, s := range []string{
		"",
		"the sky is blue",
		"pâine și sare, 🍞 și vin",
		"sk-learn is a Python library",
		"max_tokens: 4096 and total_tokens: 1234567",
		"TOKEN_LIMIT=1000000",
		"input_tokens=123456789",
		"docker run -u 1000:1000 busybox",
		"git clone git@github.com:org/repo.git",
		"https://example.com:443/path@version",
		"see https://example.com/docs#token for the token docs",
		"PASSWORD is required; set it in the form",
		"ssh -i key.pem user@host",
		"--token-limit 100000",
		"eyJ is how base64 JSON starts",
		"AKIA is a prefix",
	} {
		out, hits := r.String(s)
		if out != s || hits.Total() != 0 {
			t.Errorf("changed %q to %q (hits %v)", s, out, hits)
		}
	}
}

func TestHitsAreCounted(t *testing.T) {
	r := redact.Default()
	fakes := canary.Fakes()
	var a, b canary.Fake
	for _, f := range fakes {
		switch f.Rule {
		case "xai-key":
			a = f
		case "stripe-key":
			b = f
		}
	}
	text := a.Text + "\n" + a.Text + "\n" + b.Text
	out, hits := r.String(text)
	if hits["xai-key"] != 2 || hits["stripe-key"] != 1 || hits.Total() != 3 {
		t.Fatalf("hits = %v", hits)
	}
	if strings.Contains(out, a.Secret) || strings.Contains(out, b.Secret) {
		t.Fatal("a secret survived")
	}
	names := hits.Names()
	if len(names) != 2 || names[0] != "stripe-key" || names[1] != "xai-key" {
		t.Fatalf("names = %v", names)
	}
}

func TestProviderKeyIsClaimedByItsOwnRule(t *testing.T) {
	r := redact.Default()
	for _, f := range canary.Fakes() {
		if f.Rule != "anthropic-key" {
			continue
		}
		_, hits := r.String(f.Text)
		if hits["anthropic-key"] != 1 || hits["openai-key"] != 0 {
			t.Fatalf("an Anthropic key must not be counted as an OpenAI key: %v", hits)
		}
	}
}

func TestSecretAtTheEdgesOfTheText(t *testing.T) {
	r := redact.Default()
	var key canary.Fake
	for _, f := range canary.Fakes() {
		if f.Rule == "xai-key" {
			key = f
		}
	}
	for _, text := range []string{key.Secret, "\n" + key.Secret, key.Secret + "\n", "(" + key.Secret + ")"} {
		out, hits := r.String(text)
		if strings.Contains(out, key.Secret) || hits["xai-key"] != 1 {
			t.Errorf("%q -> %q (%v)", text, out, hits)
		}
	}
}

func TestATruncatedPrivateKeyIsStillRemoved(t *testing.T) {
	r := redact.Default()
	var pk canary.Fake
	for _, f := range canary.Fakes() {
		if f.Rule == "private-key" {
			pk = f
		}
	}
	cut := pk.Text[:strings.Index(pk.Text, "\n-----END")] // the content cap cut it before the end line
	out, hits := r.String(cut)
	if hits["private-key"] != 1 || strings.Contains(out, pk.Secret[:60]) {
		t.Fatalf("truncated key not removed: %v %q", hits, out)
	}
}

func TestCustomRules(t *testing.T) {
	r := redact.New(nil)
	if out, h := r.String("anything"); out != "anything" || h != nil {
		t.Fatalf("an empty rule set must change nothing: %q %v", out, h)
	}
}

func TestRuleNamesEndWithTheKeyNameRule(t *testing.T) {
	names := redact.Default().RuleNames()
	if names[len(names)-1] != redact.KeyNameRuleName {
		t.Fatalf("names = %v", names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("duplicate name %q", n)
		}
		seen[n] = true
	}
}

package redact

import "regexp"

// secretNameCore matches the name of a variable, header or flag that holds a secret: it must END with
// the sensitive word, so "API_KEY" and "db_password" match but "input_tokens" does not. Rules put \b in
// front of it; the anchored twins used by the fast path check that boundary by hand.
const secretNameCore = `([A-Z0-9_]*(?:TOKEN|SECRET_?KEY|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?KEY|CREDENTIALS?))`

const secretName = `\b` + secretNameCore

// Text that has been through JSON escaping, or that sits in a shell string, spells a quote as \" or, one level
// deeper, as \\\". Every quote the rules look for may carry any number of backslashes in front, so that
// NAME=\"a value\" and \"api_key\": \"v\" are read like NAME="a value" and "api_key": "v". With no backslash the
// patterns match exactly what they matched before.
const (
	optQuote = `(?:\\*["'])?` // the quote a name may be followed by, as in "api_key": or api_key=
	dquote   = `\\*"`
	squote   = `\\*'`
)

func rx(p string) *regexp.Regexp { return regexp.MustCompile(p) }

// envNeedles are literals that every env-secret match contains, lower-case: the sensitive words and
// their shortest distinguishing prefixes ("passw" is password and passwd, "secret" is secret and secret_key).
var envNeedles = []string{"token", "secret", "passw", "credential", "apikey", "api_key", "accesskey", "access_key",
	"privatekey", "private_key", "authkey", "auth_key"}

var flagNeedles = []string{"token", "secret", "passw", "apikey", "api-key", "accesskey", "access-key", "authkey", "auth-key"}

// What follows the name in the three env-secret rules: the separator (group 2), the opening quote (3, empty for a
// bare value), the value (4) and the closing quote (5). A quoted value is 4 to 300 characters and does not end in a
// backslash: the backslashes in front of the closing quote belong to the quote, they stay in the text and they cannot
// be counted as part of a value that would otherwise be too short.
const (
	envDouble = `(` + optQuote + `\s*[=:]\s*)(` + dquote + `)([^"\n]{3,299}[^"\n\\])(` + dquote + `)`
	envSingle = `(` + optQuote + `\s*[=:]\s*)(` + squote + `)([^'\n]{3,299}[^'\n\\])(` + squote + `)`
	envBare   = `(` + optQuote + `\s*[=:]\s*)()([^\s"'\x60,;)}\]]{6,})`
)

// envFast is the fast path of one of the three env-secret rules: sep is the pattern after the name.
func envFast(sep string) *fastPath {
	return &fastPath{needles: envNeedles, fold: true, caseInsensitive: true, group: 1, start: startAtWordRun,
		anch: rx(`(?i)\A` + secretNameCore + sep)}
}

// authHeader is the auth-header pattern after its word boundary: the name with the scheme (group 1) and the credential (2).
const authHeader = `(authorization` + optQuote + `\s*[:=]\s*` + optQuote + `(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})`

// flagBody is the flag-secret pattern, with the optional quote of the value in group 2.
const flagBody = `(\s--?(?:[a-z0-9]+-)*(?:token|password|passwd|secret|api-?key|access-?key|auth-?key)\s+)(` + optQuote + `)([^\s"']{6,})`

// DefaultRules returns the built-in rules, most specific first. The order matters: a provider key
// is claimed by its own rule before a generic one can see it.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "private-key", Re: rx(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`),
			Template: "[REDACTED:private-key]", Hints: []string{"PRIVATE KEY-----"}},
		{Name: "anthropic-key", Re: rx(`\bsk-ant-[A-Za-z0-9_-]{16,}`),
			Template: "[REDACTED:anthropic-key]", Hints: []string{"sk-ant-"}},
		{Name: "openai-key", Re: rx(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`),
			Template: "[REDACTED:openai-key]", Hints: []string{"sk-"},
			fast: &fastPath{needles: []string{"sk-"}, boundary: true, start: startAtHit,
				anch: rx(`\Ask-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)}},
		{Name: "xai-key", Re: rx(`\bxai-[A-Za-z0-9]{20,}`),
			Template: "[REDACTED:xai-key]", Hints: []string{"xai-"}},
		{Name: "google-api-key", Re: rx(`\bAIza[0-9A-Za-z_-]{35}`),
			Template: "[REDACTED:google-api-key]", Hints: []string{"AIza"}},
		{Name: "github-token", Re: rx(`\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{50,255})`),
			Template: "[REDACTED:github-token]", Hints: []string{"gh", "github_pat_"}},
		{Name: "aws-access-key", Re: rx(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b`),
			Template: "[REDACTED:aws-access-key]", Hints: []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA"}},
		{Name: "slack-token", Re: rx(`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
			Template: "[REDACTED:slack-token]", Hints: []string{"xox"}},
		{Name: "stripe-key", Re: rx(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`),
			Template: "[REDACTED:stripe-key]", Hints: []string{"k_live_", "k_test_"}},
		{Name: "jwt", Re: rx(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
			Template: "[REDACTED:jwt]", Hints: []string{"eyJ"}},
		{Name: "auth-header", Re: rx(`(?i)\b` + authHeader),
			Template: "${1}[REDACTED:auth-header]", Guard: 2,
			fast: &fastPath{needles: []string{"authorization"}, fold: true, caseInsensitive: true, boundary: true, start: startAtHit,
				anch: rx(`(?i)\A` + authHeader)}},
		{Name: "url-credentials", Re: rx(`(?i)\b([a-z][a-z0-9+.-]{1,15}://)([^/\s:@"']+):([^/\s@"']+)@`),
			Template: "${1}${2}:[REDACTED:url-credentials]@", Guard: 3, Hints: []string{"://"},
			fast: &fastPath{needles: []string{"://"}, caseInsensitive: true, boundary: true, start: startAtScheme,
				anch: rx(`(?i)\A([a-z][a-z0-9+.-]{1,15}://)([^/\s:@"']+):([^/\s@"']+)@`)}},
		// A quoted value may hold spaces, so the quoted forms run before the bare one.
		{Name: "env-secret", Re: rx(`(?i)` + secretName + envDouble),
			Template: `${1}${2}${3}[REDACTED:env-secret]${5}`, Guard: 4,
			fast: envFast(envDouble)},
		{Name: "env-secret", Re: rx(`(?i)` + secretName + envSingle),
			Template: `${1}${2}${3}[REDACTED:env-secret]${5}`, Guard: 4,
			fast: envFast(envSingle)},
		{Name: "env-secret", Re: rx(`(?i)` + secretName + envBare),
			Template: `${1}${2}${3}[REDACTED:env-secret]`, Guard: 4,
			fast: envFast(envBare)},
		// "--password hunter2": the flag form with a space, which the rules above do not see.
		{Name: "flag-secret", Re: rx(`(?i)` + flagBody),
			Template: `${1}${2}[REDACTED:flag-secret]`, Guard: 3,
			fast: &fastPath{needles: flagNeedles, fold: true, caseInsensitive: true, start: startAtFlag,
				anch: rx(`(?i)\A` + flagBody)}},
	}
}

// referenceRules are the default rules without their fast paths: every rule is its regular expression over
// the whole text. Tests hold the fast path to what these return.
func referenceRules() []Rule {
	rules := DefaultRules()
	for i := range rules {
		rules[i].fast = nil
	}
	return rules
}

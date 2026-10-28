package redact

import "regexp"

// secretName matches the name of a variable, header or flag that holds a secret: it must END with
// the sensitive word, so "API_KEY" and "db_password" match but "input_tokens" does not.
const secretName = `\b([A-Z0-9_]*(?:TOKEN|SECRET_?KEY|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|AUTH_?KEY|CREDENTIALS?))`

func rx(p string) *regexp.Regexp { return regexp.MustCompile(p) }

// DefaultRules returns the built-in rules, most specific first. The order matters: a provider key
// is claimed by its own rule before a generic one can see it.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "private-key", Re: rx(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`),
			Template: "[REDACTED:private-key]", Hints: []string{"PRIVATE KEY-----"}},
		{Name: "anthropic-key", Re: rx(`\bsk-ant-[A-Za-z0-9_-]{16,}`),
			Template: "[REDACTED:anthropic-key]", Hints: []string{"sk-ant-"}},
		{Name: "openai-key", Re: rx(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`),
			Template: "[REDACTED:openai-key]", Hints: []string{"sk-"}},
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
		{Name: "auth-header", Re: rx(`(?i)(\bauthorization["']?\s*[:=]\s*["']?(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})`),
			Template: "${1}[REDACTED:auth-header]", Guard: 2},
		{Name: "url-credentials", Re: rx(`(?i)\b([a-z][a-z0-9+.-]{1,15}://)([^/\s:@"']+):([^/\s@"']+)@`),
			Template: "${1}${2}:[REDACTED:url-credentials]@", Guard: 3, Hints: []string{"://"}},
		// A quoted value may hold spaces, so the quoted forms run before the bare one.
		{Name: "env-secret", Re: rx(`(?i)` + secretName + `(["']?\s*[=:]\s*)(")([^"\n]{4,300})(")`),
			Template: `${1}${2}${3}[REDACTED:env-secret]${5}`, Guard: 4},
		{Name: "env-secret", Re: rx(`(?i)` + secretName + `(["']?\s*[=:]\s*)(')([^'\n]{4,300})(')`),
			Template: `${1}${2}${3}[REDACTED:env-secret]${5}`, Guard: 4},
		{Name: "env-secret", Re: rx(`(?i)` + secretName + `(["']?\s*[=:]\s*)()([^\s"'\x60,;)}\]]{6,})`),
			Template: `${1}${2}${3}[REDACTED:env-secret]`, Guard: 4},
		// "--password hunter2": the flag form with a space, which the rules above do not see.
		{Name: "flag-secret", Re: rx(`(?i)(\s--?(?:[a-z0-9]+-)*(?:token|password|passwd|secret|api-?key|access-?key|auth-?key)\s+)(["']?)([^\s"']{6,})`),
			Template: `${1}${2}[REDACTED:flag-secret]`, Guard: 3},
	}
}

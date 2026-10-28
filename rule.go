// Package redact removes secrets from text and JSON before they are stored.
//
// It is built for one job: text written by coding agents (prompts, shell commands, tool output,
// whole session records) must not carry a key into a shared store. It prefers a false positive
// to a leak, never reads the network, and never fails on input it does not understand: text it
// has no rule for passes through unchanged.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder is what replaces a secret: "[REDACTED:" + rule name + "]".
const placeholderPrefix = "[REDACTED:"

func placeholder(rule string) string { return placeholderPrefix + rule + "]" }

// Rule finds one kind of secret and says what to keep of the match.
type Rule struct {
	// Name appears in the placeholder and in the hit counts, for example "anthropic-key".
	Name string
	// Re finds the secret. A rule that must keep surrounding text (a variable name, a URL scheme)
	// captures it in groups and repeats those groups in Template.
	Re *regexp.Regexp
	// Template is an expansion template for the replacement, as in Regexp.Expand. It must hold
	// the placeholder for Name, usually "${1}[REDACTED:name]".
	Template string
	// Hints are cheap literal pre-checks: when set, Re only runs on text that contains at least
	// one of them. Leave empty for rules that cannot be pre-checked.
	Hints []string
	// Guard is the capture group that holds the secret itself (0 means the whole match). A match
	// whose secret already is a placeholder is left alone, which keeps Redact idempotent.
	Guard int

	// fast, set on built-in rules only, finds the same matches quicker (see fast.go). Re stays the
	// definition of the rule and is what the differential test compares the fast path with.
	fast *fastPath
}

func (r Rule) mayMatch(s string) bool {
	if len(r.Hints) == 0 {
		return true
	}
	for _, h := range r.Hints {
		if strings.Contains(s, h) {
			return true
		}
	}
	return false
}

// apply replaces every match in s and returns the new text and how many matches it replaced.
func (r Rule) apply(s string, sc *scratch) (string, int) {
	if !r.mayMatch(s) {
		return s, 0
	}
	if r.fast != nil {
		if out, n, ok := r.applyFast(s, sc); ok {
			return out, n
		}
	}
	return r.applyRegex(s)
}

// applyRegex is apply done the plain way: the rule's regular expression over the whole text.
func (r Rule) applyRegex(s string) (string, int) {
	locs := r.Re.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s, 0
	}
	var b strings.Builder
	last, n := 0, 0
	for _, loc := range locs {
		g := r.Guard * 2
		if g+1 < len(loc) && loc[g] >= 0 && strings.HasPrefix(s[loc[g]:loc[g+1]], placeholderPrefix) {
			continue
		}
		b.WriteString(s[last:loc[0]])
		b.Write(r.Re.ExpandString(nil, r.Template, s, loc))
		last = loc[1]
		n++
	}
	if n == 0 {
		return s, 0
	}
	b.WriteString(s[last:])
	return b.String(), n
}

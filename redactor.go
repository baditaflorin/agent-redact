package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Hits counts how many secrets each rule replaced. A nil Hits means nothing was replaced.
type Hits map[string]int

// Total is the number of secrets replaced.
func (h Hits) Total() int {
	t := 0
	for _, n := range h {
		t += n
	}
	return t
}

// Names returns the rule names that fired, sorted.
func (h Hits) Names() []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func (h Hits) add(rule string, n int) Hits {
	if n == 0 {
		return h
	}
	if h == nil {
		h = Hits{}
	}
	h[rule] += n
	return h
}

// Merge adds other's counts into h and returns it (allocating when h is nil and other is not).
func (h Hits) Merge(other Hits) Hits {
	for k, n := range other {
		h = h.add(k, n)
	}
	return h
}

// KeyNameRuleName is the rule name reported when a JSON value is redacted because of its key.
const KeyNameRuleName = "key-name"

// keyName matches an object key that holds a secret, after the key is lower-cased and stripped of
// '_', '-', '.' and spaces. It must END with the sensitive word, so "access_token" and "apiKey"
// match but "input_tokens" and "tokenizer" do not.
var keyName = regexp.MustCompile(`(password|passwd|secret|token|apikey|accesskey|privatekey|authkey|authorization|credential|credentials|cookie|setcookie)$`)

// Redactor applies a fixed rule set. It is safe for concurrent use.
type Redactor struct {
	rules []Rule
}

// New returns a Redactor for the given rules, applied in order.
func New(rules []Rule) *Redactor { return &Redactor{rules: append([]Rule(nil), rules...)} }

// Default returns a Redactor with DefaultRules.
func Default() *Redactor { return New(DefaultRules()) }

// RuleNames lists the distinct rule names, plus the JSON key-name rule, in order.
func (r *Redactor) RuleNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, ru := range r.rules {
		if !seen[ru.Name] {
			seen[ru.Name] = true
			names = append(names, ru.Name)
		}
	}
	return append(names, KeyNameRuleName)
}

// maxPasses bounds how often String repeats itself on its own output.
const maxPasses = 5

// String redacts s. It returns s itself, unchanged, when nothing matched.
//
// It repeats until a pass finds nothing more, so that redacting its own output changes nothing: a first pass
// can shorten the text (a long secret inside a quoted value becomes a short placeholder) and so let a
// length-limited rule match the value around it on the next. Text with no secret costs one pass.
func (r *Redactor) String(s string) (string, Hits) {
	var hits Hits
	for pass := 0; pass < maxPasses; pass++ {
		out, h := r.pass(s)
		if len(h) == 0 {
			break
		}
		s = out
		hits = hits.Merge(h)
	}
	return s, hits
}

// pass applies every rule once, in order.
func (r *Redactor) pass(s string) (string, Hits) {
	var hits Hits
	var sc scratch
	for _, ru := range r.rules {
		var n int
		s, n = ru.apply(s, &sc)
		if n > 0 {
			sc = scratch{} // the text changed: what was worked out about it no longer holds
		}
		hits = hits.add(ru.Name, n)
	}
	return s, hits
}

var keyStrip = strings.NewReplacer("_", "", "-", "", ".", "", " ", "")

func isSecretKey(key string) bool {
	return keyName.MatchString(keyStrip.Replace(strings.ToLower(key)))
}

// value redacts one JSON string value, given the key it sits under ("" for an array element or a
// top-level string).
func (r *Redactor) value(key, s string) (string, Hits) {
	if key != "" && s != "" && !strings.HasPrefix(s, placeholderPrefix) && isSecretKey(key) {
		return placeholder(KeyNameRuleName), Hits{KeyNameRuleName: 1}
	}
	return r.String(s)
}

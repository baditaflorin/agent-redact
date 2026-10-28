package redact

import (
	"encoding/json"
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
// match but "input_tokens" and "tokenizer" do not. The words are the ones the text rules know (so SECRET_KEY is here as
// well as api_key) plus the JSON-only ones; each was checked against the key names of real session records, and a word
// that real records use for something harmless is not here: "sessionid", "session_key" (an identifier), "pwd" (the
// working directory) and "pass".
var keyName = regexp.MustCompile(`(password|passwd|passphrase|secret|secretkey|token|apikey|accesskey|privatekey|authkey|signingkey|encryptionkey|masterkey|authorization|credential|credentials|cookie|setcookie)$`)

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

// maxNesting is how many levels of "a JSON document held in a string" JSON follows. Real records go three
// deep at most; the bound keeps the work on a hostile document to a small multiple of its size, because
// every level re-reads the string it opened.
const maxNesting = 4

// value redacts one JSON string value, given the key it sits under ("" for an array element or a
// top-level string) and the nesting depth of the document it is in.
func (r *Redactor) value(key, s string, depth int) (string, Hits) {
	if key != "" && s != "" && !strings.HasPrefix(s, placeholderPrefix) && isSecretKey(key) {
		return placeholder(KeyNameRuleName), Hits{KeyNameRuleName: 1}
	}
	var hits Hits
	// the document goes first: read as JSON its quotes are real, and a rule that spans the whole text
	// (a private key cut off before its end line) cannot cut the document's own structure
	if depth < maxNesting && mayBeDocument(s) {
		if inner, h, ok := r.document(s, depth+1); ok {
			s, hits = inner, h
		}
	}
	out, h := r.String(s)
	return out, hits.Merge(h)
}

// mayBeDocument is the cheap test that keeps ordinary strings out of the JSON parser: after JSON white
// space the string opens an object or an array, and it holds a quote (a document with no string in it has
// nothing to redact).
func mayBeDocument(s string) bool {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	if i == len(s) || (s[i] != '{' && s[i] != '[') {
		return false
	}
	return strings.IndexByte(s[i:], '"') >= 0
}

// document redacts s as a JSON document at the given depth. ok is true only when s is exactly one valid
// JSON value and something in it was redacted; inner is then the document re-written compact.
func (r *Redactor) document(s string, depth int) (inner string, hits Hits, ok bool) {
	b := []byte(s)
	if !json.Valid(b) {
		return "", nil, false
	}
	out, hits, err := r.walk(b, depth)
	if err != nil || hits.Total() == 0 {
		return "", nil, false
	}
	return string(out), hits, true
}

package redact

import (
	"regexp"
	"sort"
	"strings"
)

// The slow rules (env-secret, flag-secret, auth-header, url-credentials, openai-key) used to run their
// regular expression over the whole text. Go's engine is slow on patterns that start with a character
// class or a case-insensitive word, so those rules dominated the cost: about 3 MB/s each on agent text.
//
// The fast path finds the places a match could be with a plain literal search, then runs the SAME
// regular expression, anchored, at the one or few offsets where a match could start. It returns exactly
// what the whole-text search returns (a differential test and a fuzz target hold it to that); it is only
// quicker because it never feeds the engine the text between candidates.

// fastPath is attached to a built-in Rule. It never changes what the rule matches.
type fastPath struct {
	// needles are literals every match contains. With fold they are lower-case ASCII and are looked
	// for case-insensitively; without it they are matched as written.
	needles []string
	fold    bool
	// caseInsensitive: the pattern is (?i). Go folds U+017F and U+212A onto s and k there, characters that are
	// not ASCII word bytes, which the hand-written start and boundary logic does not model: a text holding one
	// goes through the plain regular expression (see exoticFold). Set it for every (?i) rule.
	caseInsensitive bool
	// group, when non-zero, names a set of rules with the same needles: while the text is unchanged they
	// share one search (the three env-secret rules, which run one after the other on mostly unchanged text).
	group int
	// boundary: the pattern begins with \b, which an anchored match on a substring cannot see, so it is
	// checked by hand: the byte before the start must not be a word byte.
	boundary bool
	// start calls try with every offset at which a match containing the hit at offset hit could begin,
	// in increasing order, until try reports that it matched.
	start func(s string, hit int, try func(st int) bool)
	// anch is the rule's pattern anchored at the start offset, with the same capture groups as Re.
	anch *regexp.Regexp
}

// scratch holds what the rules of one String call can share. It describes one text: reset it whenever
// a rule changes the text.
type scratch struct {
	lower      string
	haveLower  bool
	exotic     bool
	haveExotic bool
	groupHits  [4][]int
	haveGroup  [4]bool
}

// exoticFold reports whether s holds a character that Go's case-insensitive matching folds onto an
// ASCII letter although it is not one: U+017F (long s) onto s and U+212A (Kelvin sign) onto k. The
// fast path models ASCII folding only, so such a text goes through the regular expression instead.
func (sc *scratch) exoticFold(s string) bool {
	if !sc.haveExotic {
		sc.exotic = strings.Contains(s, "\xc5\xbf") || strings.Contains(s, "\xe2\x84\xaa")
		sc.haveExotic = true
	}
	return sc.exotic
}

// lowered is s with ASCII capitals lower-cased and every other byte untouched, so offsets in it are
// offsets in s. It is s itself when there is nothing to change.
func (sc *scratch) lowered(s string) string {
	if sc.haveLower {
		return sc.lower
	}
	sc.haveLower = true
	sc.lower = s
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if c := b[j]; c >= 'A' && c <= 'Z' {
					b[j] = c + 'a' - 'A'
				}
			}
			sc.lower = string(b)
			break
		}
	}
	return sc.lower
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isRE2Space is what \s means to Go's regexp: space, tab, newline, form feed, carriage return.
func isRE2Space(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isFlagByte(c byte) bool {
	return c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// hits returns the offsets of every needle occurrence in s, in increasing order.
func (f *fastPath) hits(s string, sc *scratch) []int {
	if f.group != 0 && sc.haveGroup[f.group] {
		return sc.groupHits[f.group]
	}
	hits := f.search(s, sc)
	if f.group != 0 {
		sc.groupHits[f.group], sc.haveGroup[f.group] = hits, true
	}
	return hits
}

func (f *fastPath) search(s string, sc *scratch) []int {
	hay := s
	if f.fold {
		hay = sc.lowered(s)
	}
	var hits []int
	for _, nd := range f.needles {
		for from := 0; from < len(hay); {
			i := strings.Index(hay[from:], nd)
			if i < 0 {
				break
			}
			hits = append(hits, from+i)
			from += i + 1
		}
	}
	if len(f.needles) > 1 && len(hits) > 1 {
		sort.Ints(hits)
	}
	return hits
}

// applyFast is apply for a rule with a fastPath. handled is false when the text needs the plain regular
// expression (see exoticFold).
func (r Rule) applyFast(s string, sc *scratch) (out string, n int, handled bool) {
	f := r.fast
	if f.caseInsensitive && sc.exoticFold(s) {
		return s, 0, false
	}
	hits := f.hits(s, sc)
	if len(hits) == 0 {
		return s, 0, true
	}
	var b strings.Builder
	last, pos, lastTried := 0, 0, -1
	try := func(st int) bool {
		if st < pos || st == lastTried {
			return false
		}
		lastTried = st
		if f.boundary && st > 0 && isWordByte(s[st-1]) {
			return false
		}
		loc := f.anch.FindStringSubmatchIndex(s[st:])
		if loc == nil {
			return false
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += st
			}
		}
		pos = loc[1] // the match is consumed even when the guard leaves it alone
		g := r.Guard * 2
		if g+1 < len(loc) && loc[g] >= 0 && leaveAlone(s[loc[g]:loc[g+1]]) {
			return true
		}
		b.WriteString(s[last:loc[0]])
		b.Write(f.anch.ExpandString(nil, r.Template, s, loc))
		last = loc[1]
		n++
		return true
	}
	for _, h := range hits {
		f.start(s, h, try)
	}
	if n == 0 {
		return s, 0, true
	}
	b.WriteString(s[last:])
	return b.String(), n, true
}

// start functions

func startAtHit(_ string, hit int, try func(int) bool) { try(hit) }

// startAtWordRun: the match begins where the run of word bytes holding the hit begins.
func startAtWordRun(s string, hit int, try func(int) bool) {
	i := hit
	for i > 0 && isWordByte(s[i-1]) {
		i--
	}
	try(i)
}

// startAtFlag: "--name value" begins at the white space before the dashes.
func startAtFlag(s string, hit int, try func(int) bool) {
	i := hit
	for i > 0 && isFlagByte(s[i-1]) {
		i--
	}
	if i > 0 && isRE2Space(s[i-1]) {
		try(i - 1)
	}
}

// startAtScheme: the scheme is 2 to 16 bytes before "://"; try them left to right, as the leftmost match wins.
func startAtScheme(s string, hit int, try func(int) bool) {
	if !hasUserinfo(s, hit+3) {
		return
	}
	lo := hit - 16
	if lo < 0 {
		lo = 0
	}
	for st := lo; st <= hit-2; st++ {
		if try(st) {
			return
		}
	}
}

// hasUserinfo is a necessary condition for "user:password@" at offset from: the run of bytes that are not
// '/', white space, '@' or a quote must hold a ':' and end at an '@'.
func hasUserinfo(s string, from int) bool {
	colon := false
	for j := from; j < len(s); j++ {
		switch c := s[j]; {
		case c == '@':
			return colon
		case c == ':':
			colon = true
		case c == '/' || c == '"' || c == '\'' || isRE2Space(c):
			return false
		}
	}
	return false
}

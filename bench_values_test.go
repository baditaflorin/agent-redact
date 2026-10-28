package redact

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// valueTexts puts a credential into every fourth corpus string, in the forms the length and backslash changes touch: a
// quoted value of 1000 characters, a bare value that ends in the backslash of an escaped closing quote, and a header.
func valueTexts(strs []string) ([]string, int) {
	r := rand.New(rand.NewSource(9))
	out := make([]string, len(strs))
	total := 0
	for i, s := range strs {
		if i%4 == 0 {
			switch (i / 4) % 3 {
			case 0:
				s += fmt.Sprintf("\nexport APP_TOKEN=\"%s\"\n", benchAlnum(r, 1000))
			case 1:
				s += fmt.Sprintf("\n{\\\"cmd\\\":\\\"export APP_PASSWORD=%s\\\"}\n", benchAlnum(r, 24))
			default:
				s += fmt.Sprintf("\nCookie: sid=%s; theme=dark; lang=en\n", benchAlnum(r, 40))
			}
		}
		out[i] = s
		total += len(s)
	}
	return out, total
}

// BenchmarkValuesTheLimitsTouch is String on text where a quarter of the strings hold such a credential. v0.1.2 let the
// 1000-character value and the cookie through, so the number is the cost of finding them as well.
func BenchmarkValuesTheLimitsTouch(b *testing.B) {
	strs, _ := benchCorpus(benchCorpusBytes, 1)
	texts, total := valueTexts(strs)
	r := Default()
	b.SetBytes(int64(total))
	found := 0
	for n := 0; n < b.N; n++ {
		found = 0
		for _, s := range texts {
			if out, _ := r.String(s); strings.Contains(out, "[REDACTED:") {
				found++
			}
		}
	}
	b.ReportMetric(float64(found), "redacted_strings")
}

package redact

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

// The corpus imitates what a coding agent leaves behind, calibrated on a bounded sample of real
// session text (counts only, nothing from it is kept): string sizes are log-normal with a median of
// about 265 bytes, a p90 of about 2 KB and a p99 of about 11 KB, and the words that tempt a secret
// rule ("token", "secret", "password", "api key", "authorization", "credential", URLs) occur at
// about the density the sample showed. It is generated, so no real text is in the repository.

var benchWords = strings.Fields(`the a of and to in is for that with this as on it be are from or by an at not have but
	function returns error if err != nil return config server request response docker compose up -d git commit -m fix test
	file path line 42 200 OK json true false null import package func var const type struct interface string int bool
	context http handler middleware database query SELECT FROM WHERE INSERT INTO migration deploy build run pass fail
	warning info debug cache retry timeout worker queue batch session agent prompt reply tool call result output stdout
	/home/dev/src/app/main.go ./cmd/server --flag value --verbose -v ls -la cd .. grep -rn TODO make all npm run build
	{ } [ ] "name": "value": "id": 1 2 3 0.5 true ok done`)

// trigger words with their density per MB in the sample
var benchTriggers = []struct {
	text    string
	perMB   float64
	assigns bool // may appear as NAME=value or "name": "value"
}{
	{"token", 220, true}, {"secret", 117, true}, {"password", 22, true}, {"credential", 25, true},
	{"apikey", 44, true}, {"api_key", 31, true}, {"api-key", 12, false}, {"authorization", 16, true},
	{"bearer", 17, false}, {"task-force", 62, false}, {"https://example.com/docs/page", 497, false},
}

func benchString(r *rand.Rand, size int) string {
	var b strings.Builder
	b.Grow(size + 64)
	for b.Len() < size {
		b.WriteString(benchWords[r.Intn(len(benchWords))])
		if r.Intn(14) == 0 {
			b.WriteByte('\n')
		} else {
			b.WriteByte(' ')
		}
	}
	s := b.String()
	// sprinkle trigger words so that their density per MB matches the sample
	for _, t := range benchTriggers {
		expected := t.perMB * float64(len(s)) / 1e6
		n := int(expected)
		if r.Float64() < expected-float64(n) {
			n++
		}
		for i := 0; i < n; i++ {
			pos := r.Intn(len(s) + 1)
			ins := t.text
			switch k := r.Intn(10); {
			case t.assigns && k < 2: // a short value: not a secret, still tempts the rule
				ins = fmt.Sprintf("%s: %d", strings.ToUpper(t.text), r.Intn(9999))
			case t.assigns && k == 2: // a real-looking assignment
				ins = fmt.Sprintf("%s_%s=%s", "APP", strings.ToUpper(strings.NewReplacer("-", "_").Replace(t.text)), benchAlnum(r, 20))
			}
			s = s[:pos] + " " + ins + " " + s[pos:]
		}
	}
	return s
}

func benchAlnum(r *rand.Rand, n int) string {
	const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.Intn(len(a))]
	}
	return string(b)
}

// benchCorpus returns strings totalling about totalBytes, sizes drawn from the sample's distribution.
func benchCorpus(totalBytes int, seed int64) (strs []string, total int) {
	r := rand.New(rand.NewSource(seed))
	const mu, sigma = 5.58, 1.6 // ln(265), fitted to p90 = 2 KB
	for total < totalBytes {
		size := int(math.Exp(mu + sigma*r.NormFloat64()))
		if size < 8 {
			size = 8
		}
		if size > 60000 {
			size = 60000
		}
		s := benchString(r, size)
		strs = append(strs, s)
		total += len(s)
	}
	return strs, total
}

const benchCorpusBytes = 3 << 20

func BenchmarkCorpusShape(b *testing.B) { // not a speed test: prints what the corpus looks like
	strs, total := benchCorpus(benchCorpusBytes, 1)
	hits := map[string]int{}
	for _, s := range strs {
		_, h := Default().String(s)
		for k, n := range h {
			hits[k] += n
		}
	}
	b.Logf("%d strings, %.2f MB, mean %d B; redactions found: %v", len(strs), float64(total)/1e6, total/len(strs), hits)
}

// BenchmarkRule times every default rule alone over the corpus: the table that says where the time goes.
func BenchmarkRule(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	for i, rule := range DefaultRules() {
		b.Run(fmt.Sprintf("%02d-%s", i, rule.Name), func(b *testing.B) {
			b.SetBytes(int64(total))
			for n := 0; n < b.N; n++ {
				for _, s := range strs {
					var sc scratch
					rule.apply(s, &sc)
				}
			}
		})
	}
}

func BenchmarkString(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	r := Default()
	b.SetBytes(int64(total))
	for n := 0; n < b.N; n++ {
		for _, s := range strs {
			r.String(s)
		}
	}
}

// BenchmarkJSON wraps each string in an event-shaped JSON record, which is what the collector redacts as raw.
func BenchmarkJSON(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	docs := make([][]byte, len(strs))
	var sb strings.Builder
	for i, s := range strs {
		sb.Reset()
		sb.WriteString(`{"type":"assistant","uuid":"8f3c2f9e-1a64-4a43-9f3b-0c1d5a7e2b10","message":{"role":"assistant","content":[{"type":"text","text":`)
		writeJSONString(&sb, s)
		sb.WriteString(`}],"usage":{"input_tokens":120,"output_tokens":45}}}`)
		docs[i] = []byte(sb.String())
	}
	r := Default()
	b.SetBytes(int64(total))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, d := range docs {
			if _, _, err := r.JSON(d); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func writeJSONString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		default:
			sb.WriteRune(c)
		}
	}
	sb.WriteByte('"')
}

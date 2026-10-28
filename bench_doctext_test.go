package redact

import (
	"strings"
	"testing"
)

// stringReadingDocuments is the prototype behind the decision NOT to make String parse text that is a JSON document:
// it tries a document first, as JSON does for a string value, and falls back to the text rules.
func (r *Redactor) stringReadingDocuments(s string) (string, Hits) {
	var hits Hits
	if mayBeDocument(s) {
		if inner, h, ok := r.document(s, 1); ok {
			s, hits = inner, h
		}
	}
	out, h := r.String(s)
	return out, hits.Merge(h)
}

func documentTexts(strs []string) []string {
	docs := make([]string, len(strs))
	var sb strings.Builder
	for i, s := range strs {
		sb.Reset()
		sb.WriteString(`{"cmd":`)
		writeJSONString(&sb, s)
		sb.WriteString(`,"workdir":"/home/dev/src/app"}`)
		docs[i] = sb.String()
	}
	return docs
}

// the two ways to redact text that is a JSON document, on text where every string is one, and on the plain corpus
func BenchmarkStringOnDocumentText(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	docs := documentTexts(strs)
	r := Default()
	b.Run("text-rules-only", func(b *testing.B) {
		b.SetBytes(int64(total))
		for n := 0; n < b.N; n++ {
			for _, d := range docs {
				r.String(d)
			}
		}
	})
	b.Run("read-as-document-first", func(b *testing.B) {
		b.SetBytes(int64(total))
		for n := 0; n < b.N; n++ {
			for _, d := range docs {
				r.stringReadingDocuments(d)
			}
		}
	})
}

func BenchmarkStringOnPlainTextWithTheDocumentCheck(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	r := Default()
	b.Run("text-rules-only", func(b *testing.B) {
		b.SetBytes(int64(total))
		for n := 0; n < b.N; n++ {
			for _, s := range strs {
				r.String(s)
			}
		}
	})
	b.Run("read-as-document-first", func(b *testing.B) {
		b.SetBytes(int64(total))
		for n := 0; n < b.N; n++ {
			for _, s := range strs {
				r.stringReadingDocuments(s)
			}
		}
	})
}

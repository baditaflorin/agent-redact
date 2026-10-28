package redact

import (
	"strings"
	"testing"
)

// nestedRecords wraps every corpus string the way a coding agent stores a tool call: the text is the "cmd" of a
// document that is itself the "arguments" string of a record.
func nestedRecords(strs []string) [][]byte {
	docs := make([][]byte, len(strs))
	var inner, sb strings.Builder
	for i, s := range strs {
		inner.Reset()
		inner.WriteString(`{"cmd":`)
		writeJSONString(&inner, s)
		inner.WriteString(`,"workdir":"/home/dev/src/app"}`)
		sb.Reset()
		sb.WriteString(`{"type":"response_item","payload":{"type":"function_call","name":"shell","arguments":`)
		writeJSONString(&sb, inner.String())
		sb.WriteString(`,"call_id":"call_8f3c2f9e"}}`)
		docs[i] = []byte(sb.String())
	}
	return docs
}

// BenchmarkJSONNested is BenchmarkJSON with every string held in a document inside a string, the worst case for the
// nested path: every record is read as JSON twice. MB/s is megabytes of the corpus text, as in BenchmarkJSON.
func BenchmarkJSONNested(b *testing.B) {
	strs, total := benchCorpus(benchCorpusBytes, 1)
	docs := nestedRecords(strs)
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

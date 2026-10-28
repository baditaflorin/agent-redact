package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

var (
	errNoValue  = errors.New("redact: input holds no JSON value")
	errTwoValue = errors.New("redact: input holds more than one JSON value")
)

type frame struct {
	obj bool
	n   int    // tokens written inside this container so far (keys and values both count)
	key string // the key whose value is being written, when obj
}

// JSON redacts every string value in a JSON document and returns the document compacted, with
// its keys in their original order and its numbers exactly as written. A string under a key that
// names a secret ("password", "access_token", "Authorization", ...) is replaced whole; every
// other string goes through the rules. Keys themselves are left alone. Input that is not one
// valid JSON value is an error and nothing is returned: the caller decides what to do with text
// it cannot parse (agent-redact's CLI falls back to String).
func (r *Redactor) JSON(in []byte) ([]byte, Hits, error) {
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	var out bytes.Buffer
	out.Grow(len(in))
	var hits Hits
	var stack []frame
	done := false

	// sep writes whatever must precede the next token and reports whether that token is an
	// object key, and if it is a value, which key it belongs to.
	sep := func() (isKey bool, key string) {
		if len(stack) == 0 {
			return false, ""
		}
		f := &stack[len(stack)-1]
		defer func() { f.n++ }()
		if f.obj {
			if f.n%2 == 0 {
				if f.n > 0 {
					out.WriteByte(',')
				}
				return true, ""
			}
			out.WriteByte(':')
			return false, f.key
		}
		if f.n > 0 {
			out.WriteByte(',')
		}
		return false, ""
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if len(stack) == 0 && done {
			return nil, nil, errTwoValue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				sep()
				out.WriteByte(byte(t))
				stack = append(stack, frame{obj: t == '{'})
			default:
				stack = stack[:len(stack)-1]
				out.WriteByte(byte(t))
				done = len(stack) == 0
			}
		case string:
			isKey, key := sep()
			if isKey {
				stack[len(stack)-1].key = t
				writeString(&out, t)
				break
			}
			s, h := r.value(key, t)
			hits = hits.Merge(h)
			writeString(&out, s)
			done = len(stack) == 0
		case json.Number:
			sep()
			out.WriteString(t.String())
			done = len(stack) == 0
		case bool:
			sep()
			out.WriteString(strconv.FormatBool(t))
			done = len(stack) == 0
		case nil:
			sep()
			out.WriteString("null")
			done = len(stack) == 0
		}
	}
	if len(stack) != 0 {
		return nil, nil, io.ErrUnexpectedEOF // the decoder reports a document cut short as a plain EOF
	}
	if !done {
		return nil, nil, errNoValue
	}
	return out.Bytes(), hits, nil
}

// writeString writes s as a JSON string without HTML escaping, so that "<" and "&" stay readable.
func writeString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

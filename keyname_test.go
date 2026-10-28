package redact_test

import (
	"fmt"
	"strings"
	"testing"

	redact "github.com/baditaflorin/agent-redact"
	"github.com/baditaflorin/agent-redact/canary"
)

// Keys as they are written in real records, one per word the key-name rule knows. The last five words came with v0.1.3:
// SECRET_KEY (Django, Flask) was the one the text rules know and this rule did not.
var secretKeys = []string{
	"password", "DB_PASSWORD", "passwd", "secret", "client_secret", "token", "access_token", "refreshToken", "apiKey", "api_key", "API-KEY",
	"accessKey", "aws_secret_access_key", "privateKey", "private_key", "authKey", "Authorization", "credential", "credentials", "Cookie", "Set-Cookie",
	"SECRET_KEY", "secretKey", "secret-key", "Secret.Key", "app.secret_key", "SIGNING_KEY", "signingKey", "jwt_signing_key", "ENCRYPTION_KEY",
	"encryptionKey", "MASTER_KEY", "master-key", "passphrase", "ssh_passphrase", "PASSPHRASE",
}

// where a pair can sit: top level, in an array, deep in objects and arrays, in a document held in a string once and
// twice, in an array held in a string
func keyDocs(pair string) map[string]string {
	obj := `{"user":"ann",` + pair + `}`
	return map[string]string{
		"top level":              obj,
		"alone":                  `{` + pair + `}`,
		"array":                  `[` + obj + `]`,
		"deep":                   `{"a":[{"b":{"c":[` + obj + `]}}]}`,
		"held in a string":       `{"arguments":` + jstr(obj) + `}`,
		"held twice":             nest(obj, 2),
		"array held in a string": `{"arguments":` + jstr(`[`+obj+`]`) + `}`,
		"top-level string":       jstr(obj),
	}
}

func TestEveryKeyNameWordRedactsAtEveryLevel(t *testing.T) {
	r := redact.Default()
	const value = "abcdef123456"
	for _, key := range secretKeys {
		for where, doc := range keyDocs(jstr(key) + `:` + jstr(value)) {
			out, hits, err := r.JSON([]byte(doc))
			if err != nil || strings.Contains(string(out), value) || hits[redact.KeyNameRuleName] == 0 {
				t.Errorf("%s, %s: %s %v %v", key, where, out, hits, err)
			}
		}
	}
}

// Words that were looked at and left out: each is a key real records carry for something that is not a secret
// (session ids and the store's own session_key identifier, the shell's working directory "pwd", database keys).
func TestKeysThatAreNotSecretsAreLeftAlone(t *testing.T) {
	r := redact.Default()
	for _, key := range []string{
		"session_key", "sessionKey", "sessionid", "session_id", "primary_key", "sort_key", "cache_key", "foreign_key", "pwd", "bypass", "pass",
		"processid", "monkey", "keyboard", "public_key", "publickey", "ssh_key", "signing_key_id", "encryption_key_id", "master_key_id",
		"input_tokens", "tokenizer", "secrets_count", "passphrase_hint_shown", "key", "name",
	} {
		in := `{"user":"ann",` + jstr(key) + `:"abcdef123456"}`
		out, hits, err := r.JSON([]byte(in))
		if err != nil || string(out) != in || hits != nil {
			t.Errorf("%s: %s %v %v", key, out, hits, err)
		}
	}
}

// Every JSON canary, at the top level, in objects and arrays, and held in strings once and twice.
func TestJSONCanariesAtEveryLevel(t *testing.T) {
	r := redact.Default()
	n := 0
	for i, f := range canary.Fakes() {
		if !f.JSON {
			continue
		}
		n++
		for where, doc := range map[string]string{
			"raw":              f.Text,
			"in an array":      `[` + f.Text + `]`,
			"in an object":     `{"a":` + f.Text + `}`,
			"deep":             `{"a":[{"b":` + f.Text + `}]}`,
			"held in a string": `{"arguments":` + jstr(f.Text) + `}`,
			"held twice":       nest(f.Text, 2),
			"array of strings": `["x",` + jstr(f.Text) + `]`,
			"string in array":  `{"arguments":` + jstr(`[`+f.Text+`]`) + `}`,
		} {
			checkNested(t, r, f, fmt.Sprintf("%s/%s#%d", where, f.Rule, i), doc)
		}
	}
	if n < 2 {
		t.Fatalf("only %d JSON canaries", n)
	}
}

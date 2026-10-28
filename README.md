# agent-redact

Removes secrets from text and JSON before they are stored. Built for the text that coding agents leave
behind (prompts, shell commands, tool output, whole session records), where one pasted key would otherwise
land in a searchable archive.

- Go library and a small command line filter. Standard library only, no network, no state.
- Prefers a false positive to a leak. Text it has no rule for passes through unchanged.
- Idempotent: redacting redacted text changes nothing.
- JSON-aware: strings are redacted in place, keys stay in their original order, numbers stay as written,
  and a value under a key such as `password`, `access_token` or `Authorization` is replaced whole.

This is a safety net, not a guarantee. It catches the key formats and assignment patterns below; a secret
in a shape it does not know passes through. Keep the daily canary check (below) running.

## Command line

```
agent-redact [-mode text|json|ndjson] [-check] [-report] [FILE...]
```

| Flag | Meaning |
|---|---|
| `-mode text` | the whole input is text (default); multi-line secrets such as private keys are removed |
| `-mode json` | the input is one JSON document; it is written back compact, keys in order |
| `-mode ndjson` | one JSON document per line; a line that is not JSON is redacted as text and counted |
| `-check` | write nothing; exit 3 if anything would have been redacted (for canary tests) |
| `-report` | per-rule counts as JSON on standard error |
| `-list` | print the rule names |
| `-maxBytes N` | largest input read in text and json mode, per file (default 64 MiB) |

Input is read from the files given, or from standard input. Exit codes: 0 done, 1 error, 3 `-check` found something.
In `json` mode input that is not valid JSON is an error and nothing is written to standard output.

```
$ echo 'export DB_PASSWORD=hunter2hunter2' | agent-redact
export DB_PASSWORD=[REDACTED:env-secret]
```

## Library

```go
import redact "github.com/baditaflorin/agent-redact"

r := redact.Default()
text, hits := r.String("curl -H 'Authorization: Bearer ...'")
doc, hits, err := r.JSON(rawJSON)   // order-preserving; err if rawJSON is not one JSON value
// hits is a map of rule name to count; hits.Total(), hits.Names()
```

`redact.New(rules)` builds a Redactor from your own `[]redact.Rule`; `redact.DefaultRules()` is the built-in set.
A Redactor is safe for concurrent use.

## Rules

Every match becomes `[REDACTED:<rule>]`.

| Rule | Finds |
|---|---|
| `private-key` | PEM private key blocks, including one cut off before its end line |
| `anthropic-key`, `openai-key`, `xai-key`, `google-api-key` | provider API keys |
| `github-token`, `aws-access-key`, `slack-token`, `stripe-key` | tokens of those services |
| `jwt` | three-part JSON web tokens |
| `auth-header` | the value of `Authorization: Bearer|Basic|Token ...` |
| `url-credentials` | the password in `scheme://user:password@host` |
| `env-secret` | the value of `NAME=value` or `"name": "value"` when NAME ends in token, secret, password, api key, access key, private key, auth key or credentials (quoted values may contain spaces) |
| `flag-secret` | the value after `--password `, `--token ` and similar flags |
| `key-name` | JSON only: a string value under a key that names a secret |

A name has to END with the sensitive word, so `API_KEY` and `db_password` match while `input_tokens`,
`TOKEN_LIMIT` and `tokenizer` do not.

## Canary

`canary.Fakes()` returns one fake secret per rule, assembled at run time so this source never holds a string a
scanner would flag. Write them into a test session, let your pipeline store it, then search the stored data for
each `Secret`. Any hit means a rule or a stage let a key through.

## Status

Pre-1.0: rule names are stable, patterns will keep being tightened. Licensed under Apache-2.0.

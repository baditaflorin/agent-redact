# agent-redact

Removes secrets from text and JSON before they are stored. Built for the text that coding agents leave
behind (prompts, shell commands, tool output, whole session records), where one pasted key would otherwise
land in a searchable archive.

- Go library and a small command line filter. Standard library only, no network, no state.
- Prefers a false positive to a leak. Text it has no rule for passes through unchanged.
- Idempotent: redacting redacted text changes nothing. `String` repeats until a pass finds nothing more (at most 5),
  because a first pass can shorten the text and let a length-limited rule match the value around it on the next.
- Fast: about 30 MB/s per core on text shaped like agent output (1 MB/s before v0.1.1); see Speed.
- JSON-aware: strings are redacted in place, keys stay in their original order, numbers stay as written,
  and a value under a key such as `password`, `access_token` or `Authorization` is replaced whole.
  A string that is itself a JSON document (a tool call stored as `"arguments": "{\"cmd\": ...}"`) is read as JSON
  too, up to four levels deep (see Documents held in strings).
- Reads escaped quotes: `NAME=\"a value\"` and `\"api_key\": \"v\"` are found at any depth of escaping.

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
doc, hits, err := r.JSON(rawJSON)   // order-preserving, follows documents held in strings; err if rawJSON is not one JSON value
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
| `env-secret` | the value of `NAME=value` or `"name": "value"` when NAME ends in token, secret, password, api key, access key, private key, auth key or credentials (quoted values of 4 to 300 characters may contain spaces; quotes may be escaped) |
| `flag-secret` | the value after `--password `, `--token ` and similar flags |
| `key-name` | JSON only: a string value under a key that names a secret |

A name has to END with the sensitive word, so `API_KEY` and `db_password` match while `input_tokens`,
`TOKEN_LIMIT` and `tokenizer` do not.

**Escaped quotes.** Text that has been through JSON escaping, or that sits in a shell string, shows a quote as `\"`
and, one level deeper, as `\\\"`. The `env-secret`, `auth-header` and `flag-secret` rules accept any number of
backslashes in front of a quote, so `echo "STRIPE_SECRET=\"my long phrase\"" >> .env`, `{\"api_key\": \"v\"}` and
`\"Authorization\": \"Bearer ...\"` are found like their plain forms. The backslashes that belong to a closing quote
stay in the text, so a JSON document kept as text is still valid JSON afterwards. Two exceptions: the value of an
unquoted assignment (`NAME=value`) or of a flag takes the backslash of an escaped closing quote with it. A run of
backslashes is never taken for a value.

## Documents held in strings

A coding agent stores a tool call as a JSON document inside a JSON string (a Codex `function_call` has
`"arguments": "{\"cmd\": ...}"`; the output of a command that prints JSON is stored the same way). `JSON` reads a
string value that, after white space, starts with `{` or `[` and is exactly one valid JSON value, as JSON again and
redacts it like any other document: keys stay in order, numbers as written, the key-name rule applies to its keys,
and a document inside that document is followed in turn, to **four levels** (in a sample of real session files, 1.2% of
Codex strings and 0.1% of Claude strings were documents, none nested deeper than three). The string is written back,
compact and re-escaped, only when something in it was redacted; a string with nothing to redact keeps its exact bytes.
The text rules run over the string afterwards as well.

**Not covered:** a document nested deeper than four levels, a document cut off before its end (not valid JSON), and a
string that holds a JSON string literal (a document encoded twice) are redacted by the text rules only. Those read
escaped quotes at any depth, so a quoted secret is still found, but the key-name rule does not apply to them: a value
under `cookie`, or a value of 1 to 3 characters under `password`, is not found there. `String` (and `-mode text`) never
parses: text that is a JSON document is redacted by the text rules, which read its escaped quotes.

## Speed

On a generated corpus that imitates agent text (strings with a median of 265 bytes, a p90 of 2 KB and a p99 of
11 KB, with trigger words such as "token", "secret" and URLs at the density a real session sample showed),
measured in a container capped at 3 CPUs:

| | before v0.1.1 | v0.1.1 |
|---|---|---|
| `String` | 1.0 MB/s | 30 MB/s |
| `JSON` (one event record per call) | 0.9 MB/s | 17 MB/s |
| `env-secret` rule alone | 3 MB/s | 100 MB/s |

The slow rules are the ones whose patterns start with a character class or a case-insensitive word, which Go's
regular expression engine handles slowly. They now look for their trigger words with a plain literal search and
run the same regular expression, anchored, only at the offsets where a match could start. A text holding the
two characters that Go's case-insensitive matching folds onto ASCII letters (U+017F and U+212A) is handed back
to the plain regular expression, so the answer is the same either way.

The speed-up is not allowed to change what is found: the tests compare the fast path with the original
whole-text rules (kept in the code as the reference) on every canary, on a generated corpus, on a long list of
awkward cases and on 60,000 generated texts, and a fuzz target does the same
(`go test -fuzz FuzzFastEqualsReference`). The fuzzer found one real difference while this was built (a Kelvin
sign in a URL scheme); it is fixed and kept as a regression case.

v0.1.2 reads documents held in strings and escaped quotes (see above) without giving that speed back. Measured side by
side with v0.1.1 on the same machine, in interleaved runs (the ratio is what is comparable; the machine drifts by a few
percent between runs): `String` 0.97 to 1.00 of v0.1.1's speed, `JSON` on strings that are not documents 0.95 to 1.03,
the `env-secret` rules unchanged. `JSON` on records where every string is a document inside a string, the worst case,
runs at 0.58 of v0.1.1's speed (about 9 MB/s on the corpus), because each such record is read twice; v0.1.1 was faster
there only because it missed the secrets. In real Codex session files about 11% of the string bytes are documents.

`String` does not parse text that is a JSON document: reading it as JSON first would run at about 0.4 of the speed on
text where every string is a document (10.5 against 27 MB/s), and the escaped-quote rules already find the secrets
that parse would find, so it would only add the key-name rule, which belongs to `JSON`. On text that is not a document
the check costs nothing measurable.

Benchmarks: `go test -run XXX -bench 'BenchmarkRule|BenchmarkString|BenchmarkJSON|BenchmarkStringOn' .` prints the
per-rule table, the record benchmarks and the text-mode comparison.

## Canary

`canary.Fakes()` returns one fake secret per rule, assembled at run time so this source never holds a string a
scanner would flag. Write them into a test session, let your pipeline store it, then search the stored data for
each `Secret`. Any hit means a rule or a stage let a key through.

## Status

Pre-1.0: rule names are stable, patterns will keep being tightened. Licensed under Apache-2.0.

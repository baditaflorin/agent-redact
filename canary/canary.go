// Package canary builds fake secrets, one per redaction rule, for end-to-end checks: write them
// into a test session, let the pipeline store it, then look for Secret in the stored rows. Any
// hit means a rule or a pipeline stage let a key through.
//
// Every value is assembled from pieces at run time, so this source never contains a string that a
// secret scanner would flag, and the values are deterministic so a check can be repeated.
package canary

import "strings"

// Fake is one canary: a line of text (or JSON) that must come out redacted.
type Fake struct {
	// Rule is the rule expected to fire.
	Rule string
	// Secret is the part that must not survive. Search stored data for it.
	Secret string
	// Text is the line to feed in.
	Text string
	// JSON means Text is a JSON document and must go through Redactor.JSON.
	JSON bool
}

func rep(s string, n int) string { return strings.Repeat(s, n)[:n] }

// Fakes returns canaries for every default rule and for the JSON key-name rule: at least one each, more where a rule
// has several forms (a quoted value, a header line, a key that only the key-name rule knows).
func Fakes() []Fake {
	anthropic := "sk-" + "ant-api03-" + rep("Ab3_x9", 28)
	openai := "sk-" + "proj-" + rep("Qw7Er5", 40)
	xai := "xai-" + rep("Zk4Lm8", 40)
	google := "AIza" + "Sy" + rep("D3f-G7_", 33)
	ghp := "gh" + "p_" + rep("A1b2C3", 36)
	ghpat := "github_" + "pat_" + rep("11AB_cd", 60)
	aws := "AK" + "IA" + "QWERTY0123456789"
	slack := "xo" + "xb-" + "1234567890-" + rep("abcDEF", 24)
	stripe := "sk" + "_live_" + rep("a1B2c3", 24)
	jwt := "ey" + "J" + "hbGciOiJIUzI1NiJ9" + "." + "ey" + "J" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "abcdEFGH1234_-xyz"
	pkBody := rep("MIIEvQIBADANBgkqhkiG9w0BAQ", 160)
	privateKey := "-----BEGIN " + "RSA PRIVATE KEY" + "-----\n" + pkBody + "\n-----END " + "RSA PRIVATE KEY" + "-----"
	bearer := rep("Tk9xR3pWb1", 32)
	dbPass := "s3cr3t" + "Passw0rd" + "XyZ"
	envPass := "hunter2" + "hunter2"
	quoted := "my long " + "secret phrase"
	flagPass := "hunter2" + "flag99"
	keyNameValue := "abcdefghij" + "klmnop"
	secretKeyValue := "dj4ng0" + "Sup3rS3cr3t" + "KeyValue"
	cookieValue := "s3ss10n" + rep("Zx9Qw", 8)
	setCookieValue := "c00k1e" + rep("Mn4Bv", 8)
	fleetKey := "a" + "k_" + rep("0123456789abcdef", 32)
	fleetLease := "l" + "i_" + rep("a1b2c3d4e5f6", 24) + "_" + rep("fedcba9876543210", 64)
	fleetFallback := "f" + "b_" + rep("9876543210fedcba", 32)
	return []Fake{
		{Rule: "private-key", Secret: pkBody, Text: "key file:\n" + privateKey + "\nend of file"},
		{Rule: "anthropic-key", Secret: anthropic, Text: "export ANTHROPIC=" + anthropic + " # old"},
		{Rule: "openai-key", Secret: openai, Text: "client = OpenAI(api_key='" + openai + "')"},
		{Rule: "xai-key", Secret: xai, Text: "curl -H 'x: " + xai + "' https://example.invalid"},
		{Rule: "google-api-key", Secret: google, Text: "https://example.invalid/v1?key=" + google},
		{Rule: "github-token", Secret: ghp, Text: "git clone https://example.invalid/" + ghp + " --depth 1"},
		{Rule: "github-token", Secret: ghpat, Text: "token is " + ghpat + " ok"},
		{Rule: "aws-access-key", Secret: aws, Text: "aws key " + aws + " here"},
		{Rule: "slack-token", Secret: slack, Text: "slack " + slack},
		{Rule: "stripe-key", Secret: stripe, Text: "stripe " + stripe},
		{Rule: "jwt", Secret: jwt, Text: "cookie value " + jwt + " expires"},
		{Rule: "auth-header", Secret: bearer, Text: "curl -H \"Authorization: Bearer " + bearer + "\" https://example.invalid"},
		{Rule: "url-credentials", Secret: dbPass, Text: "DATABASE_URL=postgres://app:" + dbPass + "@db.example.invalid:5432/app"},
		{Rule: "env-secret", Secret: envPass, Text: "DB_PASSWORD=" + envPass},
		{Rule: "env-secret", Secret: quoted, Text: "STRIPE_WEBHOOK_SECRET=\"" + quoted + "\""},
		{Rule: "env-secret", Secret: envPass, Text: "{\"api_key\": \"" + envPass + "\"} printed to the log"},
		{Rule: "flag-secret", Secret: flagPass, Text: "mysql --password " + flagPass + " -h db"},
		{Rule: "key-name", Secret: keyNameValue, JSON: true, Text: "{\"user\":\"ann\",\"access_token\":\"" + keyNameValue + "\"}"},
		{Rule: "key-name", Secret: secretKeyValue, JSON: true, Text: "{\"app\":\"demo\",\"SECRET_KEY\":\"" + secretKeyValue + "\"}"},
		{Rule: "cookie-header", Secret: cookieValue, Text: "curl -H 'Cookie: session=" + cookieValue + "; theme=dark' https://example.invalid"},
		{Rule: "fleet-api-key", Secret: fleetKey, Text: "curl -H \"X-API-Key: " + fleetKey + "\" https://example.invalid"},
		{Rule: "fleet-api-key", Secret: fleetKey, Text: "key " + fleetKey + " issued"},
		{Rule: "fleet-lease-issuer", Secret: fleetLease, Text: "issuer token " + fleetLease},
		{Rule: "fleet-fallback-key", Secret: fleetFallback, Text: "if ($http_x_api_key = \"" + fleetFallback + "\") { return 200; }"},
		{Rule: "cookie-header", Secret: setCookieValue, Text: "HTTP/1.1 200 OK\nSet-Cookie: sid=" + setCookieValue + "; Path=/; HttpOnly\nContent-Type: text/html"},
	}
}

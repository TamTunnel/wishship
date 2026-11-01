/**
 * Shared secret-shaped pattern list, used on diffs (blocking) and on
 * free-text fields (flagging). Shape-based detection is inherently
 * limited: it catches known token shapes, not arbitrary high-entropy
 * blobs — that limitation is documented in the README, not hidden.
 */
export interface SecretPattern {
  name: string;
  regex: RegExp;
  /**
   * Extra validation on the matched text. The bare-AWS-secret pattern
   * needs it: a 40-char token only counts when it contains a base64
   * alphabet character (`/`/`+`/`=`) that a hex hash never has.
   */
  validate?: (match: string) => boolean;
}

const PLACEHOLDER_VALUES = new Set([
  "required",
  "password",
  "changeme",
  "example",
  "placeholder",
  "xxx",
  "your-key-here",
  "todo",
]);

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: "pem-private-key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "github-token", regex: /gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}/ },
  { name: "stripe-secret", regex: /sk_live_[A-Za-z0-9]{16,}/ },
  // Hyphens included: sk-proj-* keys broke the old [A-Za-z0-9] class.
  { name: "openai-key", regex: /sk-[A-Za-z0-9_-]{20,}/ },
  { name: "slack-token", regex: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "aws-access-key", regex: /AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}/ },
  {
    name: "aws-secret-key",
    regex: /aws_secret_access_key[^A-Za-z0-9]{0,10}[A-Za-z0-9/+=]{40}/i,
  },
  {
    name: "aws-secret-bare",
    // A 40-char AWS-format secret WITHOUT the label. Lookarounds (not
    // \b) delimit the token: a real secret may END in `/`, `+`, or `=`,
    // and \b after such a character never matches, so those secrets
    // slipped through entirely. The validate step requires a non-hex
    // base64 character so SHA-1 hashes (40 hex) and other hex digests
    // don't trip it.
    regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/,
    validate: (m) => /[/+=]/.test(m),
  },
  { name: "google-api-key", regex: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "npm-token", regex: /npm_[A-Za-z0-9]{20,}/ },
  { name: "pypi-token", regex: /pypi-[A-Za-z0-9_-]{20,}/ },
  { name: "bearer-token", regex: /Bearer\s+[A-Za-z0-9._-]{20,}/ },
  { name: "jwt", regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ },
  {
    name: "credential-assignment",
    // password = "..." / api_key: '...' with a non-placeholder value.
    regex: /(password|passwd|secret|api[-_]?key|access[-_]?token)\s*[:=]\s*["']?([^\s"'`,;]{8,})/i,
  },
  {
    name: "hex-token",
    // Assigned/quoted 64-hex only: bare hashes in prose or test data
    // must not block a PR; an assigned 64-hex value is secret-shaped.
    regex: /[:=]\s*["']?[0-9a-f]{64}\b/,
  },
];

/** Pattern names matched in `text`. Empty = clean. */
export function scanSecrets(text: string): string[] {
  const hits: string[] = [];
  for (const p of SECRET_PATTERNS) {
    const m = p.regex.exec(text);
    if (!m) continue;
    if (p.validate && !p.validate(m[0])) continue;
    if (p.name === "credential-assignment" && m[2]) {
      const value = m[2].toLowerCase().replace(/["']+$/, "");
      if (PLACEHOLDER_VALUES.has(value)) continue;
    }
    hits.push(p.name);
  }
  return hits;
}

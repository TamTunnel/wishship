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

const OPERAND_SRC = String.raw`(?:[A-Za-z_$][\w$]*|"[^"\n]*"|'[^'\n]*')`;
const CHAIN_RE = new RegExp(
  `${OPERAND_SRC}(?:\\s*\\+\\s*${OPERAND_SRC})+`,
  "g",
);
const OPERAND_ONLY_RE = new RegExp(OPERAND_SRC, "g");
const JOIN_RE =
  /([A-Za-z_$][\w$]*|\[[^\]\n]*\])\s*\.join\(\s*(?:"([^"]*)"|'([^']*)')?\s*\)/g;
const LITERAL_ASSIGN_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*["']([^"']*)["']/g;
const ARRAY_ASSIGN_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([^\]\n]*)\]/g;
const EXPR_ASSIGN_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]+)/g;

/** Unquote a string literal token, or return null for non-literals. */
function literalValue(tok: string): string | null {
  const lit = tok.match(/^["']([^"']*)["']$/);
  return lit ? lit[1] : null;
}

function resolveOperand(
  tok: string,
  assigned: Map<string, string>,
): string | null {
  const lit = literalValue(tok);
  if (lit !== null) return lit;
  return assigned.get(tok) ?? null;
}

/** Resolve a `.join()` receiver to its element tokens, if known. */
function joinElements(
  receiver: string,
  arrays: Map<string, string[]>,
): string[] | null {
  const trimmed = receiver.trim();
  if (trimmed.startsWith("[")) {
    return [...trimmed.slice(1, -1).matchAll(OPERAND_ONLY_RE)].map((m) => m[0]);
  }
  return arrays.get(trimmed) ?? null;
}

/** Resolve one `.join()` call to its joined string, or null. */
function resolveJoinCall(
  receiver: string,
  separator: string | undefined,
  assigned: Map<string, string>,
  arrays: Map<string, string[]>,
): string | null {
  const elements = joinElements(receiver, arrays);
  if (elements === null) return null;
  const resolved: string[] = [];
  for (const el of elements) {
    const v = resolveOperand(el, assigned);
    if (v === null) return null;
    resolved.push(v);
  }
  // Array.prototype.join with no argument uses ",".
  return resolved.join(separator ?? ",");
}

/**
 * Resolve a right-hand-side expression to a plain string, or null when
 * it is not a reconstructable value: a literal, an assigned identifier,
 * a full `+` chain (parens ignored), a `.join()` call, or a template
 * literal whose ${...} parts all resolve.
 */
function resolveExpression(
  expr: string,
  assigned: Map<string, string>,
  arrays: Map<string, string[]>,
): string | null {
  const e = expr.trim();
  const lit = literalValue(e);
  if (lit !== null) return lit;
  if (/^[A-Za-z_$][\w$]*$/.test(e)) return assigned.get(e) ?? null;
  const noParens = e.replace(/[()]/g, "");
  const joinMatch = [...noParens.matchAll(JOIN_RE)];
  if (joinMatch.length === 1) {
    const before = noParens.slice(0, joinMatch[0].index).trim();
    const after = noParens.slice(joinMatch[0].index + joinMatch[0][0].length).trim();
    if (before === "" && after === "") {
      return resolveJoinCall(
        joinMatch[0][1],
        joinMatch[0][2] ?? joinMatch[0][3],
        assigned,
        arrays,
      );
    }
  }
  const operands = [...noParens.matchAll(OPERAND_ONLY_RE)].map((m) => m[0]);
  if (operands.length >= 2) {
    // The whole expression must be operands joined by `+` (and
    // whitespace) — anything else means this is not a plain chain.
    const remainder = noParens
      .replace(OPERAND_ONLY_RE, "")
      .replace(/\+/g, "")
      .trim();
    if (remainder === "") {
      const resolved: string[] = [];
      for (const op of operands) {
        const v = resolveOperand(op, assigned);
        if (v === null) return null;
        resolved.push(v);
      }
      return resolved.join("");
    }
  }
  if (e.startsWith("`") && e.endsWith("`")) {
    let resolved = e.slice(1, -1);
    let ok = false;
    for (const ref of e.matchAll(/\$\{([A-Za-z_$][\w$]*)\}/g)) {
      const v = assigned.get(ref[1]);
      if (v === undefined) return null;
      resolved = resolved.replace(ref[0], v);
      ok = true;
    }
    if (ok) return resolved;
  }
  return null;
}

/**
 * Scan added lines for secret-shaped material, including SPLIT tokens.
 * Per-line scanning alone misses `const a = "sk_live_abcd";` on one
 * line and `const b = "efghijklmnop1234";` on the next, joined by
 * `a + b` — neither half matches any pattern, but the reconstruction
 * is trivial. So, in addition to per-line scanning, this scans:
 * - the lines joined with newlines and with nothing (a token wrapped
 *   across a line break),
 * - full `+` chains of any length (`a + b + c`, parenthesized
 *   groupings, chains spanning lines) with operands resolved through
 *   same-diff assignments — including values propagated through
 *   intermediate expression assignments (`const key = a + b;` then
 *   `const full = key + c;`),
 * - `.join()` reconstructions: literal arrays (`[a, b].join("")`)
 *   and identifier arrays (`parts.join("")` where `parts` is assigned
 *   an array literal in the diff), with any separator, and
 * - template literals whose ${...} parts all resolve through those
 *   assignments.
 * Deliberately NOT scanned: adjacent quoted literals with no join
 * operator between them. Concatenating mere neighbors fabricates
 * tokens that do not exist in the source — it false-positived on a
 * JSON env dump, where "1" (WISHSHIP_AGENT) + "PATH" + the PATH value
 * formed an exactly-40-char slash-containing run that tripped
 * aws-secret-bare. Only an actual join operation is evidence of
 * reconstruction.
 * Shape-based detection stays heuristic: an arbitrary high-entropy
 * blob with no known shape still passes, and that limit is documented
 * in the README, not hidden.
 */
export function scanAddedLines(lines: string[]): string[] {
  const hits = new Set<string>();
  const add = (text: string): void => {
    for (const h of scanSecrets(text)) hits.add(h);
  };
  for (const line of lines) add(line);
  add(lines.join("\n"));
  add(lines.join(""));
  // Collect same-diff assignments, then propagate resolved values
  // through expression assignments to a fixpoint, so a chain built
  // in two steps (key = a + b; full = key + c) still resolves.
  const assigned = new Map<string, string>();
  const arrays = new Map<string, string[]>();
  for (const line of lines) {
    for (const m of line.matchAll(LITERAL_ASSIGN_RE)) assigned.set(m[1], m[2]);
    for (const m of line.matchAll(ARRAY_ASSIGN_RE)) {
      arrays.set(m[1], [...m[2].matchAll(OPERAND_ONLY_RE)].map((x) => x[0]));
    }
  }
  for (let pass = 0; pass < 10; pass++) {
    let changed = false;
    for (const line of lines) {
      for (const m of line.matchAll(EXPR_ASSIGN_RE)) {
        if (assigned.has(m[1])) continue;
        const v = resolveExpression(m[2], assigned, arrays);
        if (v !== null) {
          assigned.set(m[1], v);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  // Reconstruct: expand `.join()` calls to their joined value (and
  // scan it directly), then resolve every `+` chain in the result.
  // Paren-stripped copies catch `(a + b) + c` groupings. Units cover
  // single lines, newline-joined text (multi-line chains), and
  // nothing-joined text (line-wrapped chains).
  const units = [...lines, lines.join("\n"), lines.join("")];
  for (const unit of units) {
    for (const text of [unit, unit.replace(/[()]/g, "")]) {
      const expanded = text.replace(JOIN_RE, (whole, receiver, d, s) => {
        const joined = resolveJoinCall(receiver, d ?? s, assigned, arrays);
        if (joined === null) return whole;
        add(joined);
        return JSON.stringify(joined);
      });
      for (const m of expanded.matchAll(CHAIN_RE)) {
        const operands = [...m[0].matchAll(OPERAND_ONLY_RE)].map((x) => x[0]);
        const resolved: string[] = [];
        let ok = true;
        for (const op of operands) {
          const v = resolveOperand(op, assigned);
          if (v === null) {
            ok = false;
            break;
          }
          resolved.push(v);
        }
        if (ok) add(resolved.join(""));
      }
      for (const tm of expanded.matchAll(/`([^`]*)`/g)) {
        const body = tm[1];
        let resolved = body;
        let ok = true;
        for (const ref of body.matchAll(/\$\{([A-Za-z_$][\w$]*)\}/g)) {
          const v = assigned.get(ref[1]);
          if (v === undefined) {
            ok = false;
            break;
          }
          resolved = resolved.replace(ref[0], v);
        }
        if (ok && resolved !== body) add(resolved);
      }
    }
  }
  return [...hits];
}

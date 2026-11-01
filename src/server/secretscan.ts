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

/**
 * Resolved-value secret scanning (fix round 4).
 *
 * Earlier rounds enumerated reconstruction SHAPES (per-line, joined
 * text, pairwise `+`, full `+` chains, `.join()` on literal/identifier
 * arrays, template literals) — and every round a new shape evaded the
 * enumeration (variable separator, push-built array, `.concat`). This
 * round reframes the scan around RESOLVED RUNTIME VALUES: a small
 * evaluator walks the added lines, tracks what each variable would
 * hold when fully determined, and scans those values against the
 * secret patterns. A shape the evaluator understands is caught no
 * matter how it is spelled; a shape it does not understand stays
 * unknown and is never flagged on its own.
 *
 * Modeled (all through same-diff assignments, to a fixpoint):
 * - string literals, identifiers bound to resolved values
 * - `+` chains of any length, parenthesized, multi-line
 * - template literals with ${...} substitutions (fully consumed)
 * - `.concat(...)` argument lists (string and array receivers)
 * - `.join(sep)` where sep is a literal OR a resolved variable
 *   (default ","), over literal, identifier, spread, and push-built
 *   arrays (`.push()` appends applied in diff order)
 * - `String.fromCharCode(...)` and `String.fromCodePoint(...)` with
 *   numeric-literal arguments; `String(x)` coercion; `atob(x)` and
 *   `Buffer.from(x, "base64"|"base64url"|"hex")` decoding (the decoded
 *   value is scanned, not just the encoded text)
 * - object member bindings: `{}` literals plus key assignments in
 *   diff order (`o.a`, `o["a"]`, nested paths, array indices), so
 *   member reads resolve through the same environments
 * - string methods on resolved receivers with literal-or-resolved
 *   arguments, computed with the real JS method: slice, substring,
 *   substr, replace, replaceAll, trim, trimStart, trimEnd,
 *   toUpperCase, toLowerCase, split (→ resolved array, so
 *   split→join chains resolve), charAt, at, padStart, padEnd,
 *   toString; array at()/toString()
 * - reassignment, last-write-wins in the sequential pass
 * - two-step propagation (key = a + b; full = key + c)
 *
 * Deliberately NOT modeled (stays unknown, never flagged alone):
 * - function calls other than the ones above, and values that come
 *   from outside the diff (base code, imports, parameters, runtime
 *   input) — including the half-in-base case: a diff that adds only
 *   the second half of a secret whose first half is already committed
 *   cannot be resolved by diff-only scanning (see README scope note).
 *   Ternary/conditional right-hand sides as assignments stay unknown
 *   (their branch expressions ARE still scanned by the bare pass).
 * - adjacent quoted literals with no join operator between them:
 *   concatenating mere neighbors fabricates tokens that do not exist
 *   in the source — it false-positived on a JSON env dump, where "1"
 *   (WISHSHIP_AGENT) + "PATH" + the PATH value formed an exactly-40
 *   -char slash run that tripped aws-secret-bare. Only an actual join
 *   operation is evidence of reconstruction.
 *
 * Two environments are scanned, unioned:
 * - sequential: statements in diff order, last-write-wins, pushes
 *   applied in order — the precise straight-line semantics;
 * - fixpoint: assignments only, first-write-wins (the prior rounds'
 *   semantics), iterated until stable — a fail-closed net for
 *   forward references and function bodies, where diff order does
 *   not reflect execution order. It can flag code whose straight-line
 *   runtime value differs (a variable reassigned from a call after a
 *   literal assignment), but such patterns are contrived and this
 *   behavior matches round 3, so it is not a regression.
 * Bare expressions anywhere in the diff (call arguments, return
 * values, conditions) are evaluated with each final environment and
 * scanned too, so a reconstruction that is never assigned is caught.
 */

// ---- value model: a resolved string, a resolved array (elements may
// themselves be unknown), a resolved object (property values may
// themselves be unknown), a regex literal, or null for "not
// resolvable". ----

type StrVal = { kind: "string"; value: string };
type ArrVal = { kind: "array"; items: Value[] };
type ObjVal = { kind: "object"; props: Map<string, Value> };
type RegexVal = { kind: "regex"; pattern: string; flags: string };
type Value = StrVal | ArrVal | ObjVal | RegexVal | null;

function coerceToString(v: Value): string | null {
  if (v === null) return null;
  if (v.kind === "string") return v.value;
  if (v.kind !== "array") return null;
  const parts: string[] = [];
  for (const it of v.items) {
    const s = coerceToString(it);
    if (s === null) return null;
    parts.push(s);
  }
  return parts.join(",");
}

function addValues(a: Value, b: Value): Value {
  const sa = coerceToString(a);
  const sb = coerceToString(b);
  if (sa === null || sb === null) return null;
  return { kind: "string", value: sa + sb };
}

// Numeric argument for a string method: undefined = argument absent,
// null = unresolvable (unknown value, non-string, or non-array).
// A present numeric string is converted with Number(), matching JS
// coercion (NaN then behaves per the real method, since we call it).
function numArg(a: Value | undefined): number | undefined | null {
  if (a === undefined) return undefined;
  if (a === null || a.kind !== "string") return null;
  return Number(a.value);
}

/**
 * Evaluate a string method on a resolved receiver with fully resolved
 * arguments, using the REAL JS method — so slice/substring arg
 * swapping and clamping, replace-all semantics, and split limits are
 * exact, not approximated. Returns null when any argument is
 * unresolvable (unknown stays unknown, never flagged alone).
 */
function evalStringMethod(
  recv: string,
  name: string,
  args: Value[],
): Value {
  const bad = (): null => null;
  switch (name) {
    case "slice": {
      const start = numArg(args[0]);
      const end = numArg(args[1]);
      if (start === null || end === null) return bad();
      return { kind: "string", value: recv.slice(start, end) };
    }
    case "substring": {
      const start = numArg(args[0]);
      const end = numArg(args[1]);
      if (start === null || end === null) return bad();
      return { kind: "string", value: recv.substring(start ?? 0, end) };
    }
    case "substr": {
      const start = numArg(args[0]);
      const len = numArg(args[1]);
      if (start === null || len === null) return bad();
      return { kind: "string", value: recv.substr(start ?? 0, len) };
    }
    case "replace":
    case "replaceAll": {
      const search = args[0];
      const replacement = args[1];
      if (search === undefined || replacement === undefined) return bad();
      const rep = coerceToString(replacement);
      if (rep === null) return bad();
      if (search === null) return bad();
      if (search.kind === "string") {
        return {
          kind: "string",
          value: name === "replace"
            ? recv.replace(search.value, rep)
            : recv.replaceAll(search.value, rep),
        };
      }
      if (search.kind === "regex") {
        let re: RegExp;
        try {
          re = new RegExp(search.pattern, search.flags);
        } catch {
          return bad();
        }
        if (name === "replaceAll" && !re.flags.includes("g")) return bad();
        return {
          kind: "string",
          value: name === "replace"
            ? recv.replace(re, rep)
            : recv.replaceAll(re, rep),
        };
      }
      return bad();
    }
    case "trim":
      return { kind: "string", value: recv.trim() };
    case "trimStart":
      return { kind: "string", value: recv.trimStart() };
    case "trimEnd":
      return { kind: "string", value: recv.trimEnd() };
    case "toUpperCase":
      return { kind: "string", value: recv.toUpperCase() };
    case "toLowerCase":
      return { kind: "string", value: recv.toLowerCase() };
    case "split": {
      const sep = args[0];
      const limit = numArg(args[1]);
      if (sep === null || limit === null) return bad();
      let parts: string[];
      if (sep === undefined) {
        parts = [recv];
      } else if (sep.kind === "string") {
        parts = recv.split(sep.value);
      } else if (sep.kind === "regex") {
        try {
          parts = recv.split(new RegExp(sep.pattern, sep.flags));
        } catch {
          return bad();
        }
      } else {
        return bad();
      }
      if (limit !== undefined) parts = parts.slice(0, limit);
      return {
        kind: "array",
        items: parts.map((p) => ({ kind: "string" as const, value: p })),
      };
    }
    case "charAt": {
      const idx = numArg(args[0]);
      if (idx === null) return bad();
      return { kind: "string", value: recv.charAt(idx ?? 0) };
    }
    case "at": {
      const idx = numArg(args[0]);
      if (idx === null) return bad();
      const out = recv.at(idx ?? 0);
      return out === undefined ? null : { kind: "string", value: out };
    }
    case "padStart": {
      const len = numArg(args[0]);
      const pad = args[1] === undefined ? " " : coerceToString(args[1]);
      if (len === null || pad === null) return bad();
      return { kind: "string", value: recv.padStart(len ?? 0, pad) };
    }
    case "padEnd": {
      const len = numArg(args[0]);
      const pad = args[1] === undefined ? " " : coerceToString(args[1]);
      if (len === null || pad === null) return bad();
      return { kind: "string", value: recv.padEnd(len ?? 0, pad) };
    }
    case "toString":
      return { kind: "string", value: recv };
    default:
      return bad();
  }
}

/** Decode a base64 (or base64url) string to bytes-as-latin1, or null. */
function decodeBase64(s: string, urlSafe: boolean): string | null {
  try {
    const buf = urlSafe
      ? Buffer.from(s, "base64url")
      : Buffer.from(s, "base64");
    return buf.toString("latin1");
  } catch {
    return null;
  }
}

// ---- tokenizer ----

type Tok =
  | { t: "ident"; v: string }
  | { t: "string"; v: string }
  | { t: "template"; raw: string }
  | { t: "number"; v: string }
  | { t: "regex"; v: string }
  | { t: "punct"; v: string };

function decodeEscape(text: string, i: number): { ch: string; next: number } {
  const c = text[i + 1];
  switch (c) {
    case "n": return { ch: "\n", next: i + 2 };
    case "t": return { ch: "\t", next: i + 2 };
    case "r": return { ch: "\r", next: i + 2 };
    case "b": return { ch: "\b", next: i + 2 };
    case "f": return { ch: "\f", next: i + 2 };
    case "v": return { ch: "\v", next: i + 2 };
    case "0": return { ch: "\0", next: i + 2 };
    case "x": {
      const hex = text.slice(i + 2, i + 4);
      return /^[0-9a-fA-F]{2}$/.test(hex)
        ? { ch: String.fromCharCode(parseInt(hex, 16)), next: i + 4 }
        : { ch: "x", next: i + 2 };
    }
    case "u": {
      if (text[i + 2] === "{") {
        const end = text.indexOf("}", i + 3);
        if (end !== -1) {
          const cp = parseInt(text.slice(i + 3, end), 16);
          if (!Number.isNaN(cp)) return { ch: String.fromCodePoint(cp), next: end + 1 };
        }
        return { ch: "u", next: i + 2 };
      }
      const hex = text.slice(i + 2, i + 6);
      return /^[0-9a-fA-F]{4}$/.test(hex)
        ? { ch: String.fromCharCode(parseInt(hex, 16)), next: i + 6 }
        : { ch: "u", next: i + 2 };
    }
    default: return { ch: c ?? "", next: i + 2 };
  }
}

/** Index just past the template literal starting at `start` (a backtick), or -1. */
function skipTemplate(text: string, start: number): number {
  let i = start + 1;
  // Stack of open ${...} frames; each frame counts its own braces.
  const stack: number[] = [];
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\\") { i += 2; continue; }
    if (ch === "`") {
      if (stack.length === 0) return i + 1;
      // Nested template inside a substitution: skip it wholesale.
      const end = skipTemplate(text, i);
      if (end === -1) return -1;
      i = end;
      continue;
    }
    if (ch === "$" && text[i + 1] === "{") { stack.push(1); i += 2; continue; }
    if (stack.length > 0) {
      if (ch === '"' || ch === "'") {
        i++;
        while (i < text.length && text[i] !== ch) i += text[i] === "\\" ? 2 : 1;
        i++;
        continue;
      }
      if (ch === "{") { stack[stack.length - 1]++; i++; continue; }
      if (ch === "}") {
        stack[stack.length - 1]--;
        if (stack[stack.length - 1] === 0) stack.pop();
        i++;
        continue;
      }
    }
    i++;
  }
  return -1;
}

function scanRegex(text: string, start: number): { text: string; end: number } | null {
  let i = start + 1;
  let inClass = false;
  while (i < text.length) {
    const ch = text[i];
    if (ch === "\n") return null;
    if (ch === "\\") { i += 2; continue; }
    if (ch === "[") {
      inClass = true;
      i++;
      if (text[i] === "^") i++;
      if (text[i] === "]") i++;
      continue;
    }
    if (ch === "]") { inClass = false; i++; continue; }
    if (ch === "/" && !inClass) {
      let end = i + 1;
      while (end < text.length && /[a-z]/.test(text[end])) end++;
      return { text: text.slice(start, end), end };
    }
    i++;
  }
  return null;
}

const REGEX_PRECEDING_KEYWORDS = new Set([
  "return", "typeof", "void", "delete", "new", "in", "of", "instanceof",
  "case", "do", "else", "throw", "yield", "await", "const", "let", "var",
  "function", "class", "extends", "import", "export", "default", "if",
  "for", "while", "switch", "catch", "with",
]);

function tokenize(text: string): Tok[] {
  const toks: Tok[] = [];
  const prevIsOperand = (): boolean => {
    const p = toks[toks.length - 1];
    if (!p) return false;
    if (p.t === "ident") return !REGEX_PRECEDING_KEYWORDS.has(p.v);
    if (p.t === "string" || p.t === "number" || p.t === "template" || p.t === "regex") return true;
    return p.t === "punct" && (p.v === ")" || p.v === "]");
  };
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      let value = "";
      i++;
      while (i < text.length && text[i] !== ch && text[i] !== "\n") {
        if (text[i] === "\\") {
          const d = decodeEscape(text, i);
          value += d.ch;
          i = d.next;
        } else {
          value += text[i];
          i++;
        }
      }
      if (text[i] === ch) i++;
      toks.push({ t: "string", v: value });
      continue;
    }
    if (ch === "`") {
      const end = skipTemplate(text, i);
      if (end === -1) {
        toks.push({ t: "template", raw: text.slice(i + 1) });
        i = text.length;
      } else {
        toks.push({ t: "template", raw: text.slice(i + 1, end - 1) });
        i = end;
      }
      continue;
    }
    if (ch === "?" && text[i + 1] === "." && !/[0-9]/.test(text[i + 2] ?? "")) {
      toks.push({ t: "punct", v: "." });
      i += 2;
      continue;
    }
    if (ch === "." && text[i + 1] === "." && text[i + 2] === ".") {
      toks.push({ t: "punct", v: "..." });
      i += 3;
      continue;
    }
    if (ch === "+" && text[i + 1] === "=") {
      toks.push({ t: "punct", v: "+=" });
      i += 2;
      continue;
    }
    if (ch === "/" && text[i + 1] === "=") {
      toks.push({ t: "punct", v: "/=" });
      i += 2;
      continue;
    }
    if (ch === "/") {
      if (prevIsOperand()) {
        toks.push({ t: "punct", v: "/" });
        i++;
        continue;
      }
      const m = scanRegex(text, i);
      if (m !== null) {
        toks.push({ t: "regex", v: m.text });
        i = m.end;
        continue;
      }
      toks.push({ t: "punct", v: "/" });
      i++;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < text.length && /[\w$]/.test(text[j])) j++;
      toks.push({ t: "ident", v: text.slice(i, j) });
      i = j;
      continue;
    }
    if (/[0-9]/.test(ch)) {
      let j = i + 1;
      while (j < text.length && /[0-9A-Za-z._]/.test(text[j])) j++;
      toks.push({ t: "number", v: text.slice(i, j) });
      i = j;
      continue;
    }
    toks.push({ t: "punct", v: ch });
    i++;
  }
  return toks;
}

// ---- expression parser (structure-driven; values come from env) ----

class Parser {
  pos = 0;
  constructor(
    private toks: Tok[],
    private env: Map<string, Value>,
  ) {}

  atEnd(): boolean {
    return this.pos >= this.toks.length;
  }

  private peek(off = 0): Tok | undefined {
    return this.toks[this.pos + off];
  }

  /** True when the token at `off` is punctuation `v`. */
  private peekPunct(v: string, off = 0): boolean {
    const t = this.peek(off);
    return t?.t === "punct" && t.v === v;
  }

  parseExpr(): Value {
    return this.parseAdditive();
  }

  private parseAdditive(): Value {
    let left = this.parsePostfix();
    while (this.peekPunct("+")) {
      this.pos++;
      const right = this.parsePostfix();
      left = addValues(left, right);
    }
    return left;
  }

  private parsePostfix(): Value {
    const start = this.pos;
    let v = this.parsePrimary();
    for (;;) {
      if (this.peekPunct(".")) {
        const member = this.peek(1);
        const open = this.peek(2);
        if (member?.t !== "ident") break;
        if (open?.t === "punct" && open.v === "(") {
          // Method call.
          const recvTok = this.toks[start];
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "String" &&
            (member.v === "fromCharCode" || member.v === "fromCodePoint")
          ) {
            this.pos += 3;
            const args = this.parseArgs();
            const codes: number[] = [];
            for (const a of args) {
              if (a !== null && a.kind === "string" && /^-?\d+$/.test(a.value.trim())) {
                codes.push(parseInt(a.value.trim(), 10));
              } else {
                return null;
              }
            }
            try {
              v = {
                kind: "string",
                value: member.v === "fromCharCode"
                  ? String.fromCharCode(...codes)
                  : String.fromCodePoint(...codes),
              };
            } catch {
              return null;
            }
            continue;
          }
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "Buffer" &&
            member.v === "from"
          ) {
            this.pos += 3;
            const args = this.parseArgs();
            const data = args[0];
            if (data === undefined || data === null || data.kind !== "string") return null;
            const enc = args[1] === undefined ? "utf8" : coerceToString(args[1]);
            if (enc === null) return null;
            if (enc === "base64" || enc === "base64url") {
              const decoded = decodeBase64(data.value, enc === "base64url");
              if (decoded === null) return null;
              v = { kind: "string", value: decoded };
            } else if (
              enc === "utf8" || enc === "utf-8" || enc === "ascii" ||
              enc === "latin1" || enc === "binary"
            ) {
              v = { kind: "string", value: data.value };
            } else if (enc === "hex") {
              try {
                v = { kind: "string", value: Buffer.from(data.value, "hex").toString("latin1") };
              } catch {
                return null;
              }
            } else {
              return null;
            }
            continue;
          }
          if (member.v === "concat" || member.v === "join") {
            this.pos += 3;
            const args = this.parseArgs();
            if (member.v === "concat") {
              if (v === null) return null;
              if (v.kind === "string") {
                let out = v.value;
                for (const a of args) {
                  const s = coerceToString(a);
                  if (s === null) return null;
                  out += s;
                }
                v = { kind: "string", value: out };
              } else if (v.kind === "array") {
                const items = [...v.items];
                for (const a of args) {
                  if (a === null) items.push(null);
                  else if (a.kind === "array") items.push(...a.items);
                  else items.push(a);
                }
                v = { kind: "array", items };
              } else {
                return null;
              }
            } else {
              if (v === null || v.kind !== "array") return null;
              const sep = args.length === 0 ? "," : coerceToString(args[0]);
              if (sep === null) return null;
              const parts: string[] = [];
              for (const it of v.items) {
                const s = coerceToString(it);
                if (s === null) return null;
                parts.push(s);
              }
              v = { kind: "string", value: parts.join(sep) };
            }
            continue;
          }
          // String methods on a resolved string receiver, computed for
          // real (slice/substring/replace/split/trim/case/...).
          if (v !== null && v.kind === "string") {
            this.pos += 3;
            const args = this.parseArgs();
            const out = evalStringMethod(v.value, member.v, args);
            if (out === null) return null;
            v = out;
            continue;
          }
          // Array methods: at(i) reads an element, toString() joins.
          if (v !== null && v.kind === "array") {
            if (member.v === "at") {
              this.pos += 3;
              const args = this.parseArgs();
              const idx = numArg(args[0]);
              if (idx === null || idx === undefined) return null;
              const item = v.items[idx];
              if (item === undefined) return null;
              v = item;
              continue;
            }
            if (member.v === "toString") {
              this.pos += 3;
              this.parseArgs();
              const s = coerceToString(v);
              if (s === null) return null;
              v = { kind: "string", value: s };
              continue;
            }
          }
          // Any other method call: unknown result; consume args and stop.
          this.pos += 3;
          this.parseArgs();
          return null;
        }
        // Property access (not a call): on an object receiver this
        // resolves the member (round 5); on any other receiver the
        // value is unchanged (e.g. `(a + b).length` still computes a+b).
        if (v !== null && v.kind === "object") {
          v = v.props.get(member.v) ?? null;
        }
        this.pos += 2;
        continue;
      }
      if (this.peekPunct("[")) {
        // Index access: arr[i], obj["key"], str[i]. A string index
        // yields a single character (so char-by-char reconstruction
        // still resolves through `+` chains); out of range is unknown.
        this.pos++;
        const idx = this.parseExpr();
        if (!this.peekPunct("]")) return null;
        this.pos++;
        if (v !== null && v.kind === "array") {
          const n = numArg(idx);
          if (n === null || n === undefined) return null;
          const item = v.items[n];
          v = item === undefined ? null : item;
        } else if (v !== null && v.kind === "object") {
          const k = coerceToString(idx);
          v = k === null ? null : (v.props.get(k) ?? null);
        } else if (v !== null && v.kind === "string") {
          const n = numArg(idx);
          if (n === null || n === undefined) return null;
          const ch = v.value[n];
          v = ch === undefined ? null : { kind: "string", value: ch };
        } else {
          v = null;
        }
        continue;
      }
      break;
    }
    return v;
  }

  /** Parses `(args)` with pos just after `(`; consumes through `)`. */
  parseArgs(): Value[] {
    const args: Value[] = [];
    if (this.peekPunct(")")) {
      this.pos++;
      return args;
    }
    while (!this.atEnd()) {
      if (this.peekPunct("...")) {
        this.pos++;
        const v = this.parseExpr();
        if (v !== null && v.kind === "array") args.push(...v.items);
        else args.push(v);
      } else {
        args.push(this.parseExpr());
      }
      if (this.peekPunct(",")) {
        this.pos++;
        continue;
      }
      if (this.peekPunct(")")) {
        this.pos++;
        break;
      }
      break;
    }
    return args;
  }

  private parsePrimary(): Value {
    const tok = this.peek();
    if (!tok) return null;
    if (tok.t === "string" || tok.t === "number") {
      this.pos++;
      return { kind: "string", value: tok.v };
    }
    if (tok.t === "template") {
      this.pos++;
      return this.evalTemplate(tok.raw);
    }
    if (tok.t === "ident") {
      this.pos++;
      if (tok.v === "true") return { kind: "string", value: "true" };
      if (tok.v === "false") return { kind: "string", value: "false" };
      if (tok.v === "null") return { kind: "string", value: "null" };
      if (tok.v === "undefined") return { kind: "string", value: "undefined" };
      // Bare calls with known semantics: String(x) coerces, atob(x)
      // base64-decodes. Other bare calls are not consumed here (the
      // callee binding evaluates to unknown, as before).
      if ((tok.v === "String" || tok.v === "atob") && this.peekPunct("(")) {
        this.pos++;
        const args = this.parseArgs();
        if (tok.v === "String") {
          const s = args.length === 0 ? "" : coerceToString(args[0]);
          return s === null ? null : { kind: "string", value: s };
        }
        const data = args[0];
        if (data === undefined || data === null || data.kind !== "string") return null;
        const decoded = decodeBase64(data.value, false);
        return decoded === null ? null : { kind: "string", value: decoded };
      }
      return this.env.get(tok.v) ?? null;
    }
    if (tok.t === "regex") {
      this.pos++;
      const text = tok.v;
      const lastSlash = text.lastIndexOf("/");
      if (lastSlash <= 0) return null;
      const pattern = text.slice(1, lastSlash);
      const flags = text.slice(lastSlash + 1);
      if (!/^[dgimsuvy]*$/.test(flags)) return null;
      try {
        new RegExp(pattern, flags);
      } catch {
        return null;
      }
      return { kind: "regex", pattern, flags };
    }
    if (tok.t === "punct" && tok.v === "(") {
      this.pos++;
      const v = this.parseExpr();
      if (this.peekPunct(")")) this.pos++;
      return v;
    }
    if (tok.t === "punct" && tok.v === "[") {
      this.pos++;
      const items: Value[] = [];
      if (this.peekPunct("]")) {
        this.pos++;
        return { kind: "array", items };
      }
      while (!this.atEnd()) {
        if (this.peekPunct("...")) {
          this.pos++;
          const v = this.parseExpr();
          if (v !== null && v.kind === "array") items.push(...v.items);
          else items.push(v);
        } else {
          items.push(this.parseExpr());
        }
        if (this.peekPunct(",")) {
          this.pos++;
          if (this.peekPunct("]")) {
            this.pos++;
            break;
          }
          continue;
        }
        if (this.peekPunct("]")) {
          this.pos++;
          break;
        }
        break;
      }
      return { kind: "array", items };
    }
    if (tok.t === "punct" && tok.v === "{") {
      return this.parseObjectLiteral();
    }
    // Anything else: consume one token, unknown.
    this.pos++;
    return null;
  }

  /**
   * Parse an object literal into an object value (round 5). Entries
   * are parsed leniently: an unparseable entry (method, computed key
   * over an unknown expression) is skipped, but entries that do parse
   * still bind — a member read of a known key resolves. Shorthand
   * `{name}` binds the environment value of `name`.
   */
  private parseObjectLiteral(): Value {
    // pos is at `{`.
    this.pos++;
    const props = new Map<string, Value>();
    const skipToEntryEnd = (): void => {
      let depth = 0;
      while (!this.atEnd()) {
        const t = this.toks[this.pos];
        if (t.t === "punct" && (t.v === "{" || t.v === "[" || t.v === "(")) depth++;
        else if (t.t === "punct" && (t.v === "}" || t.v === "]" || t.v === ")")) {
          if (depth === 0) return;
          depth--;
        } else if (depth === 0 && t.t === "punct" && t.v === ",") return;
        this.pos++;
      }
    };
    for (;;) {
      if (this.peekPunct("}")) {
        this.pos++;
        break;
      }
      if (this.peekPunct(",")) {
        this.pos++;
        continue;
      }
      if (this.atEnd()) break;
      if (this.peekPunct("...")) {
        this.pos++;
        const v = this.parseExpr();
        if (v !== null && v.kind === "object") {
          for (const [k, val] of v.props) props.set(k, val);
        }
        continue;
      }
      const keyTok = this.peek();
      let key: string | null = null;
      if (keyTok?.t === "ident") key = keyTok.v;
      else if (keyTok?.t === "string") key = keyTok.v;
      else if (keyTok?.t === "number") key = keyTok.v;
      if (key === null) {
        this.pos++;
        skipToEntryEnd();
        continue;
      }
      const afterKey = this.peek(1);
      if (afterKey?.t === "punct" && afterKey.v === ":") {
        this.pos += 2;
        props.set(key, this.parseExpr());
        continue;
      }
      const next = this.peek(1);
      if (next?.t === "punct" && (next.v === "," || next.v === "}")) {
        this.pos++;
        props.set(key, this.env.get(key) ?? null);
        continue;
      }
      // Method shorthand or computed key: skip to the next entry.
      this.pos++;
      skipToEntryEnd();
    }
    return { kind: "object", props };
  }

  /** Index of the `}` closing the substitution opened at `start - 2`, or -1. */
  private findSubstitutionEnd(raw: string, start: number): number {
    let depth = 1;
    let i = start;
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === "\\") { i += 2; continue; }
      if (ch === '"' || ch === "'") {
        i++;
        while (i < raw.length && raw[i] !== ch) i += raw[i] === "\\" ? 2 : 1;
        i++;
        continue;
      }
      if (ch === "`") {
        const end = skipTemplate(raw, i);
        if (end === -1) return -1;
        i = end;
        continue;
      }
      if (ch === "{") depth++;
      if (ch === "}") {
        depth--;
        if (depth === 0) return i;
      }
      i++;
    }
    return -1;
  }

  private evalTemplate(raw: string): Value {
    let out = "";
    let i = 0;
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === "\\" && i + 1 < raw.length) {
        const d = decodeEscape(raw, i);
        out += d.ch;
        i = d.next;
        continue;
      }
      if (ch === "$" && raw[i + 1] === "{") {
        const close = this.findSubstitutionEnd(raw, i + 2);
        if (close === -1) return null;
        const sub = new Parser(tokenize(raw.slice(i + 2, close)), this.env);
        const v = sub.parseExpr();
        // The substitution must be fully consumed: a partially parsed
        // expression (ternary, comma, ...) is not the runtime value.
        if (sub.pos !== sub.toks.length) return null;
        const s = coerceToString(v);
        if (s === null) return null;
        out += s;
        i = close + 1;
        continue;
      }
      out += ch;
      i++;
    }
    return { kind: "string", value: out };
  }
}

// ---- statement walk: assignments and .push() ----

/**
 * Apply `base.key... = rhs` (or `+=`) to the environment (round 5).
 * Missing containers are created on demand — the member value is
 * diff-derived either way, so creating the container is fail-closed.
 * A non-container in the path is a runtime no-op/throw, so it is left
 * alone. In fixpoint mode an already-bound non-null key is never
 * overwritten (first-write-wins), except that a null placeholder left
 * by an earlier pass may still be filled when its dependencies bind.
 */
function applyMemberAssign(
  env: Map<string, Value>,
  keys: string[],
  rhs: Value,
  isPlusEq: boolean,
  mode: "sequential" | "fixpoint",
): void {
  const base = keys[0];
  let cur = env.get(base);
  if (cur === undefined) {
    cur = { kind: "object", props: new Map() };
    env.set(base, cur);
  }
  if (cur === null || (cur.kind !== "object" && cur.kind !== "array")) return;
  let holder: ObjVal | ArrVal = cur;
  for (let i = 1; i < keys.length - 1; i++) {
    const k = keys[i];
    let next: Value;
    if (holder.kind === "object") {
      next = holder.props.get(k) ?? null;
    } else {
      const n = Number(k);
      next = Number.isInteger(n) ? (holder.items[n] ?? null) : null;
    }
    if (next === null || (next.kind !== "object" && next.kind !== "array")) {
      if (next !== null) return; // non-container in the path: no-op
      next = { kind: "object", props: new Map() };
      if (holder.kind === "object") holder.props.set(k, next);
      else {
        const n = Number(k);
        if (!Number.isInteger(n)) return;
        holder.items[n] = next;
      }
    }
    holder = next;
  }
  const last = keys[keys.length - 1];
  if (holder.kind === "object") {
    const existing = holder.props.get(last);
    if (mode === "fixpoint" && existing !== undefined && existing !== null) return;
    if (isPlusEq) {
      const combined = existing !== undefined ? addValues(existing, rhs) : rhs;
      holder.props.set(last, combined);
    } else {
      holder.props.set(last, rhs);
    }
  } else {
    const n = Number(last);
    if (!Number.isInteger(n)) return;
    const existing = holder.items[n];
    if (mode === "fixpoint" && existing !== undefined && existing !== null) return;
    if (isPlusEq) {
      const combined = existing !== undefined ? addValues(existing, rhs) : rhs;
      holder.items[n] = combined;
    } else {
      holder.items[n] = rhs;
    }
  }
}

/**
 * Walks the token stream once, applying assignments (and, in
 * sequential mode, `.push()` appends) to `env`. Returns true if any
 * new binding was added (fixpoint mode only; sequential always
 * returns false). A bare assignment/push is recognized only at a
 * statement start — the previous token must be the start, `;`, `{`,
 * `}`, `,`, `)` or `]`, or an identifier/string/number/template/
 * regex token (ASI: a new statement may follow an expression end) —
 * so `obj.key = ...` never binds a variable named `key` (previous
 * token `.`); instead it binds the member on the object value via
 * applyMemberAssign (round 5), and `x[0] = ...` binds an array
 * element, never `x` itself.
 */
function walkStatements(
  toks: Tok[],
  env: Map<string, Value>,
  mode: "sequential" | "fixpoint",
): boolean {
  let changed = false;
  const p = new Parser(toks, env);
  const atStatementStart = (idx: number): boolean => {
    if (idx === 0) return true;
    const prev = toks[idx - 1];
    if (prev.t === "punct") return [";", "{", "}", ",", ")", "]"].includes(prev.v);
    return true; // ident/string/number/template/regex: expression end
  };
  while (!p.atEnd()) {
    const start = p.pos;
    let j = start;
    const first = toks[j];
    if (first?.t === "ident" && (first.v === "const" || first.v === "let" || first.v === "var")) {
      j++;
    } else if (!atStatementStart(start)) {
      p.pos++;
      continue;
    }
    const nameTok = toks[j];
    const eq = toks[j + 1];
    if (
      nameTok?.t === "ident" &&
      eq?.t === "punct" &&
      (eq.v === "=" || eq.v === "+=")
    ) {
      p.pos = j + 2;
      const rhs = p.parseExpr();
      if (mode === "sequential") {
        if (eq.v === "=") {
          if (rhs !== null) env.set(nameTok.v, rhs);
          else env.delete(nameTok.v);
        } else {
          const cur = env.get(nameTok.v);
          const combined = cur !== undefined ? addValues(cur, rhs) : rhs;
          if (combined !== null) env.set(nameTok.v, combined);
          else env.delete(nameTok.v);
        }
      } else if (!env.has(nameTok.v) && rhs !== null) {
        env.set(nameTok.v, rhs);
        changed = true;
      }
      const semi = toks[p.pos];
      if (semi?.t === "punct" && semi.v === ";") p.pos++;
      continue;
    }
    const dot = toks[j + 1];
    const pushName = toks[j + 2];
    const pushOpen = toks[j + 3];
    if (
      mode === "sequential" &&
      nameTok?.t === "ident" &&
      dot?.t === "punct" && dot.v === "." &&
      pushName?.t === "ident" && pushName.v === "push" &&
      pushOpen?.t === "punct" && pushOpen.v === "("
    ) {
      p.pos = j + 4;
      const args = p.parseArgs();
      const cur = env.get(nameTok.v);
      if (cur !== undefined && cur !== null && cur.kind === "array") {
        cur.items.push(...args);
      } else if (cur === undefined) {
        // Pushes into an array declared outside the diff: track the
        // pushed elements alone. This can only flag when the pushed
        // elements themselves reconstruct a secret shape; base-code
        // elements the diff cannot see are a miss, not a false flag,
        // in the other direction.
        env.set(nameTok.v, { kind: "array", items: args });
      }
      // Push on a non-array would throw at runtime; ignore.
      const semi = toks[p.pos];
      if (semi?.t === "punct" && semi.v === ";") p.pos++;
      continue;
    }
    // Member assignment path: base (.key | ["key"] | [0] | [bound])* =
    // rhs (or +=). Binds into the object/array value so later member
    // reads resolve (round 5: `o = {}; o.a = ...; o.a + o.b`).
    if (nameTok?.t === "ident") {
      const keys: string[] = [nameTok.v];
      let k = j + 1;
      let ok = true;
      while (true) {
        const sep = toks[k];
        const keyTok = toks[k + 1];
        if (sep?.t === "punct" && sep.v === "." && keyTok?.t === "ident") {
          keys.push(keyTok.v);
          k += 2;
          continue;
        }
        if (sep?.t === "punct" && sep.v === "[") {
          const inner = toks[k + 1];
          const close = toks[k + 2];
          if (
            (inner?.t === "string" || inner?.t === "number") &&
            close?.t === "punct" && close.v === "]"
          ) {
            keys.push(inner.v);
            k += 3;
            continue;
          }
          if (inner?.t === "ident" && close?.t === "punct" && close.v === "]") {
            const bound = env.get(inner.v);
            if (bound !== null && bound !== undefined && bound.kind === "string") {
              keys.push(bound.value);
              k += 3;
              continue;
            }
          }
          ok = false;
          break;
        }
        break;
      }
      const eqTok = toks[k];
      if (
        ok && keys.length > 1 &&
        eqTok?.t === "punct" && (eqTok.v === "=" || eqTok.v === "+=")
      ) {
        p.pos = k + 1;
        const rhs = p.parseExpr();
        applyMemberAssign(env, keys, rhs, eqTok.v === "+=", mode);
        const semi = toks[p.pos];
        if (semi?.t === "punct" && semi.v === ";") p.pos++;
        continue;
      }
    }
    p.pos++;
  }
  return changed;
}

/**
 * Scan added lines for secret-shaped material, including SPLIT tokens
 * rebuilt at runtime. In addition to per-line scanning and the joined
 * newline/nothing texts (a token wrapped across a line break), this
 * resolves the runtime values of variables and bare expressions (see
 * the resolver notes above) and scans those values. Unresolvable
 * expressions stay unknown and are never flagged alone; adjacent
 * literals with no join operator are never concatenated.
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
  const toks = tokenize(lines.join("\n"));
  // Sequential environment: diff order, last-write-wins, pushes in order.
  const envA = new Map<string, Value>();
  walkStatements(toks, envA, "sequential");
  // Fixpoint environment: assignments only, first-write-wins, iterated
  // to stability — the fail-closed net for forward references.
  const envB = new Map<string, Value>();
  for (let pass = 0; pass < 10; pass++) {
    if (!walkStatements(toks, envB, "fixpoint")) break;
  }
  for (const env of [envA, envB]) {
    for (const v of env.values()) {
      if (v !== null && v.kind === "string") add(v.value);
    }
    // Bare expressions anywhere in the diff, evaluated with the final
    // environment: reconstructions that are never assigned (call
    // arguments, return values, conditions, ternary branches).
    const p = new Parser(toks, env);
    while (!p.atEnd()) {
      const start = p.pos;
      const v = p.parseExpr();
      if (v !== null && v.kind === "string") add(v.value);
      p.pos = v !== null ? Math.max(p.pos, start + 1) : start + 1;
    }
  }
  return [...hits];
}

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
 * - numeric values and arithmetic (round 6): `charCodeAt` /
 *   `codePointAt` on resolved strings yield numbers, `+` (with JS
 *   string/number semantics), `-`, `*`, `/`, `%`, unary +/-, and
 *   ++/-- compute, and `fromCharCode`/`fromCodePoint` accept
 *   computed numbers
 * - decoders and constructors (round 6): `decodeURIComponent`,
 *   `decodeURI`, `unescape`, `new TextDecoder().decode(...)` /
 *   `new TextEncoder().encode(...)`, `Uint8Array.from`/`of` /
 *   `new Uint8Array(...)`, `JSON.parse` (→ modeled object/array),
 *   `Array.from`/`of` (with a diff-defined map function applied)
 * - diff-defined functions (round 6): declarations, function
 *   expressions, and arrow functions (block or concise bodies) are
 *   evaluated with arguments bound — single return expressions,
 *   straight-line assignments (incl. +=, push, ++/--), `for...of`
 *   loops over resolved arrays with += accumulation, and `if`/`else`
 *   (known conditions take one branch; unknown conditions union
 *   both branches' returns). Function-valued `replace` callbacks
 *   are evaluated per match. Plus the conservative fallback: a call
 *   whose raw string-literal arguments (or array-literal elements)
 *   concatenate in order to a secret pattern is flagged even when
 *   the body is intractable — honest code never passes fragments
 *   that concatenate to a secret into a helper except to rebuild one.
 *
 * Deliberately NOT modeled (stays unknown, never flagged alone):
 * - recursion, closures over mutated state, classes, `eval`, and
 *   genuinely complex control flow (classic `for` loops, `while`,
 *   `switch`, `try` bodies are skipped, not interpreted — a helper
 *   with such a body is still caught when called with literal
 *   fragments, via the fallback below, but not when the fragments
 *   arrive via variables); method calls on objects whose property
 *   is a multi-path function (single-path object methods DO resolve);
 *   multi-path call results combined with further expressions (a
 *   branchy helper returning one fragment, concatenated with another
 *   fragment at the call site — each branch outcome is scanned, but
 *   not the combination)
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

// ---- value model: a resolved string, a resolved number, a resolved
// array (elements may themselves be unknown), a resolved object
// (property values may themselves be unknown), a regex literal, a
// text encoder/decoder marker, a diff-defined function value, or null
// for "not resolvable". ----

type StrVal = { kind: "string"; value: string };
type NumVal = { kind: "number"; value: number };
type ArrVal = { kind: "array"; items: Value[] };
type ObjVal = { kind: "object"; props: Map<string, Value> };
type RegexVal = { kind: "regex"; pattern: string; flags: string };
type TextDecoderVal = { kind: "textdecoder" };
type TextEncoderVal = { kind: "textencoder" };
type FuncVal = { kind: "function"; def: FuncDef };
type Value =
  | StrVal
  | NumVal
  | ArrVal
  | ObjVal
  | RegexVal
  | TextDecoderVal
  | TextEncoderVal
  | FuncVal
  | null;

function coerceToString(v: Value): string | null {
  if (v === null) return null;
  if (v.kind === "string") return v.value;
  if (v.kind === "number") return String(v.value);
  if (v.kind !== "array") return null;
  const parts: string[] = [];
  for (const it of v.items) {
    const s = coerceToString(it);
    if (s === null) return null;
    parts.push(s);
  }
  return parts.join(",");
}

/** JS `+` semantics: number + number sums, anything else string-concatenates. */
function addValues(a: Value, b: Value): Value {
  if (a !== null && a.kind === "number" && b !== null && b.kind === "number") {
    return { kind: "number", value: a.value + b.value };
  }
  const sa = coerceToString(a);
  const sb = coerceToString(b);
  if (sa === null || sb === null) return null;
  return { kind: "string", value: sa + sb };
}

/** JS numeric coercion for `-`, `*`, `/`, `%`, `++`, `--`: null when not coercible. */
function toNum(v: Value): number | null {
  if (v === null) return null;
  if (v.kind === "number") return v.value;
  if (v.kind !== "string") return null;
  const n = Number(v.value);
  return Number.isNaN(n) ? null : n;
}

// Numeric argument for a string method: undefined = argument absent,
// null = unresolvable (unknown value, non-string, or non-array).
// A present numeric string is converted with Number(), matching JS
// coercion (NaN then behaves per the real method, since we call it).
function numArg(a: Value | undefined): number | undefined | null {
  if (a === undefined) return undefined;
  if (a === null) return null;
  if (a.kind === "number") return a.value;
  if (a.kind !== "string") return null;
  return Number(a.value);
}

/** `unescape` is not in the ES2022 lib, so implement its %XX / %uXXXX decoding. */
function unescapeJs(s: string): string {
  return s.replace(/%u([0-9a-fA-F]{4})|%([0-9a-fA-F]{2})/g, (_m, u, h) => {
    if (u !== undefined) return String.fromCharCode(parseInt(u, 16));
    return String.fromCharCode(parseInt(h, 16));
  });
}

/**
 * Evaluate a string method on a resolved receiver with fully resolved
 * arguments, using the REAL JS method — so slice/substring arg
 * swapping and clamping, replace-all semantics, and split limits are
 * exact, not approximated. Returns null when any argument is
 * unresolvable (unknown stays unknown, never flagged alone).
 * Function-valued replacements (round 6) are evaluated per match with
 * the JS callback arguments (match, groups..., offset, string); if any
 * callback evaluation fails, the whole replacement is unknown.
 */
function evalStringMethod(
  recv: string,
  name: string,
  args: Value[],
  env: Map<string, Value>,
  ctx: EvalCtx,
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
      if (search === null) return bad();
      if (replacement !== null && replacement.kind === "function") {
        return replaceWithCallback(recv, search, name === "replaceAll", replacement.def, env, ctx);
      }
      const rep = coerceToString(replacement);
      if (rep === null) return bad();
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
    case "charCodeAt": {
      const idx = numArg(args[0]);
      if (idx === null) return bad();
      return { kind: "number", value: recv.charCodeAt(idx ?? 0) };
    }
    case "codePointAt": {
      const idx = numArg(args[0]);
      if (idx === null) return bad();
      const cp = recv.codePointAt(idx ?? 0);
      return cp === undefined ? null : { kind: "number", value: cp };
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

/**
 * String.replace/replaceAll with a function-valued replacement (round 6).
 * The callback is evaluated per match with the JS callback arguments;
 * if any callback evaluation fails (multi-path body, unknown value),
 * the whole replacement is unknown rather than silently partial.
 */
function replaceWithCallback(
  recv: string,
  search: Value,
  all: boolean,
  def: FuncDef,
  env: Map<string, Value>,
  ctx: EvalCtx,
): Value {
  const call = (match: string, groups: string[], offset: number): string | null => {
    const cbArgs: Value[] = [
      { kind: "string", value: match },
      ...groups.map((g) => ({ kind: "string", value: g }) as Value),
      { kind: "number", value: offset },
      { kind: "string", value: recv },
    ];
    const outs = evaluateFunction(def, cbArgs, env, ctx);
    if (outs.length !== 1 || outs[0] === null) return null;
    return coerceToString(outs[0]);
  };
  if (search === null) return null;
  if (search.kind === "string") {
    const needle = search.value;
    if (!all) {
      const idx = recv.indexOf(needle);
      if (idx === -1) return { kind: "string", value: recv };
      const rep = call(needle, [], idx);
      if (rep === null) return null;
      return { kind: "string", value: recv.slice(0, idx) + rep + recv.slice(idx + needle.length) };
    }
    if (needle === "") {
      const chars = recv.split("");
      let out = "";
      for (let k = 0; k <= chars.length; k++) {
        if (k > 0) out += chars[k - 1];
        const rep = call("", [], k);
        if (rep === null) return null;
        out += rep;
      }
      return { kind: "string", value: out };
    }
    const parts = recv.split(needle);
    let out = parts[0];
    let offset = 0;
    for (let k = 1; k < parts.length; k++) {
      offset += parts[k - 1].length;
      const rep = call(needle, [], offset);
      if (rep === null) return null;
      out += rep + parts[k];
      offset += needle.length;
    }
    return { kind: "string", value: out };
  }
  if (search.kind === "regex") {
    let re: RegExp;
    try {
      re = new RegExp(search.pattern, search.flags);
    } catch {
      return null;
    }
    if (all && !re.flags.includes("g")) return null;
    const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
    const global = new RegExp(re.source, flags);
    let out = "";
    let last = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = global.exec(recv)) !== null) {
      if (guard++ > recv.length + 1) return null;
      // Unmatched groups arrive as undefined in JS; our model uses the
      // "undefined" string, matching the existing convention.
      const groups = m.slice(1).map((g) => (g === undefined ? "undefined" : g));
      const rep = call(m[0], groups, m.index);
      if (rep === null) return null;
      out += recv.slice(last, m.index) + rep;
      last = m.index + m[0].length;
      if (m[0].length === 0) global.lastIndex++;
      if (!all) break;
    }
    out += recv.slice(last);
    return { kind: "string", value: out };
  }
  return null;
}

/** Convert a JSON.parse result to a resolver value (round 6, depth-capped). */
function jsonToValue(v: unknown, depth: number): Value {
  if (depth > 20) return null;
  if (typeof v === "string") return { kind: "string", value: v };
  if (typeof v === "number") return { kind: "number", value: v };
  if (typeof v === "boolean") return { kind: "string", value: v ? "true" : "false" };
  if (v === null) return { kind: "string", value: "null" };
  if (Array.isArray(v)) return { kind: "array", items: v.map((it) => jsonToValue(it, depth + 1)) };
  if (typeof v === "object") {
    const props = new Map<string, Value>();
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      props.set(k, jsonToValue(val, depth + 1));
    }
    return { kind: "object", props };
  }
  return null;
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
    if (ch === "+" && text[i + 1] === "+") {
      toks.push({ t: "punct", v: "++" });
      i += 2;
      continue;
    }
    if (ch === "-" && text[i + 1] === "-") {
      toks.push({ t: "punct", v: "--" });
      i += 2;
      continue;
    }
    if (ch === "=" && text[i + 1] === ">") {
      toks.push({ t: "punct", v: "=>" });
      i += 2;
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

// ---- shared token helpers (round 6: function modeling) ----

/** Index of the bracket closing the one at `openIdx` (balanced), or -1. */
function matchBracket(toks: Tok[], openIdx: number): number {
  const open = toks[openIdx];
  if (open?.t !== "punct") return -1;
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  const close = pairs[open.v];
  if (!close) return -1;
  let depth = 0;
  for (let i = openIdx; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "punct") continue;
    if (t.v === open.v) depth++;
    else if (t.v === close) {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/** Index of the next top-level expression delimiter (`,`, `;`, closer), or end. */
function findExprEnd(toks: Tok[], start: number): number {
  let depth = 0;
  for (let i = start; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "punct") continue;
    if (t.v === "(" || t.v === "[" || t.v === "{") depth++;
    else if (t.v === ")" || t.v === "]" || t.v === "}") {
      if (depth === 0) return i;
      depth--;
    } else if (depth === 0 && (t.v === "," || t.v === ";")) return i;
  }
  return toks.length;
}

/** Index of the next top-level `;` or enclosing-block `}`, or end. */
function findStmtEnd(toks: Tok[], start: number): number {
  let depth = 0;
  for (let i = start; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "punct") continue;
    if (t.v === "(" || t.v === "[" || t.v === "{") depth++;
    else if (t.v === ")" || t.v === "]" || t.v === "}") {
      if (depth === 0) return i;
      depth--;
    } else if (t.v === ";" && depth === 0) return i;
  }
  return toks.length;
}

/** Split a token slice on top-level commas. An empty slice has no parts. */
function splitTopLevel(toks: Tok[]): Tok[][] {
  if (toks.length === 0) return [];
  const parts: Tok[][] = [];
  let depth = 0;
  let cur: Tok[] = [];
  for (const t of toks) {
    if (t.t === "punct" && (t.v === "(" || t.v === "[" || t.v === "{")) depth++;
    else if (t.t === "punct" && (t.v === ")" || t.v === "]" || t.v === "}")) depth--;
    if (t.t === "punct" && t.v === "," && depth === 0) {
      parts.push(cur);
      cur = [];
      continue;
    }
    cur.push(t);
  }
  parts.push(cur);
  return parts;
}

interface FuncParam {
  name: string;
  defaultToks?: Tok[];
  rest?: boolean;
}

interface FuncDef {
  params: FuncParam[];
  bodyToks: Tok[];
  isBlock: boolean;
}

function parseParams(slice: Tok[]): FuncParam[] {
  const params: FuncParam[] = [];
  for (const part of splitTopLevel(slice)) {
    if (part.length === 0) continue;
    let idx = 0;
    let rest = false;
    if (part[0]?.t === "punct" && part[0].v === "...") {
      rest = true;
      idx = 1;
    }
    const nameTok = part[idx];
    if (nameTok?.t !== "ident") continue;
    const eqIdx = part.findIndex((t, k) => k > idx && t.t === "punct" && t.v === "=");
    params.push({
      name: nameTok.v,
      rest,
      defaultToks: eqIdx === -1 ? undefined : part.slice(eqIdx + 1),
    });
  }
  return params;
}

// ---- expression parser (structure-driven; values come from env) ----

class Parser {
  pos = 0;
  constructor(
    private toks: Tok[],
    private env: Map<string, Value>,
    private ctx: EvalCtx = defaultCtx(),
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
    let left = this.parseMultiplicative();
    while (this.peekPunct("+") || this.peekPunct("-")) {
      const opTok = this.peek();
      const op = opTok?.t === "punct" ? opTok.v : undefined;
      this.pos++;
      const right = this.parseMultiplicative();
      if (op === "+") {
        left = addValues(left, right);
      } else {
        const a = toNum(left);
        const b = toNum(right);
        left = a === null || b === null ? null : { kind: "number", value: a - b };
      }
    }
    return left;
  }

  private parseMultiplicative(): Value {
    let left = this.parsePostfix();
    while (this.peekPunct("*") || this.peekPunct("/") || this.peekPunct("%")) {
      const opTok = this.peek();
      const op = opTok?.t === "punct" ? opTok.v : undefined;
      this.pos++;
      const right = this.parsePostfix();
      const a = toNum(left);
      const b = toNum(right);
      if (a === null || b === null) {
        left = null;
      } else if (op === "*") {
        left = { kind: "number", value: a * b };
      } else if (op === "/") {
        left = { kind: "number", value: a / b };
      } else {
        left = { kind: "number", value: a % b };
      }
    }
    return left;
  }

  private parsePostfix(): Value {
    const start = this.pos;
    let v = this.parsePrimary();
    for (;;) {
      // Bare call to a diff-defined function value: evaluate the body
      // with arguments bound (round 6). Multi-path bodies yield null
      // here; the call-site scan pass in scanAddedLines flags secrets
      // among their possible outcomes.
      if (v !== null && v.kind === "function" && this.peekPunct("(")) {
        this.pos++;
        const args = this.parseArgs();
        const outs = evaluateFunction(v.def, args, this.env, this.ctx);
        v = outs.length === 1 ? outs[0] : null;
        continue;
      }
      // Postfix ++ / --: JS yields ToNumber(old value).
      if (this.peekPunct("++") || this.peekPunct("--")) {
        this.pos++;
        const n = toNum(v);
        v = n === null ? null : { kind: "number", value: n };
        continue;
      }
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
              if (a !== null && a.kind === "number") {
                codes.push(a.value);
              } else if (a !== null && a.kind === "string" && /^-?\d+$/.test(a.value.trim())) {
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
          // Uint8Array.from / Uint8Array.of (round 6): byte arrays.
          // A mapFn argument is not modeled (unknown) — mapping bytes
          // through an arbitrary function is outside the resolver.
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "Uint8Array" &&
            (member.v === "from" || member.v === "of")
          ) {
            this.pos += 3;
            const args = this.parseArgs();
            const toByte = (n: number): number => ((Math.trunc(n) % 256) + 256) % 256;
            if (member.v === "of") {
              const bytes: number[] = [];
              for (const a of args) {
                const n = a === null ? null : toNum(a);
                if (n === null) return null;
                bytes.push(toByte(n));
              }
              v = { kind: "array", items: bytes.map((b) => ({ kind: "number" as const, value: b })) };
            } else {
              if (args.length > 1 && args[1] !== undefined) return null;
              const src = args[0];
              if (src === undefined || src === null) return null;
              if (src.kind === "array") {
                const bytes: number[] = [];
                for (const it of src.items) {
                  const n = toNum(it);
                  if (n === null) return null;
                  bytes.push(toByte(n));
                }
                v = { kind: "array", items: bytes.map((b) => ({ kind: "number" as const, value: b })) };
              } else if (src.kind === "string") {
                v = {
                  kind: "array",
                  items: [...Buffer.from(src.value, "utf8")].map((b) => ({ kind: "number" as const, value: b })),
                };
              } else {
                return null;
              }
            }
            continue;
          }
          // JSON.parse of a resolved string (round 6): the parsed value
          // is modeled, so member reads on it resolve.
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "JSON" &&
            member.v === "parse"
          ) {
            this.pos += 3;
            const args = this.parseArgs();
            const data = args[0];
            if (data === undefined || data === null || data.kind !== "string") return null;
            try {
              v = jsonToValue(JSON.parse(data.value), 0);
            } catch {
              return null;
            }
            continue;
          }
          // Array.from / Array.of (round 6). A mapFn is applied per
          // element when it is a diff-defined function; any other
          // mapFn leaves the result unknown.
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "Array" &&
            (member.v === "from" || member.v === "of")
          ) {
            this.pos += 3;
            const args = this.parseArgs();
            if (member.v === "of") {
              v = { kind: "array", items: args };
              continue;
            }
            const src = args[0];
            if (src === undefined || src === null) return null;
            let items: Value[];
            if (src.kind === "array") items = [...src.items];
            else if (src.kind === "string") {
              items = [...src.value].map((ch) => ({ kind: "string" as const, value: ch }));
            } else {
              return null;
            }
            const mapFn = args[1];
            if (mapFn !== undefined) {
              if (mapFn === null || mapFn.kind !== "function") return null;
              const mapped: Value[] = [];
              for (let idx = 0; idx < items.length; idx++) {
                const outs = evaluateFunction(
                  mapFn.def,
                  [items[idx], { kind: "number", value: idx }],
                  this.env,
                  this.ctx,
                );
                if (outs.length !== 1) return null;
                mapped.push(outs[0]);
              }
              items = mapped;
            }
            v = { kind: "array", items };
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
            const out = evalStringMethod(v.value, member.v, args, this.env, this.ctx);
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
          // TextDecoder().decode(bytes) / TextEncoder().encode(string)
          // (round 6; the byte codec itself is Buffer, which is exact
          // for UTF-8 — the only label this models).
          if (v !== null && v.kind === "textdecoder" && member.v === "decode") {
            this.pos += 3;
            const args = this.parseArgs();
            const data = args[0];
            if (data === undefined || data === null || data.kind !== "array") return null;
            const bytes: number[] = [];
            for (const it of data.items) {
              const n = toNum(it);
              if (n === null) return null;
              bytes.push(((Math.trunc(n) % 256) + 256) % 256);
            }
            v = { kind: "string", value: Buffer.from(bytes).toString("utf8") };
            continue;
          }
          if (v !== null && v.kind === "textencoder" && member.v === "encode") {
            this.pos += 3;
            const args = this.parseArgs();
            const data = args[0];
            if (data === undefined || data === null || data.kind !== "string") return null;
            v = {
              kind: "array",
              items: [...Buffer.from(data.value, "utf8")].map((b) => ({ kind: "number" as const, value: b })),
            };
            continue;
          }
          // Method call on an object whose property is a diff-defined
          // function value: evaluate it (round 6).
          if (v !== null && v.kind === "object") {
            const fn = v.props.get(member.v);
            if (fn !== undefined && fn !== null && fn.kind === "function") {
              this.pos += 3;
              const args = this.parseArgs();
              const outs = evaluateFunction(fn.def, args, this.env, this.ctx);
              v = outs.length === 1 ? outs[0] : null;
              continue;
            }
          }
          // Any other method call: unknown result; consume args and stop.
          this.pos += 3;
          this.parseArgs();
          return null;
        }
        // Property access (not a call): on an object receiver this
        // resolves the member (round 5); `.length` on a string/array
        // receiver is a number (round 6 — previously the receiver was
        // left unchanged, which over-flagged `secret.length`); on any
        // other receiver the value is unchanged.
        if (v !== null && v.kind === "object") {
          v = v.props.get(member.v) ?? null;
        } else if (
          member.v === "length" &&
          v !== null &&
          (v.kind === "string" || v.kind === "array")
        ) {
          v = { kind: "number", value: v.kind === "string" ? v.value.length : v.items.length };
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

  /** Parse an arrow-function body starting at `bodyStart`; null if unparseable. */
  private parseArrowBody(params: FuncParam[], bodyStart: number): FuncDef | null {
    const bodyTok = this.toks[bodyStart];
    if (bodyTok === undefined) return null;
    if (bodyTok.t === "punct" && bodyTok.v === "{") {
      const end = matchBracket(this.toks, bodyStart);
      if (end === -1) return null;
      this.pos = end + 1;
      return { params, bodyToks: this.toks.slice(bodyStart + 1, end), isBlock: true };
    }
    const end = findExprEnd(this.toks, bodyStart);
    if (end === bodyStart) return null;
    this.pos = end;
    return { params, bodyToks: this.toks.slice(bodyStart, end), isBlock: false };
  }

  private parsePrimary(): Value {
    const tok = this.peek();
    if (!tok) return null;
    // Prefix ++ / --: JS yields the NEW value.
    if (tok.t === "punct" && (tok.v === "++" || tok.v === "--")) {
      this.pos++;
      const operand = this.parsePostfix();
      const n = toNum(operand);
      if (n === null) return null;
      return { kind: "number", value: tok.v === "++" ? n + 1 : n - 1 };
    }
    // Unary + / -: numeric coercion (a non-numeric operand is unknown).
    if (tok.t === "punct" && (tok.v === "-" || tok.v === "+")) {
      this.pos++;
      const operand = this.parsePostfix();
      if (operand === null) return null;
      if (operand.kind === "number") {
        return { kind: "number", value: tok.v === "-" ? -operand.value : operand.value };
      }
      const n = toNum(operand);
      if (n === null) return null;
      return { kind: "number", value: tok.v === "-" ? -n : n };
    }
    if (tok.t === "string") {
      this.pos++;
      return { kind: "string", value: tok.v };
    }
    if (tok.t === "number") {
      this.pos++;
      const n = Number(tok.v);
      return Number.isNaN(n) ? { kind: "string", value: tok.v } : { kind: "number", value: n };
    }
    if (tok.t === "template") {
      this.pos++;
      return this.evalTemplate(tok.raw);
    }
    if (tok.t === "ident") {
      // Arrow function with a single unparenthesized parameter: x => ...
      const afterIdent = this.peek(1);
      if (afterIdent?.t === "punct" && afterIdent.v === "=>") {
        const def = this.parseArrowBody([{ name: tok.v }], this.pos + 2);
        if (def !== null) return { kind: "function", def };
      }
      // Function expression: function [name] (params) { body }
      if (tok.v === "function") {
        let j = this.pos + 1;
        if (this.toks[j]?.t === "ident") j++;
        const openTok = this.toks[j];
        if (openTok?.t === "punct" && openTok.v === "(") {
          const close = matchBracket(this.toks, j);
          if (close !== -1) {
            const params = parseParams(this.toks.slice(j + 1, close));
            const b = close + 1;
            const braceTok = this.toks[b];
            if (braceTok?.t === "punct" && braceTok.v === "{") {
              const end = matchBracket(this.toks, b);
              if (end !== -1) {
                this.pos = end + 1;
                return { kind: "function", def: { params, bodyToks: this.toks.slice(b + 1, end), isBlock: true } };
              }
            }
          }
        }
        return null;
      }
      // new TextDecoder() / new TextEncoder() / new Uint8Array(...)
      // (round 6). Other constructors evaluate to unknown.
      if (tok.v === "new") {
        const ctor = this.toks[this.pos + 1];
        if (ctor?.t !== "ident") return null;
        let j = this.pos + 2;
        let args: Value[] = [];
        const newParen = this.toks[j];
        if (newParen?.t === "punct" && newParen.v === "(") {
          const close = matchBracket(this.toks, j);
          if (close === -1) return null;
          args = splitTopLevel(this.toks.slice(j + 1, close)).map(
            (s) => new Parser(s, this.env, this.ctx).parseExpr(),
          );
          j = close + 1;
        }
        this.pos = j;
        if (ctor.v === "TextDecoder") {
          const label = args[0];
          if (
            label !== undefined &&
            (label === null || label.kind !== "string" || (label.value !== "utf-8" && label.value !== "utf8"))
          ) {
            return null;
          }
          return { kind: "textdecoder" };
        }
        if (ctor.v === "TextEncoder") return { kind: "textencoder" };
        if (ctor.v === "Uint8Array") {
          if (args.length === 0) return { kind: "array", items: [] };
          const a = args[0];
          if (a !== null && a.kind === "array") return a;
          if (a !== null && a.kind === "number") {
            const n = Math.trunc(a.value);
            if (n < 0 || n > 10000) return null;
            return { kind: "array", items: Array.from({ length: n }, () => ({ kind: "number" as const, value: 0 })) };
          }
          return { kind: "array", items: [] };
        }
        return null;
      }
      this.pos++;
      if (tok.v === "true") return { kind: "string", value: "true" };
      if (tok.v === "false") return { kind: "string", value: "false" };
      if (tok.v === "null") return { kind: "string", value: "null" };
      if (tok.v === "undefined") return { kind: "string", value: "undefined" };
      if (tok.v === "NaN") return { kind: "number", value: NaN };
      if (tok.v === "Infinity") return { kind: "number", value: Infinity };
      // Bare calls with known semantics (round 6 adds the decoders):
      // String(x) coerces, atob(x) base64-decodes, decodeURIComponent /
      // decodeURI / unescape decode their argument. Other bare calls
      // are not consumed here (the callee binding evaluates to unknown,
      // as before — unless it is a diff-defined function, handled by
      // the call logic in parsePostfix).
      if (
        (tok.v === "String" || tok.v === "atob" || tok.v === "decodeURIComponent" ||
          tok.v === "decodeURI" || tok.v === "unescape") &&
        this.peekPunct("(")
      ) {
        this.pos++;
        const args = this.parseArgs();
        if (tok.v === "String") {
          const s = args.length === 0 ? "" : coerceToString(args[0]);
          return s === null ? null : { kind: "string", value: s };
        }
        const data = args[0];
        if (data === undefined || data === null || data.kind !== "string") return null;
        if (tok.v === "atob") {
          const decoded = decodeBase64(data.value, false);
          return decoded === null ? null : { kind: "string", value: decoded };
        }
        try {
          const decoded = tok.v === "decodeURIComponent"
            ? decodeURIComponent(data.value)
            : tok.v === "decodeURI"
              ? decodeURI(data.value)
              : unescapeJs(data.value);
          return { kind: "string", value: decoded };
        } catch {
          return null;
        }
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
      // Arrow function: (params) => body
      const close = matchBracket(this.toks, this.pos);
      const arrowTok = close === -1 ? undefined : this.toks[close + 1];
      if (close !== -1 && arrowTok?.t === "punct" && arrowTok.v === "=>") {
        const params = parseParams(this.toks.slice(this.pos + 1, close));
        const def = this.parseArrowBody(params, close + 2);
        if (def !== null) return { kind: "function", def };
      }
      this.pos++;
      let v = this.parseExpr();
      // Comma operator in parens: (a, b) evaluates to b.
      while (this.peekPunct(",")) {
        this.pos++;
        v = this.parseExpr();
      }
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
        const sub = new Parser(tokenize(raw.slice(i + 2, close)), this.env, this.ctx);
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

// ---- function modeling (round 6) ----

/**
 * Evaluation context threaded through parsers: the diff-defined
 * functions, the call depth (recursion guard), the functions already
 * on the call stack (cycle guard), and a shared step budget that
 * bounds pathological helper bodies.
 */
interface EvalCtx {
  funcs: Map<string, FuncDef>;
  depth: number;
  stack: Set<FuncDef>;
  steps: { count: number };
}

function defaultCtx(): EvalCtx {
  return { funcs: new Map(), depth: 0, stack: new Set(), steps: { count: 0 } };
}

/** Collect `function name(params) { body }` declarations from the diff. */
function collectFunctions(toks: Tok[]): Map<string, FuncDef> {
  const map = new Map<string, FuncDef>();
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "ident" || t.v !== "function") continue;
    const nameTok = toks[i + 1];
    const open = toks[i + 2];
    if (nameTok?.t !== "ident" || open?.t !== "punct" || open.v !== "(") continue;
    const close = matchBracket(toks, i + 2);
    if (close === -1) continue;
    const b = close + 1;
    if (toks[b]?.t !== "punct" || toks[b].v !== "{") continue;
    const end = matchBracket(toks, b);
    if (end === -1) continue;
    map.set(nameTok.v, {
      params: parseParams(toks.slice(i + 3, close)),
      bodyToks: toks.slice(b + 1, end),
      isBlock: true,
    });
  }
  return map;
}

/**
 * Evaluate a diff-defined function with arguments bound. Returns the
 * list of possible return values: a single value for single-path
 * bodies, several when an unknown condition branches, plus the
 * implicit `undefined` when execution can fall off the end. A
 * recursive call or a depth overflow yields a single unknown.
 */
function evaluateFunction(
  def: FuncDef,
  argValues: Value[],
  outerEnv: Map<string, Value>,
  ctx: EvalCtx,
): Value[] {
  if (ctx.depth > 8 || ctx.stack.has(def)) return [null];
  const env = new Map(outerEnv);
  for (let i = 0; i < def.params.length; i++) {
    const p = def.params[i];
    if (p.rest) {
      env.set(p.name, { kind: "array", items: argValues.slice(i) });
      break;
    }
    if (i < argValues.length) {
      env.set(p.name, argValues[i]);
    } else if (p.defaultToks) {
      const d = new Parser(p.defaultToks, env, ctx);
      env.set(p.name, d.parseExpr());
    } else {
      env.set(p.name, null);
    }
  }
  const next: EvalCtx = {
    funcs: ctx.funcs,
    depth: ctx.depth + 1,
    stack: new Set(ctx.stack).add(def),
    steps: ctx.steps,
  };
  if (!def.isBlock) {
    const p = new Parser(def.bodyToks, env, next);
    const v = p.parseExpr();
    return [p.pos === def.bodyToks.length ? v : null];
  }
  const r = interpretBlock(def.bodyToks, env, next);
  const outs = [...r.returns];
  if (r.flow === "fall") outs.push({ kind: "string", value: "undefined" });
  return outs.length === 0 ? [null] : outs;
}

type BlockFlow = "fall" | "return" | "break" | "continue";

interface BlockResult {
  returns: Value[];
  flow: BlockFlow;
}

/** Extent of the statement starting at `start`: block-inner tokens or one statement. */
function stmtExtent(toks: Tok[], start: number): { toks: Tok[]; next: number } {
  const t = toks[start];
  if (t?.t === "punct" && t.v === "{") {
    const end = matchBracket(toks, start);
    if (end === -1) return { toks: [], next: toks.length };
    return { toks: toks.slice(start + 1, end), next: end + 1 };
  }
  if (t?.t === "ident" && (t.v === "if" || t.v === "for" || t.v === "while")) {
    let j = start + 1;
    const parenTok = toks[j];
    if (parenTok?.t === "punct" && parenTok.v === "(") {
      const close = matchBracket(toks, j);
      if (close === -1) return { toks: toks.slice(start), next: toks.length };
      j = close + 1;
    }
    const body = stmtExtent(toks, j);
    let next = body.next;
    const elseTok = toks[next];
    if (t.v === "if" && elseTok?.t === "ident" && elseTok.v === "else") {
      const e = stmtExtent(toks, next + 1);
      next = e.next;
    }
    return { toks: toks.slice(start, next), next };
  }
  const end = findStmtEnd(toks, start);
  const next = end < toks.length && toks[end]?.t === "punct" && toks[end].v === ";" ? end + 1 : end;
  return { toks: toks.slice(start, end), next };
}

/** Index just past a statement we do not interpret (while/switch/try/do). */
function skipStatement(toks: Tok[], start: number): number {
  const t = toks[start];
  if (t?.t === "ident" && t.v === "do") {
    const body = stmtExtent(toks, start + 1);
    let next = body.next;
    const whileTok = toks[next];
    if (whileTok?.t === "ident" && whileTok.v === "while") {
      const open = next + 1;
      const close = open < toks.length && toks[open]?.t === "punct" && toks[open].v === "("
        ? matchBracket(toks, open)
        : -1;
      next = close === -1 ? toks.length : close + 1;
      const semi = toks[next];
      if (semi?.t === "punct" && semi.v === ";") next++;
    }
    return next;
  }
  let j = start + 1;
  const parenTok = toks[j];
  if (parenTok?.t === "punct" && parenTok.v === "(") {
    const close = matchBracket(toks, j);
    if (close === -1) return toks.length;
    j = close + 1;
  }
  const body = stmtExtent(toks, j);
  let next = body.next;
  if (t?.t === "ident" && t.v === "try") {
    for (;;) {
      const catchTok = toks[next];
      if (!(catchTok?.t === "ident" && (catchTok.v === "catch" || catchTok.v === "finally"))) break;
      let k = next + 1;
      const catchParen = toks[k];
      if (catchParen?.t === "punct" && catchParen.v === "(") {
        const close = matchBracket(toks, k);
        if (close === -1) return toks.length;
        k = close + 1;
      }
      const b = stmtExtent(toks, k);
      next = b.next;
    }
  }
  return next;
}

/**
 * Interpret a token slice as a statement list. Assignments, +=, push,
 * and ++/-- mutate `env`; `return`/`break`/`continue` end the block
 * with that flow. Unsupported statements are skipped, not fatal —
 * the return value is what the scan needs, and skipping an unknown
 * statement keeps later returns reachable. Unknown conditions
 * evaluate BOTH branches and union their returns (fail-closed for
 * scanning); branch assignments are dropped in that case.
 */
function interpretBlock(toks: Tok[], env: Map<string, Value>, ctx: EvalCtx): BlockResult {
  const returns: Value[] = [];
  let i = 0;
  while (i < toks.length) {
    if (ctx.steps.count++ > 20000) break;
    const t = toks[i];
    if (t.t === "punct" && t.v === ";") {
      i++;
      continue;
    }
    if (t.t === "ident" && t.v === "return") {
      const end = findStmtEnd(toks, i + 1);
      const p = new Parser(toks.slice(i + 1, end), env, ctx);
      returns.push(p.parseExpr());
      return { returns, flow: "return" };
    }
    if (t.t === "ident" && t.v === "throw") return { returns, flow: "return" };
    if (t.t === "ident" && (t.v === "break" || t.v === "continue")) {
      return { returns, flow: t.v as BlockFlow };
    }
    if (t.t === "ident" && t.v === "if") {
      const r = interpretIf(toks, i, env, ctx);
      returns.push(...r.returns);
      if (r.flow !== "fall") return { returns, flow: r.flow };
      i = r.next;
      continue;
    }
    if (t.t === "ident" && t.v === "for") {
      const r = interpretForOf(toks, i, env, ctx);
      returns.push(...r.returns);
      if (r.flow === "return") return { returns, flow: "return" };
      i = r.next;
      continue;
    }
    if (t.t === "punct" && t.v === "{") {
      const end = matchBracket(toks, i);
      if (end === -1) break;
      const r = interpretBlock(toks.slice(i + 1, end), env, ctx);
      returns.push(...r.returns);
      if (r.flow !== "fall") return { returns, flow: r.flow };
      i = end + 1;
      continue;
    }
    if (t.t === "ident" && (t.v === "while" || t.v === "switch" || t.v === "try" || t.v === "do")) {
      i = skipStatement(toks, i);
      continue;
    }
    const end = findStmtEnd(toks, i);
    execSimple(toks.slice(i, end), env, ctx);
    i = end < toks.length && toks[end]?.t === "punct" && toks[end].v === ";" ? end + 1 : end;
  }
  return { returns, flow: "fall" };
}

function interpretIf(
  toks: Tok[],
  start: number,
  env: Map<string, Value>,
  ctx: EvalCtx,
): BlockResult & { next: number } {
  const open = start + 1;
  const close = open < toks.length && toks[open]?.t === "punct" && toks[open].v === "("
    ? matchBracket(toks, open)
    : -1;
  if (close === -1) return { returns: [], flow: "fall", next: toks.length };
  const condToks = toks.slice(open + 1, close);
  const thenRes = stmtExtent(toks, close + 1);
  let next = thenRes.next;
  let elseToks: Tok[] | null = null;
  const elseTok = toks[next];
  if (elseTok?.t === "ident" && elseTok.v === "else") {
    const elseRes = stmtExtent(toks, next + 1);
    elseToks = elseRes.toks;
    next = elseRes.next;
  }
  const condParser = new Parser(condToks, env, ctx);
  const cond = condParser.parseExpr();
  const truthy = cond === null
    ? null
    : cond.kind === "string"
      ? cond.value === "true" ? true : cond.value === "false" ? false : null
      : cond.kind === "number"
        ? cond.value !== 0 && !Number.isNaN(cond.value)
        : null;
  if (truthy === true) {
    const r = interpretBlock(thenRes.toks, env, ctx);
    return { returns: r.returns, flow: r.flow, next };
  }
  if (truthy === false) {
    if (elseToks === null) return { returns: [], flow: "fall", next };
    const r = interpretBlock(elseToks, env, ctx);
    return { returns: r.returns, flow: r.flow, next };
  }
  const returns: Value[] = [];
  const rThen = interpretBlock(thenRes.toks, new Map(env), ctx);
  returns.push(...rThen.returns);
  let elseFlow: BlockFlow = "fall";
  if (elseToks !== null) {
    const rElse = interpretBlock(elseToks, new Map(env), ctx);
    returns.push(...rElse.returns);
    elseFlow = rElse.flow;
  }
  const thenFalls = rThen.flow === "fall";
  if (thenFalls || elseFlow === "fall") return { returns, flow: "fall", next };
  if (rThen.flow === elseFlow) return { returns, flow: rThen.flow, next };
  return { returns, flow: "fall", next };
}

function interpretForOf(
  toks: Tok[],
  start: number,
  env: Map<string, Value>,
  ctx: EvalCtx,
): BlockResult & { next: number } {
  const open = start + 1;
  const close = open < toks.length && toks[open]?.t === "punct" && toks[open].v === "("
    ? matchBracket(toks, open)
    : -1;
  if (close === -1) return { returns: [], flow: "fall", next: toks.length };
  const header = toks.slice(open + 1, close);
  let ofIdx = -1;
  let depth = 0;
  for (let k = 0; k < header.length; k++) {
    const h = header[k];
    if (h.t === "punct" && (h.v === "(" || h.v === "[" || h.v === "{")) depth++;
    else if (h.t === "punct" && (h.v === ")" || h.v === "]" || h.v === "}")) depth--;
    else if (depth === 0 && h.t === "ident" && h.v === "of") {
      ofIdx = k;
      break;
    }
  }
  const body = stmtExtent(toks, close + 1);
  if (ofIdx === -1) {
    // Not for..of (e.g. a classic for loop): skip the whole statement.
    return { returns: [], flow: "fall", next: body.next };
  }
  let loopVar: string | null = null;
  for (let k = ofIdx - 1; k >= 0; k--) {
    const h = header[k];
    if (h.t === "ident" && h.v !== "const" && h.v !== "let" && h.v !== "var") {
      loopVar = h.v;
      break;
    }
  }
  if (loopVar === null) return { returns: [], flow: "fall", next: body.next };
  const p = new Parser(header.slice(ofIdx + 1), env, ctx);
  const arrVal = p.parseExpr();
  const returns: Value[] = [];
  if (arrVal !== null && arrVal.kind === "array") {
    const items = arrVal.items.slice(0, 10000);
    for (const item of items) {
      if (ctx.steps.count++ > 20000) break;
      env.set(loopVar, item);
      const r = interpretBlock(body.toks, env, ctx);
      returns.push(...r.returns);
      if (r.flow === "return") return { returns, flow: "return", next: body.next };
      if (r.flow === "break") break;
    }
  }
  return { returns, flow: "fall", next: body.next };
}

/** Execute one simple statement (assignment, +=, push, ++/--) in a helper body. */
function execSimple(slice: Tok[], env: Map<string, Value>, ctx: EvalCtx): void {
  if (slice.length === 0) return;
  let j = 0;
  const first = slice[0];
  if (first?.t === "ident" && (first.v === "const" || first.v === "let" || first.v === "var")) j = 1;
  const nameTok = slice[j];
  if (nameTok?.t !== "ident") return;
  const after = slice[j + 1];
  if (after?.t === "punct" && (after.v === "=" || after.v === "+=")) {
    const p = new Parser(slice.slice(j + 2), env, ctx);
    const rhs = p.parseExpr();
    if (after.v === "=") {
      if (rhs !== null) env.set(nameTok.v, rhs);
      else env.delete(nameTok.v);
    } else {
      const cur = env.get(nameTok.v);
      const combined = cur !== undefined ? addValues(cur, rhs) : rhs;
      if (combined !== null) env.set(nameTok.v, combined);
      else env.delete(nameTok.v);
    }
    return;
  }
  if (after?.t === "punct" && (after.v === "++" || after.v === "--")) {
    const cur = env.get(nameTok.v);
    const n = cur === undefined ? null : toNum(cur);
    if (n === null) {
      env.delete(nameTok.v);
      return;
    }
    env.set(nameTok.v, { kind: "number", value: after.v === "++" ? n + 1 : n - 1 });
    return;
  }
  const pushName = slice[j + 2];
  const pushOpen = slice[j + 3];
  if (
    after?.t === "punct" && after.v === "." &&
    pushName?.t === "ident" && pushName.v === "push" &&
    pushOpen?.t === "punct" && pushOpen.v === "("
  ) {
    const close = matchBracket(slice, j + 3);
    if (close === -1) return;
    const args = splitTopLevel(slice.slice(j + 4, close)).map(
      (s) => new Parser(s, env, ctx).parseExpr(),
    );
    const cur = env.get(nameTok.v);
    if (cur !== undefined && cur !== null && cur.kind === "array") {
      cur.items.push(...args);
    } else if (cur === undefined) {
      env.set(nameTok.v, { kind: "array", items: args });
    }
    return;
  }
  const keys: string[] = [nameTok.v];
  let k = j + 1;
  let ok = true;
  while (true) {
    const sep = slice[k];
    const keyTok = slice[k + 1];
    if (sep?.t === "punct" && sep.v === "." && keyTok?.t === "ident") {
      keys.push(keyTok.v);
      k += 2;
      continue;
    }
    if (sep?.t === "punct" && sep.v === "[") {
      const inner = slice[k + 1];
      const closeTok = slice[k + 2];
      if (
        (inner?.t === "string" || inner?.t === "number") &&
        closeTok?.t === "punct" && closeTok.v === "]"
      ) {
        keys.push(inner.v);
        k += 3;
        continue;
      }
      if (inner?.t === "ident" && closeTok?.t === "punct" && closeTok.v === "]") {
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
  const eqTok = slice[k];
  if (ok && keys.length > 1 && eqTok?.t === "punct" && (eqTok.v === "=" || eqTok.v === "+=")) {
    const p = new Parser(slice.slice(k + 1), env, ctx);
    const rhs = p.parseExpr();
    applyMemberAssign(env, keys, rhs, eqTok.v === "+=", "sequential");
    return;
  }
  // Anything else: a side-effect-free expression statement, ignored.
}

/**
 * Call-site scan pass (round 6). For every call to a diff-defined
 * function in the diff, evaluate the body with the call's arguments
 * and scan every possible return value — this catches multi-path
 * bodies (unknown-condition branches) that single-value expression
 * evaluation must leave unknown. Plus the conservative fallback:
 * concatenating the call's raw string-literal arguments (and
 * array-literal elements) in order is scanned too, so an intractable
 * body that merely forwards its literal fragments still trips the
 * scan. The fallback only fires when the concatenation itself is
 * secret-shaped, so honest helpers are untouched.
 */
function scanCallSites(
  toks: Tok[],
  env: Map<string, Value>,
  ctx: EvalCtx,
  add: (text: string) => void,
): void {
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t !== "ident") continue;
    const open = toks[i + 1];
    if (open?.t !== "punct" || open.v !== "(") continue;
    const prev = toks[i - 1];
    if (prev?.t === "punct" && prev.v === ".") continue; // method call
    if (prev?.t === "ident" && prev.v === "function") continue; // declaration
    const callee = env.get(t.v);
    if (callee === undefined || callee === null || callee.kind !== "function") continue;
    const close = matchBracket(toks, i + 1);
    if (close === -1) continue;
    const argSlices = splitTopLevel(toks.slice(i + 2, close));
    const argValues = argSlices.map((s) => new Parser(s, env, ctx).parseExpr());
    const outs = evaluateFunction(callee.def, argValues, env, ctx);
    for (const o of outs) {
      if (o !== null && o.kind === "string") add(o.value);
    }
    let concat = "";
    let any = false;
    for (const s of argSlices) {
      const lit = rawLiteralConcat(s);
      if (lit !== null) {
        concat += lit;
        any = true;
      }
    }
    if (any) add(concat);
  }
}

/** A slice's value if it is a string literal, a substitution-free template, or an array of string literals. */
function rawLiteralConcat(slice: Tok[]): string | null {
  if (slice.length === 1 && slice[0].t === "string") return slice[0].v;
  if (slice.length === 1 && slice[0].t === "template" && !slice[0].raw.includes("${")) {
    return slice[0].raw;
  }
  const firstTok = slice[0];
  const lastTok = slice[slice.length - 1];
  if (
    slice.length >= 2 &&
    firstTok.t === "punct" && firstTok.v === "[" &&
    lastTok.t === "punct" && lastTok.v === "]"
  ) {
    const inner = slice.slice(1, slice.length - 1);
    let out = "";
    let expectValue = true;
    for (const tok of inner) {
      if (tok.t === "punct" && tok.v === ",") {
        if (expectValue) return null;
        expectValue = true;
        continue;
      }
      if (tok.t === "string" && expectValue) {
        out += tok.v;
        expectValue = false;
        continue;
      }
      return null;
    }
    return out;
  }
  return null;
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
  ctx: EvalCtx = defaultCtx(),
): boolean {
  let changed = false;
  const p = new Parser(toks, env, ctx);
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
  const funcs = collectFunctions(toks);
  const ctx: EvalCtx = { funcs, depth: 0, stack: new Set(), steps: { count: 0 } };
  // Sequential environment: diff order, last-write-wins, pushes in order.
  const envA = new Map<string, Value>();
  for (const [name, def] of funcs) envA.set(name, { kind: "function", def });
  walkStatements(toks, envA, "sequential", ctx);
  // Fixpoint environment: assignments only, first-write-wins, iterated
  // to stability — the fail-closed net for forward references.
  const envB = new Map<string, Value>();
  for (const [name, def] of funcs) envB.set(name, { kind: "function", def });
  for (let pass = 0; pass < 10; pass++) {
    if (!walkStatements(toks, envB, "fixpoint", ctx)) break;
  }
  for (const env of [envA, envB]) {
    for (const v of env.values()) {
      if (v !== null && v.kind === "string") add(v.value);
    }
    // Bare expressions anywhere in the diff, evaluated with the final
    // environment: reconstructions that are never assigned (call
    // arguments, return values, conditions, ternary branches).
    const p = new Parser(toks, env, ctx);
    while (!p.atEnd()) {
      const start = p.pos;
      const v = p.parseExpr();
      if (v !== null && v.kind === "string") add(v.value);
      p.pos = v !== null ? Math.max(p.pos, start + 1) : start + 1;
    }
    // Call-site scan pass (round 6): multi-path function outcomes
    // plus the raw-literal-argument fallback.
    scanCallSites(toks, env, ctx, add);
  }
  return [...hits];
}

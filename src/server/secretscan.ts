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
 * - multi-valued results (round 6b): when a diff-defined call's body
 *   yields several possible returns, the call result is the SET of
 *   those values (capped at 16, branch order), and `+`, `concat`,
 *   `join`, string methods, member/index reads, template
 *   substitutions, and `String`/`atob`/decoder calls distribute over
 *   the set — so a branchy helper's fragments combined with further
 *   expressions at the call site are caught. Plus the
 *   resolved-argument fallback: the conservative fallback above,
 *   computed over RESOLVED argument values (variables bound to
 *   literals/arrays in the diff, sets fanning out to their members)
 *   instead of raw literals, so fragments held in variables are
 *   caught even when the helper body is intractable. An argument
 *   that does not fully resolve skips the resolved fallback for
 *   that call (its fragments are still scanned individually).
 * - set distribution, completed (round 7): `for...of` loops are
 *   interpreted at the top level as well as in helper bodies, and a
 *   set-valued iterable fans out to its member arrays (set items
 *   inside an array distribute through the body); modeled builtins
 *   distribute over set arguments (`JSON.parse`, `Buffer.from`,
 *   `fromCharCode`/`fromCodePoint`, `Uint8Array.from`/`of`,
 *   `Array.from`, and the decoders); function-valued `replace`
 *   callbacks with multi-path bodies yield branch-union sets that
 *   distribute through the replacement; array `slice` and `reverse`
 *   are modeled (slice on arrays was also unmodeled before round 7,
 *   so a slice().reverse() chain died at slice()).
 * - spread argument-list variants (round 8): a spread of a
 *   set-valued array fans out to one argument list per member
 *   array, because a spread changes arity and a single flat list
 *   cannot represent "one of these argument lists" — without this,
 *   `String.fromCharCode(...pickCodes(flag))` collapsed to one set
 *   argument that the per-code distribution saw as an array and
 *   gave up on. Spread of a non-array stays a single argument.
 * - `.apply()` / `.call()` (round 9): apply/call forms rewrite to
 *   the equivalent direct call and are re-parsed with the same
 *   environment, so every call form above evaluates identically in
 *   apply/call form — `fn.apply(thisArg, argArray)` becomes
 *   `fn(...argArray)`, `fn.call(thisArg, ...args)` becomes
 *   `fn(...args)`, and `Reflect.apply(fn, thisArg, argArray)`
 *   (recognized by its receiver tokens, only when `Reflect` is
 *   unbound) becomes `fn(...argArray)`. An own apply/call property
 *   on an object receiver is a plain method call, not
 *   Function.prototype.apply, and falls through. `.push.apply()` /
 *   `.push.call()` are side effects, not values: they append into
 *   the thisArg array (exact JS semantics) in the statement walk
 *   and in helper bodies, and in the Parser in sequential mode
 *   only (the fixpoint pass is assignments-only).
 *
 * Deliberately NOT modeled (stays unknown, never flagged alone):
 * - recursion, closures over mutated state, classes, `eval`, and
 *   genuinely complex control flow (classic `for` loops, `while`,
 *   `switch`, `try` bodies are skipped, not interpreted — a helper
 *   with such a body is still caught when called with fragments,
 *   literal or variable-held, via the fallbacks, but a body that
 *   TRANSFORMS its inputs rather than forwarding them is not
 *   modeled); method calls on objects whose property is a
 *   multi-path function (single-path object methods DO resolve)
 * - transform-aware obfuscation (round 7 stopping boundary): custom
 *   ciphers, custom encodings, and reorder tricks beyond `reverse`
 *   are undecidable for static analysis in general. A diff carrying
 *   a cipher and only encoded fragments contains no secret halves
 *   in any form, and the decoder itself is a visible tell in the PR
 *   diff — maintainer PR review is the backstop here, not the scan.
 *   Likewise values from outside the diff (see below).
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
/**
 * Multi-valued result (round 6b): when a diff-defined call's body
 * yields several possible returns (unknown-condition branches), the
 * call result is the SET of those values, not unknown — so later
 * operations distribute over the set and combinations that form a
 * secret are caught (previously each branch outcome was scanned
 * alone, but never combined with further expressions at the call
 * site). Members are never sets (flattened on construction) and
 * never null (filtered); the set is capped at SET_CAP values, first
 * in branch order — truncation keeps genuine possible values, so it
 * can only miss a combination past the cap, never fabricate one.
 */
type SetVal = { kind: "set"; values: Value[] };
type Value =
  | StrVal
  | NumVal
  | ArrVal
  | ObjVal
  | RegexVal
  | TextDecoderVal
  | TextEncoderVal
  | FuncVal
  | SetVal
  | null;

const SET_CAP = 16;

/** Build a set value: flatten nested sets, drop nulls, dedup scalars, cap. */
function makeSet(values: Value[]): Value {
  const out: Value[] = [];
  const seen = new Set<string>();
  const push = (v: Value): void => {
    if (v === null) return;
    if (v.kind === "set") {
      for (const m of v.values) push(m);
      return;
    }
    if (v.kind === "string" || v.kind === "number") {
      const k = `${v.kind}:${String(v.value)}`;
      if (seen.has(k)) return;
      seen.add(k);
    }
    out.push(v);
  };
  for (const v of values) push(v);
  if (out.length === 0) return null;
  if (out.length === 1) return out[0];
  return { kind: "set", values: out.slice(0, SET_CAP) };
}

/**
 * Distribute fn over set-valued inputs: the cross product of the
 * members, capped at SET_CAP results (first in deterministic order).
 * Inputs without sets call fn directly, unchanged. Null results are
 * dropped (that combination is unknown); all-null yields null.
 */
function distribute(inputs: Value[], fn: (concrete: Value[]) => Value): Value {
  if (!inputs.some((v) => v !== null && v.kind === "set")) return fn(inputs);
  const options: Value[][] = inputs.map((v) =>
    v !== null && v.kind === "set" ? v.values : [v],
  );
  const results: Value[] = [];
  const walk = (idx: number, acc: Value[]): void => {
    if (results.length >= SET_CAP) return;
    if (idx === options.length) {
      const r = fn(acc);
      if (r !== null) results.push(r);
      return;
    }
    for (const o of options[idx]) {
      walk(idx + 1, [...acc, o]);
      if (results.length >= SET_CAP) return;
    }
  };
  walk(0, []);
  return makeSet(results);
}

/** Map a possibly-set value through fn, distributing over members. */
function mapSetValues(v: Value, fn: (x: Value) => Value): Value {
  if (v === null || v.kind !== "set") return fn(v);
  return makeSet(v.values.map(fn));
}

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

/** JS `+` semantics: number + number sums, anything else string-concatenates. Sets distribute. */
function addValues(a: Value, b: Value): Value {
  if ((a !== null && a.kind === "set") || (b !== null && b.kind === "set")) {
    return distribute([a, b], ([x, y]) => addValuesSingle(x, y));
  }
  return addValuesSingle(a, b);
}

function addValuesSingle(a: Value, b: Value): Value {
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
 * The callback is evaluated per match with the JS callback arguments.
 * Round 7: a multi-path callback body yields a branch-union SET of
 * possible replacements (previously the whole replacement went
 * unknown unless the body had exactly one outcome), and the result
 * distributes over that set — so a branchy callback's fragments
 * combined with further expressions at the call site are caught.
 * A branch outcome that is unknown is dropped, never fabricated:
 * only known possible replacements contribute, and if every outcome
 * is unknown the whole replacement is unknown.
 */
function replaceWithCallback(
  recv: string,
  search: Value,
  all: boolean,
  def: FuncDef,
  env: Map<string, Value>,
  ctx: EvalCtx,
): Value {
  const call = (match: string, groups: string[], offset: number): Value => {
    const cbArgs: Value[] = [
      { kind: "string", value: match },
      ...groups.map((g) => ({ kind: "string", value: g }) as Value),
      { kind: "number", value: offset },
      { kind: "string", value: recv },
    ];
    const outs = evaluateFunction(def, cbArgs, env, ctx);
    const strs: Value[] = [];
    for (const o of outs) {
      if (o === null) continue;
      if (o.kind === "set") {
        // A callback returning a branchy value contributes each
        // member as a possible replacement.
        for (const m of o.values) {
          const ms = coerceToString(m);
          if (ms === null) continue;
          strs.push({ kind: "string", value: ms });
        }
        continue;
      }
      const s = coerceToString(o);
      if (s === null) continue;
      strs.push({ kind: "string", value: s });
    }
    return makeSet(strs);
  };
  if (search === null) return null;
  // Collect matches in order. For string needles this is exactly JS
  // replace semantics (non-overlapping, left to right; an empty
  // needle matches at every position); for regexes it mirrors the
  // global-exec loop (with the empty-match lastIndex++ rule).
  interface RepMatch {
    start: number;
    end: number;
    text: string;
    groups: string[];
  }
  const matches: RepMatch[] = [];
  if (search.kind === "string") {
    const needle = search.value;
    if (!all) {
      const idx = recv.indexOf(needle);
      if (idx !== -1) {
        matches.push({ start: idx, end: idx + needle.length, text: needle, groups: [] });
      }
    } else if (needle === "") {
      for (let k = 0; k <= recv.length; k++) {
        matches.push({ start: k, end: k, text: "", groups: [] });
      }
    } else {
      let from = 0;
      for (;;) {
        const idx = recv.indexOf(needle, from);
        if (idx === -1) break;
        matches.push({ start: idx, end: idx + needle.length, text: needle, groups: [] });
        from = idx + needle.length;
      }
    }
  } else if (search.kind === "regex") {
    let re: RegExp;
    try {
      re = new RegExp(search.pattern, search.flags);
    } catch {
      return null;
    }
    if (all && !re.flags.includes("g")) return null;
    const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
    const global = new RegExp(re.source, flags);
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = global.exec(recv)) !== null) {
      if (guard++ > recv.length + 1) return null;
      // Unmatched groups arrive as undefined in JS; our model uses the
      // "undefined" string, matching the existing convention.
      matches.push({
        start: m.index,
        end: m.index + m[0].length,
        text: m[0],
        groups: m.slice(1).map((g) => (g === undefined ? "undefined" : g)),
      });
      if (m[0].length === 0) global.lastIndex++;
      if (!all) break;
    }
  } else {
    return null;
  }
  if (matches.length === 0) return { kind: "string", value: recv };
  // Candidate-set accumulation: start from the empty prefix and, per
  // match, append the intervening segment plus each possible
  // replacement. Set results are capped by makeSet (16, branch
  // order) — truncation can only miss a combination, never invent one.
  let candidates: Value[] = [{ kind: "string", value: "" }];
  let last = 0;
  for (const mt of matches) {
    const rep = call(mt.text, mt.groups, mt.start);
    if (rep === null) return null;
    const repMembers: Value[] = rep.kind === "set" ? rep.values : [rep];
    const next: Value[] = [];
    for (const cand of candidates) {
      if (cand === null || cand.kind !== "string") continue;
      for (const r of repMembers) {
        const s = coerceToString(r);
        if (s === null) continue;
        next.push({ kind: "string", value: cand.value + recv.slice(last, mt.start) + s });
      }
    }
    const capped = makeSet(next);
    candidates = capped === null ? [] : capped.kind === "set" ? capped.values : [capped];
    if (candidates.length === 0) return null;
    last = mt.end;
  }
  const finals: Value[] = [];
  for (const cand of candidates) {
    if (cand !== null && cand.kind === "string") {
      finals.push({ kind: "string", value: cand.value + recv.slice(last) });
    }
  }
  return makeSet(finals);
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

/** Index read arr[i] / obj["key"] / str[i] for one concrete receiver. */
function readIndex(v: Value, idx: Value): Value {
  if (v !== null && v.kind === "array") {
    const n = numArg(idx);
    if (n === null || n === undefined) return null;
    const item = v.items[n];
    return item === undefined ? null : item;
  }
  if (v !== null && v.kind === "object") {
    const k = coerceToString(idx);
    return k === null ? null : (v.props.get(k) ?? null);
  }
  if (v !== null && v.kind === "string") {
    const n = numArg(idx);
    if (n === null || n === undefined) return null;
    const ch = v.value[n];
    return ch === undefined ? null : { kind: "string", value: ch };
  }
  return null;
}

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
      // with arguments bound (round 6). Multi-path bodies yield a SET
      // of possible returns (round 6b), so later operations
      // distribute over the branches and combinations forming a
      // secret are caught; the call-site scan pass in scanAddedLines
      // additionally flags secrets among the outcomes themselves.
      if (v !== null && v.kind === "function" && this.peekPunct("(")) {
        this.pos++;
        const def = v.def;
        // Round 8: evaluate per argument-list variant, so a spread
        // of a set-valued array binds each variant's items as the
        // parameters instead of collapsing to one set argument.
        const outs = this.parseArgsVariants().flatMap((args) =>
          evaluateFunction(def, args, this.env, this.ctx),
        );
        v = makeSet(outs);
        continue;
      }
      // Set receiver with a postfix chain (round 6b): evaluate the
      // whole remaining chain per member, reusing all existing
      // method/member/index logic with zero duplication. Each member
      // is bound to a temp identifier and the chain tokens are
      // re-parsed against it; a member whose chain does not fully
      // parse contributes nothing. This is what makes methods,
      // member reads, index reads, and further calls all distribute
      // over branch-union results.
      if (v !== null && v.kind === "set" && (this.peekPunct(".") || this.peekPunct("["))) {
        const chainEnd = this.findChainEnd();
        if (chainEnd === this.pos) break;
        const chainToks = this.toks.slice(this.pos, chainEnd);
        const results: Value[] = [];
        for (const m of v.values) {
          const env2 = new Map(this.env);
          env2.set("__wishship_set_member_6b", m);
          const sub = new Parser(
            [{ t: "ident", v: "__wishship_set_member_6b" }, ...chainToks],
            env2,
            this.ctx,
          );
          const r = sub.parseExpr();
          results.push(sub.pos === sub.toks.length ? r : null);
        }
        this.pos = chainEnd;
        v = makeSet(results);
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
          // Round 9: `.apply()` / `.call()` rewrite to the
          // equivalent direct call (see tryApplyCall), so a
          // variadic builtin, modeled builtin, or diff-defined
          // function evaluates identically in apply/call form.
          // An own apply/call property on an object receiver falls
          // through to the plain method-call dispatch below.
          if (member.v === "apply" || member.v === "call") {
            const r = this.tryApplyCall(start, member.v, v);
            if (r !== undefined) {
              if (r === null) return null;
              v = r;
              continue;
            }
          }
          const recvTok = this.toks[start];
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "String" &&
            (member.v === "fromCharCode" || member.v === "fromCodePoint")
          ) {
            this.pos += 3;
            // Round 8: evaluate per argument-list variant, so a
            // spread of a set-valued array expands to individual
            // code arguments per variant (previously the spread
            // set collapsed to one argument, which the per-code
            // distribution saw as an array and gave up on).
            const out = this.evalArgVariants((args) =>
              distribute(args, (concrete) => {
                const codes: number[] = [];
                for (const a of concrete) {
                  if (a !== null && a.kind === "number") {
                    codes.push(a.value);
                  } else if (a !== null && a.kind === "string" && /^-?\d+$/.test(a.value.trim())) {
                    codes.push(parseInt(a.value.trim(), 10));
                  } else {
                    return null;
                  }
                }
                try {
                  return {
                    kind: "string",
                    value: member.v === "fromCharCode"
                      ? String.fromCharCode(...codes)
                      : String.fromCodePoint(...codes),
                  };
                } catch {
                  return null;
                }
              }),
            );
            if (out === null) return null;
            v = out;
            continue;
          }
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "Buffer" &&
            member.v === "from"
          ) {
            this.pos += 3;
            // Round 7: set data / encoding arguments distribute, so
            // Buffer.from over a branchy value decodes each member.
            // Round 8: per argument-list variant, so a spread of a
            // set-valued [data, encoding] pair expands correctly.
            const encDefault: Value = { kind: "string", value: "utf8" };
            const out = this.evalArgVariants((args) =>
              distribute(
                [args[0] ?? null, args[1] === undefined ? encDefault : args[1]],
                (concrete) => {
                  const [d, e] = concrete;
                  if (d === undefined || d === null || d.kind !== "string") return null;
                  const enc = coerceToString(e);
                  if (enc === null) return null;
                  if (enc === "base64" || enc === "base64url") {
                    const decoded = decodeBase64(d.value, enc === "base64url");
                    if (decoded === null) return null;
                    return { kind: "string", value: decoded };
                  }
                  if (
                    enc === "utf8" || enc === "utf-8" || enc === "ascii" ||
                    enc === "latin1" || enc === "binary"
                  ) {
                    return { kind: "string", value: d.value };
                  }
                  if (enc === "hex") {
                    try {
                      return { kind: "string", value: Buffer.from(d.value, "hex").toString("latin1") };
                    } catch {
                      return null;
                    }
                  }
                  return null;
                },
              ),
            );
            if (out === null) return null;
            v = out;
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
            const toByte = (n: number): number => ((Math.trunc(n) % 256) + 256) % 256;
            if (member.v === "of") {
              // Round 7: set arguments distribute over the byte list.
              // Round 8: per argument-list variant, so a spread of a
              // set-valued byte array expands to individual bytes.
              const out = this.evalArgVariants((args) =>
                distribute(args, (concrete) => {
                  const bytes: number[] = [];
                  for (const a of concrete) {
                    const n = a === null ? null : toNum(a);
                    if (n === null) return null;
                    bytes.push(toByte(n));
                  }
                  return { kind: "array", items: bytes.map((b) => ({ kind: "number" as const, value: b })) };
                }),
              );
              if (out === null) return null;
              v = out;
            } else {
              // Round 8: per argument-list variant; a variant with a
              // second (mapFn) argument contributes nothing, as
              // before, instead of killing the other variants.
              const out = this.evalArgVariants((args) => {
                if (args.length > 1 && args[1] !== undefined) return null;
                // Round 7: a set source decodes member by member.
                return mapSetValues(args[0] ?? null, (src) => {
                  if (src === undefined || src === null) return null;
                  if (src.kind === "array") {
                    const bytes: number[] = [];
                    for (const it of src.items) {
                      const n = toNum(it);
                      if (n === null) return null;
                      bytes.push(toByte(n));
                    }
                    return { kind: "array", items: bytes.map((b) => ({ kind: "number" as const, value: b })) };
                  }
                  if (src.kind === "string") {
                    return {
                      kind: "array",
                      items: [...Buffer.from(src.value, "utf8")].map((b) => ({ kind: "number" as const, value: b })),
                    };
                  }
                  return null;
                });
              });
              if (out === null) return null;
              v = out;
            }
            continue;
          }
          // JSON.parse of a resolved string (round 6): the parsed value
          // is modeled, so member reads on it resolve. Round 7: a set
          // argument parses member by member, so a branchy JSON
          // string yields a set of parsed values that member reads
          // then distribute over (via the set-chain case above).
          if (
            this.pos - start === 1 &&
            recvTok?.t === "ident" &&
            recvTok.v === "JSON" &&
            member.v === "parse"
          ) {
            this.pos += 3;
            // Round 8: per argument-list variant (a spread of a
            // set-valued [json] pair expands correctly).
            const out = this.evalArgVariants((args) =>
              mapSetValues(args[0] ?? null, (data) => {
                if (data === undefined || data === null || data.kind !== "string") return null;
                try {
                  return jsonToValue(JSON.parse(data.value), 0);
                } catch {
                  return null;
                }
              }),
            );
            if (out === null) return null;
            v = out;
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
            // Round 8: per argument-list variant, so a spread of a
            // set-valued array expands to individual elements for
            // `of`, and a spread [source, mapFn] pair splits
            // correctly for `from`.
            if (member.v === "of") {
              const out = this.evalArgVariants((args) => ({ kind: "array", items: args }) as Value);
              if (out === null) return null;
              v = out;
              continue;
            }
            const out = this.evalArgVariants((args) => {
              const src = args[0];
              // Round 7: a set source maps member by member to a set
              // of arrays, so later operations distribute over them.
              return mapSetValues(src ?? null, (s) => {
                if (s === undefined || s === null) return null;
                let items: Value[];
                if (s.kind === "array") items = [...s.items];
                else if (s.kind === "string") {
                  items = [...s.value].map((ch) => ({ kind: "string" as const, value: ch }));
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
                    // Multi-path map results become a set item (round 6b)
                    // rather than killing the whole Array.from.
                    mapped.push(makeSet(outs));
                  }
                  items = mapped;
                }
                return { kind: "array", items };
              });
            });
            if (out === null) return null;
            v = out;
            continue;
          }
          if (member.v === "concat" || member.v === "join") {
            this.pos += 3;
            // Round 8: per argument-list variant, so a spread of a
            // set-valued array expands to individual elements.
            const out = this.evalArgVariants((args) =>
              distribute([v, ...args], (concrete) => {
              const [rv, ...rest] = concrete;
              if (member.v === "concat") {
                if (rv === null) return null;
                if (rv.kind === "string") {
                  let sOut = rv.value;
                  for (const a of rest) {
                    const s = coerceToString(a);
                    if (s === null) return null;
                    sOut += s;
                  }
                  return { kind: "string", value: sOut };
                }
                if (rv.kind === "array") {
                  const items = [...rv.items];
                  for (const a of rest) {
                    if (a === null) items.push(null);
                    else if (a.kind === "array") items.push(...a.items);
                    else items.push(a);
                  }
                  return { kind: "array", items };
                }
                return null;
              }
              // join: the receiver array's items may themselves be
              // sets (round 6b, e.g. [pick(flag), "frag"].join("")),
              // so the join distributes over each item's options.
              if (rv === null || rv.kind !== "array") return null;
              const sep = rest.length === 0 ? "," : coerceToString(rest[0]);
              if (sep === null) return null;
              const itemOpts: string[][] = [];
              for (const it of rv.items) {
                if (it !== null && it.kind === "set") {
                  const opts: string[] = [];
                  for (const m of it.values) {
                    const s = coerceToString(m);
                    if (s !== null) opts.push(s);
                  }
                  if (opts.length === 0) return null;
                  itemOpts.push(opts);
                } else {
                  const s = coerceToString(it);
                  if (s === null) return null;
                  itemOpts.push([s]);
                }
              }
              let combos: string[][] = [[]];
              for (const opts of itemOpts) {
                const next: string[][] = [];
                for (const c of combos) {
                  for (const o of opts) {
                    if (next.length >= 256) break;
                    next.push([...c, o]);
                  }
                  if (next.length >= 256) break;
                }
                combos = next;
              }
              return makeSet(
                combos.map((c) => ({ kind: "string" as const, value: c.join(sep) })),
              );
            }));
            if (out === null) return null;
            v = out;
            continue;
          }
          // String methods on a resolved string receiver, computed for
          // real (slice/substring/replace/split/trim/case/...). Set
          // receivers are intercepted by the chain case above; set
          // ARGUMENTS still distribute here.
          if (v !== null && v.kind === "string") {
            this.pos += 3;
            // Round 8: per argument-list variant.
            const out = this.evalArgVariants((args) =>
              distribute([v, ...args], (concrete) => {
                const [rv, ...rest] = concrete;
                if (rv === null || rv.kind !== "string") return null;
                return evalStringMethod(rv.value, member.v, rest, this.env, this.ctx);
              }),
            );
            if (out === null) return null;
            v = out;
            continue;
          }
          // Array methods: at(i) reads an element, toString() joins.
          // Set receivers are intercepted by the chain case above;
          // set index arguments still distribute in `at`.
          if (v !== null && v.kind === "array") {
            if (member.v === "at") {
              this.pos += 3;
              // Round 8: per argument-list variant.
              const out = this.evalArgVariants((args) =>
                distribute([v, ...args], (concrete) => {
                  const [rv, ...rest] = concrete;
                  if (rv === null || rv.kind !== "array") return null;
                  const idx = numArg(rest[0]);
                  if (idx === null || idx === undefined) return null;
                  const item = rv.items[idx];
                  return item === undefined ? null : item;
                }),
              );
              if (out === null) return null;
              v = out;
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
            // Array slice / reverse (round 7): computed with the real
            // JS method on the items list, so slice().reverse().join()
            // chains resolve. Reverse returns a NEW array: JS reverses
            // in place, but the resolver tracks values, not aliasing —
            // copy semantics matches the slice().reverse() chain and
            // never fabricates a value (a later read of the original
            // array simply keeps the old order, a miss, not a flag).
            if (member.v === "slice") {
              this.pos += 3;
              // Round 8: per argument-list variant; a variant with
              // unresolvable bounds contributes nothing.
              const out = this.evalArgVariants((args) => {
                if (v === null || v.kind !== "array") return null;
                const start = numArg(args[0]);
                const end = numArg(args[1]);
                if (start === null || end === null) return null;
                return { kind: "array", items: v.items.slice(start ?? 0, end) } as Value;
              });
              if (out === null) return null;
              v = out;
              continue;
            }
            if (member.v === "reverse") {
              this.pos += 3;
              this.parseArgs();
              v = { kind: "array", items: [...v.items].reverse() };
              continue;
            }
          }
          // TextDecoder().decode(bytes) / TextEncoder().encode(string)
          // (round 6; the byte codec itself is Buffer, which is exact
          // for UTF-8 — the only label this models). A set of byte
          // arrays / strings distributes over its members (round 6b).
          if (v !== null && v.kind === "textdecoder" && member.v === "decode") {
            this.pos += 3;
            // Round 8: per argument-list variant.
            const out = this.evalArgVariants((args) =>
              mapSetValues(args[0] ?? null, (data) => {
                if (data === undefined || data === null || data.kind !== "array") return null;
                const bytes: number[] = [];
                for (const it of data.items) {
                  const n = toNum(it);
                  if (n === null) return null;
                  bytes.push(((Math.trunc(n) % 256) + 256) % 256);
                }
                return { kind: "string", value: Buffer.from(bytes).toString("utf8") };
              }),
            );
            if (out === null) return null;
            v = out;
            continue;
          }
          if (v !== null && v.kind === "textencoder" && member.v === "encode") {
            this.pos += 3;
            // Round 8: per argument-list variant.
            const out = this.evalArgVariants((args) =>
              mapSetValues(args[0] ?? null, (data) => {
                if (data === undefined || data === null || data.kind !== "string") return null;
                return {
                  kind: "array",
                  items: [...Buffer.from(data.value, "utf8")].map((b) => ({ kind: "number" as const, value: b })),
                };
              }),
            );
            if (out === null) return null;
            v = out;
            continue;
          }
          // Method call on an object whose property is a diff-defined
          // function value: evaluate it (round 6); multi-path bodies
          // yield a set of possible returns (round 6b).
          if (v !== null && v.kind === "object") {
            const fn = v.props.get(member.v);
            if (fn !== undefined && fn !== null && fn.kind === "function") {
              this.pos += 3;
              // Round 8: per argument-list variant, as for bare
              // diff-defined calls above.
              const outs = this.parseArgsVariants().flatMap((args) =>
                evaluateFunction(fn.def, args, this.env, this.ctx),
              );
              v = makeSet(outs);
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
        // other receiver the value is unchanged. Set receivers are
        // intercepted by the chain case above.
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
        // Set receivers are intercepted by the chain case above.
        this.pos++;
        const idx = this.parseExpr();
        if (!this.peekPunct("]")) return null;
        this.pos++;
        v = readIndex(v, idx);
        continue;
      }
      break;
    }
    return v;
  }

  /** Index just past the postfix chain starting at pos (`.x()`, `[i]`, `++`/`--` runs). */
  private findChainEnd(): number {
    let j = this.pos;
    while (j < this.toks.length) {
      const t = this.toks[j];
      if (t.t === "punct" && t.v === ".") {
        const id = this.toks[j + 1];
        if (id?.t !== "ident") break;
        j += 2;
        const open = this.toks[j];
        if (open?.t === "punct" && open.v === "(") {
          const close = matchBracket(this.toks, j);
          if (close === -1) break;
          j = close + 1;
        }
        continue;
      }
      if (t.t === "punct" && t.v === "[") {
        const close = matchBracket(this.toks, j);
        if (close === -1) break;
        j = close + 1;
        continue;
      }
      if (t.t === "punct" && (t.v === "++" || t.v === "--")) {
        j++;
        continue;
      }
      break;
    }
    return j;
  }

  /** Parses `(args)` with pos just after `(`; consumes through `)`.
   *  Returns each argument with its spread flag, without expanding
   *  arity: a spread argument keeps its whole value here — arity
   *  expansion happens in parseArgs / parseArgsVariants. */
  parseArgsRaw(): { value: Value; spread: boolean }[] {
    const args: { value: Value; spread: boolean }[] = [];
    if (this.peekPunct(")")) {
      this.pos++;
      return args;
    }
    while (!this.atEnd()) {
      if (this.peekPunct("...")) {
        this.pos++;
        args.push({ value: this.parseExpr(), spread: true });
      } else {
        args.push({ value: this.parseExpr(), spread: false });
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

  /** Flat argument list with the historical semantics: spread of an
   *  array inlines its items; anything else (including a spread
   *  set) stays a single argument. */
  parseArgs(): Value[] {
    const args: Value[] = [];
    for (const a of this.parseArgsRaw()) {
      if (a.spread && a.value !== null && a.value.kind === "array") {
        args.push(...a.value.items);
      } else {
        args.push(a.value);
      }
    }
    return args;
  }

  /** Argument-list variants (round 8): a spread of a set-valued
   *  array fans out — one variant per member array, its items
   *  inlined — because a spread changes arity, and a single flat
   *  list cannot represent "one of these argument lists". That was
   *  the fromCharCode/fromCodePoint gap: a spread set collapsed to
   *  one set argument, which the per-argument distribution then
   *  saw as an array where it expected a number and gave up.
   *  Spread of a non-array stays a single argument (the historical
   *  fail-closed behavior: a spread string is not exploded into
   *  chars, so single-arg builtins like atob keep distributing
   *  over the whole string). Total variants are capped at 256
   *  (the join cross-product precedent); past the cap a variant
   *  is missed, never fabricated. */
  parseArgsVariants(): Value[][] {
    const MAX_VARIANTS = 256;
    let variants: Value[][] = [[]];
    for (const a of this.parseArgsRaw()) {
      if (!a.spread) {
        for (const v of variants) v.push(a.value);
        continue;
      }
      if (a.value !== null && a.value.kind === "array") {
        for (const v of variants) v.push(...a.value.items);
        continue;
      }
      if (a.value !== null && a.value.kind === "set") {
        const next: Value[][] = [];
        for (const v of variants) {
          for (const m of a.value.values) {
            if (next.length >= MAX_VARIANTS) break;
            if (m !== null && m.kind === "array") next.push([...v, ...m.items]);
            else next.push([...v, m]);
          }
          if (next.length >= MAX_VARIANTS) break;
        }
        variants = next;
        continue;
      }
      for (const v of variants) v.push(a.value);
    }
    return variants;
  }

  /** Evaluate `fn` over each argument-list variant (pos just after
   *  `(`), combining the per-variant results with makeSet. A
   *  variant that yields null contributes nothing; all-null yields
   *  null, matching the single-list behavior. */
  evalArgVariants(fn: (args: Value[]) => Value): Value {
    const outs: Value[] = [];
    for (const args of this.parseArgsVariants()) outs.push(fn(args));
    return makeSet(outs);
  }

  /**
   * Evaluate `.apply()` / `.call()` (round 9). `pos` is at the `.`
   * before the member name and `start` is the start of the callee
   * chain; on return `pos` is past the closing paren (or left
   * wherever parsing stopped on a malformed call — the caller
   * abandons the chain with null in that case).
   *
   * Value calls rewrite to the equivalent direct call and are
   * re-parsed with the same environment, so every call form the
   * resolver already evaluates also evaluates in apply/call form:
   * `fn.apply(thisArg, argArray)` becomes `fn(...argArray)` and
   * `fn.call(thisArg, ...args)` becomes `fn(...args)` (the thisArg
   * never contributes value material). `Reflect.apply(fn, thisArg,
   * argArray)` is recognized by its receiver tokens, but only when
   * `Reflect` is unbound in the environment, so a user-defined
   * `Reflect` is never hijacked. Each rewrite strictly shortens
   * the token stream (the `.apply(`/`.call(` wrapper and the
   * thisArg are dropped), so nested apply/call forms terminate.
   *
   * A callee ending in `.push` is NOT rewritten: it is a side
   * effect. `x.push.apply(y, elems)` / `x.push.call(y, ...elems)`
   * append into the thisArg array (exact JS semantics — the
   * receiver's base is irrelevant), in sequential mode only,
   * mirroring the statement walk. A set-valued thisArg fans out
   * per member array; a non-array thisArg is a runtime throw, so
   * nothing is pushed. Returns the new length (or a set of
   * lengths for a set target), or null when nothing was pushed.
   *
   * Returns undefined ONLY when the caller should fall through to
   * the existing dispatch: an own apply/call property on an object
   * receiver is a plain method call, not Function.prototype.apply.
   * Any other failure returns null (fail-closed) with the call
   * consumed.
   */
  private tryApplyCall(start: number, kind: "apply" | "call", recv: Value): Value | undefined {
    const calleeToks = this.toks.slice(start, this.pos);
    if (calleeToks.length === 0) return null;
    if (recv !== null && recv.kind === "object") {
      const own = recv.props.get(kind);
      if (own !== undefined && own !== null && own.kind === "function") return undefined;
    }
    const last = calleeToks[calleeToks.length - 1];
    const prev = calleeToks[calleeToks.length - 2];
    const isPush =
      last?.t === "ident" && last.v === "push" && prev?.t === "punct" && prev.v === "." &&
      recv !== null && recv.kind === "array";
    // Advance past `.apply(` / `.call(`.
    this.pos += 3;
    const close = matchBracket(this.toks, this.pos - 1);
    if (close === -1) return null;
    const groups = splitTopLevel(this.toks.slice(this.pos, close));
    const after = close + 1;
    if (isPush) {
      this.pos = after;
      // Sequential mode only: the fixpoint pass is assignments-only.
      if (this.ctx.mode !== "sequential") return null;
      const parsed = groups.map((g) => {
        if (g.length > 0 && g[0]?.t === "punct" && g[0].v === "...") {
          return {
            value: new Parser(g.slice(1), this.env, this.ctx).parseExpr(),
            spread: true,
          };
        }
        return { value: new Parser(g, this.env, this.ctx).parseExpr(), spread: false };
      });
      let target: Value | null = null;
      let elemVals: Value[] = [];
      if (kind === "apply") {
        if (parsed.length < 2) return null;
        target = parsed[0].value;
        const arr = parsed[1].value;
        if (arr === null) return null;
        if (arr.kind === "array") elemVals = [...arr.items];
        else if (arr.kind === "set") elemVals = [arr];
        else return null;
      } else {
        if (parsed.length < 1) return null;
        target = parsed[0].value;
        for (const a of parsed.slice(1)) {
          if (a.spread && a.value !== null && a.value.kind === "array") {
            elemVals.push(...a.value.items);
          } else {
            elemVals.push(a.value);
          }
        }
      }
      const targets: Value[] = [];
      if (target !== null && target.kind === "array") targets.push(target);
      else if (target !== null && target.kind === "set") {
        for (const m of target.values) {
          if (m !== null && m.kind === "array") targets.push(m);
        }
      }
      if (targets.length === 0) return null;
      for (const t of targets) {
        if (t !== null && t.kind === "array") t.items.push(...elemVals);
      }
      const lens: Value[] = [];
      for (const t of targets) {
        if (t !== null && t.kind === "array") lens.push({ kind: "number", value: t.items.length });
      }
      return makeSet(lens);
    }
    // Rewrite path: value calls only.
    const punct = (v: string): Tok => ({ t: "punct", v });
    const isReflect =
      calleeToks.length === 1 &&
      calleeToks[0]?.t === "ident" &&
      calleeToks[0].v === "Reflect" &&
      recv === null;
    let callToks: Tok[];
    if (kind === "apply") {
      if (isReflect) {
        if (groups.length < 3) {
          this.pos = after;
          return null;
        }
        callToks = [...groups[0], punct("("), punct("..."), ...groups[2], punct(")")];
      } else {
        if (groups.length < 2) {
          this.pos = after;
          return null;
        }
        callToks = [...calleeToks, punct("("), punct("..."), ...groups[1], punct(")")];
      }
    } else {
      const rest: Tok[] = [];
      groups.slice(1).forEach((g, i) => {
        if (i > 0) rest.push(punct(","));
        rest.push(...g);
      });
      callToks = [...calleeToks, punct("("), ...rest, punct(")")];
    }
    const sub = new Parser(callToks, this.env, this.ctx);
    const out = sub.parseExpr();
    this.pos = after;
    if (sub.pos !== sub.toks.length) return null;
    return out;
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
        // Round 8: per argument-list variant, so a spread of a
        // set-valued array expands correctly here too.
        if (tok.v === "String") {
          return this.evalArgVariants((args) => {
            if (args.length === 0) return { kind: "string", value: "" };
            return mapSetValues(args[0], (a) => {
              const s = coerceToString(a);
              return s === null ? null : { kind: "string", value: s };
            });
          });
        }
        return this.evalArgVariants((args) => {
          const data = args[0];
          if (data === undefined) return null;
          return mapSetValues(data, (d) => {
            if (d === null || d.kind !== "string") return null;
            if (tok.v === "atob") {
              const decoded = decodeBase64(d.value, false);
              return decoded === null ? null : { kind: "string", value: decoded };
            }
            try {
              const decoded = tok.v === "decodeURIComponent"
                ? decodeURIComponent(d.value)
                : tok.v === "decodeURI"
                  ? decodeURI(d.value)
                  : unescapeJs(d.value);
              return { kind: "string", value: decoded };
            } catch {
              return null;
            }
          });
        });
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
    // Possible outputs: a substitution evaluating to a set fans out
    // to one output per member (round 6b), capped like all sets.
    let outs = [""];
    let i = 0;
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === "\\" && i + 1 < raw.length) {
        const d = decodeEscape(raw, i);
        outs = outs.map((o) => o + d.ch);
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
        const members: Value[] = v !== null && v.kind === "set" ? v.values : [v];
        const next: string[] = [];
        for (const o of outs) {
          for (const m of members) {
            const s = coerceToString(m);
            if (s !== null) next.push(o + s);
          }
          if (next.length >= 256) break;
        }
        if (next.length === 0) return null;
        outs = next.slice(0, SET_CAP);
        i = close + 1;
        continue;
      }
      outs = outs.map((o) => o + ch);
      i++;
    }
    return makeSet(outs.map((o) => ({ kind: "string" as const, value: o })));
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
  // Round 9: the statement-walk pass currently running. The Parser
  // applies `.push.apply` / `.push.call` side effects only in
  // sequential mode, mirroring the statement walk, which skips
  // pushes in fixpoint mode (assignments-only). Unset for ad-hoc
  // parsers, where push side effects are skipped (fail-closed for
  // the value; statement-level pushes are still tracked by the
  // sequential walk itself).
  mode?: "sequential" | "fixpoint";
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
  // Round 7: a set-valued iterable fans out to its member arrays.
  // Member arrays are iterated in sequence (the loop body mutates the
  // shared env, as for concrete arrays); set ITEMS inside an array
  // are bound whole, so the body distributes over them via the 6b
  // set machinery instead of fabricating a sequential concatenation
  // of two possible executions. Bounds: the 10000-item cap per array
  // plus the shared 20000-step guard.
  const arrays: ArrVal[] = [];
  if (arrVal !== null && arrVal.kind === "array") arrays.push(arrVal);
  else if (arrVal !== null && arrVal.kind === "set") {
    for (const m of arrVal.values) if (m !== null && m.kind === "array") arrays.push(m);
  }
  for (const arr of arrays) {
    const items = arr.items.slice(0, 10000);
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
  // Round 9: `.push.apply()` / `.push.call()` in helper bodies.
  // The target is the thisArg array (exact JS semantics), as in
  // the statement walk; unlike plain push above, this branch is
  // unconditional, matching execSimple's existing push behavior.
  const pushDot2 = slice[j + 3];
  const pushApplyName = slice[j + 4];
  const pushApplyOpen = slice[j + 5];
  if (
    after?.t === "punct" && after.v === "." &&
    pushName?.t === "ident" && pushName.v === "push" &&
    pushDot2?.t === "punct" && pushDot2.v === "." &&
    pushApplyName?.t === "ident" && (pushApplyName.v === "apply" || pushApplyName.v === "call") &&
    pushApplyOpen?.t === "punct" && pushApplyOpen.v === "("
  ) {
    const close = matchBracket(slice, j + 5);
    if (close === -1) return;
    const groups = splitTopLevel(slice.slice(j + 6, close));
    const parseGroup = (g: Tok[]): { value: Value; spread: boolean } => {
      if (g.length > 0 && g[0]?.t === "punct" && g[0].v === "...") {
        return {
          value: new Parser(g.slice(1), env, ctx).parseExpr(),
          spread: true,
        };
      }
      return { value: new Parser(g, env, ctx).parseExpr(), spread: false };
    };
    const parsed = groups.map(parseGroup);
    let target: Value | null = null;
    let elemVals: Value[] = [];
    if (pushApplyName.v === "apply") {
      if (parsed.length >= 2) {
        target = parsed[0].value;
        const arr = parsed[1].value;
        if (arr !== null && arr.kind === "array") elemVals = [...arr.items];
        else if (arr !== null && arr.kind === "set") elemVals = [arr];
      }
    } else {
      if (parsed.length >= 1) {
        target = parsed[0].value;
        for (const a of parsed.slice(1)) {
          if (a.spread && a.value !== null && a.value.kind === "array") {
            elemVals.push(...a.value.items);
          } else {
            elemVals.push(a.value);
          }
        }
      }
    }
    const targets: Value[] = [];
    if (target !== null && target.kind === "array") targets.push(target);
    else if (target !== null && target.kind === "set") {
      for (const m of target.values) {
        if (m !== null && m.kind === "array") targets.push(m);
      }
    }
    for (const t of targets) {
      if (t !== null && t.kind === "array") t.items.push(...elemVals);
    }
    if (targets.length === 0 && elemVals.length > 0 && groups.length > 0) {
      const thisArgGroup = groups[0];
      if (
        thisArgGroup !== undefined && thisArgGroup.length === 1 &&
        thisArgGroup[0]?.t === "ident" && !env.has(thisArgGroup[0].v)
      ) {
        env.set(thisArgGroup[0].v, { kind: "array", items: elemVals });
      }
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

/** Flatten a resolved argument to its string material, or null if not fully resolvable. */
function flattenArg(a: Value): string | null {
  if (a === null) return null;
  if (a.kind === "string") return a.value;
  if (a.kind === "number") return String(a.value);
  if (a.kind === "array") {
    let out = "";
    for (const it of a.items) {
      const s = flattenArg(it);
      if (s === null) return null;
      out += s;
    }
    return out;
  }
  return null;
}

/** Add every string a value may hold (sets fan out to their members). */
function addValueStrings(v: Value, add: (text: string) => void): void {
  if (v === null) return;
  if (v.kind === "string") {
    add(v.value);
    return;
  }
  if (v.kind === "set") {
    for (const m of v.values) addValueStrings(m, add);
  }
}

/**
 * Call-site scan pass (round 6). For every call to a diff-defined
 * function in the diff, evaluate the body with the call's arguments
 * and scan every possible return value — this catches multi-path
 * bodies (unknown-condition branches) that single-value expression
 * evaluation must leave unknown. Plus two fallbacks, both firing
 * only when the concatenation itself is secret-shaped, so honest
 * helpers are untouched: the raw-literal fallback (concatenating the
 * call's raw string-literal arguments and array-literal elements in
 * order), and the resolved-argument fallback (round 6b: the same
 * concatenation over RESOLVED argument values, so fragments held in
 * variables are caught even when the body is intractable — classic
 * for, while, recursion — and set arguments fan out to their
 * members). An argument that does not fully resolve skips the
 * resolved fallback for that call: its fragments are still scanned
 * individually, and a skipped argument never contributes a
 * fabricated partial concatenation.
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
    for (const o of outs) addValueStrings(o, add);
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
    // Resolved-argument fallback (round 6b): as above, over resolved
    // values instead of raw literals; set arguments fan out.
    const argOptions: string[][] = [];
    let skipResolved = false;
    for (const a of argValues) {
      if (a !== null && a.kind === "set") {
        const opts: string[] = [];
        for (const m of a.values) {
          const s = flattenArg(m);
          if (s !== null) opts.push(s);
        }
        if (opts.length === 0) {
          skipResolved = true;
          break;
        }
        argOptions.push(opts);
      } else {
        const s = flattenArg(a);
        if (s === null) {
          skipResolved = true;
          break;
        }
        argOptions.push([s]);
      }
    }
    if (!skipResolved) {
      let combos = [""];
      for (const opts of argOptions) {
        const next: string[] = [];
        for (const c of combos) {
          for (const o of opts) {
            if (next.length >= 1024) break;
            next.push(c + o);
          }
          if (next.length >= 1024) break;
        }
        combos = next;
      }
      for (const c of combos) add(c);
    }
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
  // Round 9: record the pass so Parser-side `.push.apply` /
  // `.push.call` side effects apply in sequential mode only.
  ctx.mode = mode;
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
    // Top-level for..of (round 7): interpret it so loop accumulation
    // (e.g. `s += p` over `[pick(flag)]`) resolves into the
    // environment — previously the loop was skipped token by token,
    // so `s` was deleted (unbound loop variable) and the combination
    // with later expressions never resolved. Classic `for` loops keep
    // the existing token-by-token walk (their bodies' statements are
    // visited individually below), and `for await` is never routed
    // here (its header is not parenthesized, so the scan fails).
    // Fixpoint mode keeps the old walk: the sequential environment
    // is the precise one; the fixpoint pass is only a net for
    // forward references.
    if (
      mode === "sequential" &&
      first?.t === "ident" && first.v === "for" &&
      atStatementStart(start)
    ) {
      const open = start + 1;
      const close = open < toks.length && toks[open]?.t === "punct" && toks[open].v === "("
        ? matchBracket(toks, open)
        : -1;
      if (close !== -1) {
        const header = toks.slice(open + 1, close);
        let depth = 0;
        let isForOf = false;
        for (const h of header) {
          if (h.t === "punct" && (h.v === "(" || h.v === "[" || h.v === "{")) depth++;
          else if (h.t === "punct" && (h.v === ")" || h.v === "]" || h.v === "}")) depth--;
          else if (depth === 0 && h.t === "ident" && h.v === "of") {
            isForOf = true;
            break;
          }
        }
        if (isForOf) {
          const r = interpretForOf(toks, start, env, ctx);
          p.pos = r.next;
          continue;
        }
      }
    }
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
    // Round 9: `.push.apply()` / `.push.call()` statements. The
    // target is the thisArg array (exact JS semantics —
    // `x.push.apply(y, e)` pushes into y, not x), not the
    // statement's own name. Sequential mode only, like plain push.
    const pushDot2 = toks[j + 3];
    const pushApplyName = toks[j + 4];
    const pushApplyOpen = toks[j + 5];
    if (
      mode === "sequential" &&
      nameTok?.t === "ident" &&
      dot?.t === "punct" && dot.v === "." &&
      pushName?.t === "ident" && pushName.v === "push" &&
      pushDot2?.t === "punct" && pushDot2.v === "." &&
      pushApplyName?.t === "ident" && (pushApplyName.v === "apply" || pushApplyName.v === "call") &&
      pushApplyOpen?.t === "punct" && pushApplyOpen.v === "("
    ) {
      p.pos = j + 6;
      const raw = p.parseArgsRaw();
      let target: Value | null = null;
      let elemVals: Value[] = [];
      if (pushApplyName.v === "apply") {
        if (raw.length >= 2) {
          target = raw[0].value;
          const arr = raw[1].value;
          if (arr !== null && arr.kind === "array") elemVals = [...arr.items];
          else if (arr !== null && arr.kind === "set") elemVals = [arr];
        }
      } else {
        if (raw.length >= 1) {
          target = raw[0].value;
          for (const a of raw.slice(1)) {
            if (a.spread && a.value !== null && a.value.kind === "array") {
              elemVals.push(...a.value.items);
            } else {
              elemVals.push(a.value);
            }
          }
        }
      }
      const targets: Value[] = [];
      if (target !== null && target.kind === "array") targets.push(target);
      else if (target !== null && target.kind === "set") {
        for (const m of target.values) {
          if (m !== null && m.kind === "array") targets.push(m);
        }
      }
      for (const t of targets) {
        if (t !== null && t.kind === "array") t.items.push(...elemVals);
      }
      if (targets.length === 0 && elemVals.length > 0) {
        // Push into an array declared outside the diff, named by a
        // bare-ident thisArg: track the pushed elements alone
        // (mirrors the plain-push rule above).
        const thisArgTok = toks[j + 6];
        const afterThisArg = toks[j + 7];
        if (
          thisArgTok?.t === "ident" &&
          afterThisArg?.t === "punct" && afterThisArg.v === "," &&
          !env.has(thisArgTok.v)
        ) {
          env.set(thisArgTok.v, { kind: "array", items: elemVals });
        }
      }
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
    for (const v of env.values()) addValueStrings(v, add);
    // Bare expressions anywhere in the diff, evaluated with the final
    // environment: reconstructions that are never assigned (call
    // arguments, return values, conditions, ternary branches).
    const p = new Parser(toks, env, ctx);
    while (!p.atEnd()) {
      const start = p.pos;
      const v = p.parseExpr();
      addValueStrings(v, add);
      p.pos = v !== null ? Math.max(p.pos, start + 1) : start + 1;
    }
    // Call-site scan pass (round 6): multi-path function outcomes
    // plus the raw-literal-argument and resolved-argument fallbacks.
    scanCallSites(toks, env, ctx, add);
  }
  return [...hits];
}

import { execFile } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import type { AgentBackend, TaskSpec } from "./agent";
import { scanSecrets } from "./secretscan";
import type { CheckResult, RepoConfig, Tier } from "./store";
import { addedLinesOf } from "./worktree";

const execFileAsync = promisify(execFile);

const OUTPUT_CAP = 100 * 1024;
const CHECK_TIMEOUT_MS = 10 * 60 * 1000;

export interface DiscoveredCommands {
  test: string | null;
  lint: string | null;
  typecheck: string | null;
}

/**
 * Discover verification commands from REPO CONFIG ONLY — never from wish
 * text (§3.4, probe 7). Sources: package.json scripts and Makefile
 * targets. Placeholder scripts ("no test specified") count as absent,
 * which yields PARTIAL, not BLOCKED.
 */
export async function discoverCommands(repoDir: string): Promise<DiscoveredCommands> {
  const out: DiscoveredCommands = { test: null, lint: null, typecheck: null };
  try {
    const pkg = JSON.parse(
      await readFile(join(repoDir, "package.json"), "utf8"),
    ) as { scripts?: Record<string, string> };
    const scripts = pkg.scripts ?? {};
    const pick = (name: string): string | null => {
      const cmd = scripts[name];
      if (!cmd) return null;
      if (/no test specified/i.test(cmd)) return null;
      // Bare echo scripts are placeholders, not suites — for every
      // command, not just test. An echo "test" that always passes
      // would otherwise mint a VERIFIED tier out of nothing.
      if (/^\s*echo\b/.test(cmd)) return null;
      return cmd;
    };
    out.test = pick("test");
    out.lint = pick("lint");
    out.typecheck = pick("typecheck");
  } catch {
    // No package.json — fall through to Makefile.
  }
  try {
    const makefile = await readFile(join(repoDir, "Makefile"), "utf8");
    const targets = new Set(
      makefile
        .split("\n")
        .map((l) => {
          const m = l.match(/^([A-Za-z0-9_.-]+)\s*:/);
          return m ? m[1] : null;
        })
        .filter((t): t is string => t !== null),
    );
    if (!out.test && targets.has("test")) out.test = "make test";
    if (!out.lint && targets.has("lint")) out.lint = "make lint";
    if (!out.typecheck && targets.has("typecheck")) out.typecheck = "make typecheck";
  } catch {
    // No Makefile.
  }
  return out;
}

async function runShell(
  command: string,
  cwd: string,
): Promise<{ passed: boolean; output: string }> {
  // Spawn detached with output to temp files and a process-group kill
  // on timeout. Piping stdout would let a pipe-holding descendant of a
  // malicious test script stall the wait indefinitely (the Successor
  // fix-round lesson); the group kill bounds wall-clock time.
  const { spawn } = await import("node:child_process");
  const { mkdtemp, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const scratch = await mkdtemp(join(tmpdir(), "wishship-check-"));
  try {
    const outFile = join(scratch, "out");
    const errFile = join(scratch, "err");
    const { open } = await import("node:fs/promises");
    const outFd = await open(outFile, "w");
    const errFd = await open(errFile, "w");
    try {
      const result = await new Promise<{ code: number | null; timedOut: boolean }>(
        (resolve) => {
          let timedOut = false;
          const child = spawn("/bin/sh", ["-c", command], {
            cwd,
            env: { PATH: process.env.PATH ?? "", HOME: cwd },
            detached: true,
            stdio: ["ignore", outFd.fd, errFd.fd],
          });
          const timer = setTimeout(() => {
            timedOut = true;
            try {
              if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
              else child.kill("SIGKILL");
            } catch {
              child.kill("SIGKILL");
            }
          }, CHECK_TIMEOUT_MS);
          timer.unref?.();
          child.on("error", () => {
            clearTimeout(timer);
            resolve({ code: null, timedOut });
          });
          child.on("close", (code) => {
            clearTimeout(timer);
            resolve({ code, timedOut });
          });
        },
      );
      const read = async (p: string): Promise<string> => {
        try {
          return (await readFile(p, "utf8")).slice(0, OUTPUT_CAP + 1024);
        } catch {
          return "";
        }
      };
      const output = truncate((await read(outFile)) + (await read(errFile)));
      if (result.timedOut) {
        return { passed: false, output: output + "\n[check timed out]" };
      }
      return { passed: result.code === 0, output };
    } finally {
      await outFd.close().catch(() => undefined);
      await errFd.close().catch(() => undefined);
    }
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

function truncate(s: string): string {
  return s.length > OUTPUT_CAP
    ? s.slice(0, OUTPUT_CAP) + "\n[output truncated]"
    : s;
}

// ---------- dependency changes ----------

const LOCKFILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "Gemfile.lock",
  "Pipfile.lock",
  "poetry.lock",
  "go.sum",
  "Cargo.lock",
  "composer.lock",
]);

const DEP_MANIFESTS = ["go.mod", "Cargo.toml", "pyproject.toml", "Gemfile", "composer.json", "requirements.txt"];

async function readBaseFile(
  worktreeDir: string,
  commit: string,
  path: string,
): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("git", ["show", `${commit}:${path}`], {
      cwd: worktreeDir,
      env: { PATH: process.env.PATH ?? "" },
      maxBuffer: 10 * 1024 * 1024,
    });
    return stdout;
  } catch {
    return null;
  }
}

function packageDepMap(pkgJson: string): Map<string, string> {
  try {
    const pkg = JSON.parse(pkgJson) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      scripts?: Record<string, string>;
    };
    const out = new Map<string, string>();
    for (const section of ["dependencies", "devDependencies", "peerDependencies"] as const) {
      for (const [k, v] of Object.entries(pkg[section] ?? {})) out.set(`${section}:${k}`, v);
    }
    // Scripts are verification surface: an agent rewriting `test` to a
    // no-op must trip the same violation as a dependency change.
    for (const [k, v] of Object.entries(pkg.scripts ?? {})) out.set(`script:${k}`, v);
    return out;
  } catch {
    return new Map();
  }
}

/**
 * Compare dependency manifests at the base commit vs. the verified tree.
 * Any lockfile change, dependency add/remove/VERSION change, script
 * change, or build-file (Makefile) change is a violation (BLOCKED by
 * default; the maintainer may allow a retry with dependencies permitted
 * for that run). Nested manifests (e.g. packages/foo/package.json,
 * subdir/requirements.txt) are walked too — only the root used to be.
 */
export async function detectDependencyChanges(
  worktreeDir: string,
  baseCommit: string,
  verifyDir: string,
  filesChanged: string[],
): Promise<string[]> {
  const violations: string[] = [];
  for (const f of filesChanged) {
    const base = f.split("/").pop() ?? f;
    if (LOCKFILES.has(base)) violations.push(`lockfile changed: ${f}`);
    if (base === "Makefile") violations.push(`build file changed: ${f}`);
  }
  for (const f of filesChanged) {
    const base = f.split("/").pop() ?? f;
    const isPackageJson = base === "package.json";
    if (!isPackageJson && !DEP_MANIFESTS.includes(base)) continue;
    const before = await readBaseFile(worktreeDir, baseCommit, f);
    let after: string | null = null;
    try {
      after = await readFile(join(verifyDir, f), "utf8");
    } catch {
      after = null;
    }
    if (isPackageJson) {
      const beforeMap = before ? packageDepMap(before) : new Map<string, string>();
      const afterMap = after ? packageDepMap(after) : new Map<string, string>();
      for (const [k, v] of afterMap) {
        if (!beforeMap.has(k)) {
          violations.push(
            k.startsWith("script:")
              ? `script added: ${k.slice(7)} (${f})`
              : `dependency added: ${k} (${f})`,
          );
        } else if (beforeMap.get(k) !== v) {
          violations.push(
            k.startsWith("script:")
              ? `script changed: ${k.slice(7)} (${f})`
              : `dependency version changed: ${k} ${beforeMap.get(k)} -> ${v} (${f})`,
          );
        }
      }
      for (const k of beforeMap.keys()) {
        if (!afterMap.has(k)) {
          violations.push(
            k.startsWith("script:")
              ? `script removed: ${k.slice(7)} (${f})`
              : `dependency removed: ${k} (${f})`,
          );
        }
      }
    } else if (before !== after) {
      violations.push(`manifest changed: ${f}`);
    }
  }
  return violations;
}

// ---------- churn heuristic ----------

const STOPWORDS = new Set([
  "the", "and", "for", "with", "from", "into", "this", "that", "add",
  "feature", "support", "implement", "please", "should", "would", "when",
  "user", "users", "app", "board", "wish",
]);

function tokensOf(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((t) => t.length >= 3 && !STOPWORDS.has(t)),
  );
}

export interface ChurnResult {
  unrelatedFiles: string[];
  unrelatedAddedLines: number;
  blocked: boolean;
}

/** Added lines per file, parsed from diff headers. */
export function addedLinesPerFile(patch: string): Map<string, string[]> {
  const perFile = new Map<string, string[]>();
  let current: string | null = null;
  for (const line of patch.split("\n")) {
    const m = line.match(/^\+\+\+ b\/(.+)$/);
    if (m) {
      current = m[1];
      perFile.set(current, []);
      continue;
    }
    if (current && line.startsWith("+") && !line.startsWith("+++")) {
      perFile.get(current)!.push(line.slice(1));
    }
  }
  return perFile;
}

function isCommentLine(line: string): boolean {
  const t = line.trim();
  return (
    t.startsWith("//") ||
    t.startsWith("#") ||
    t.startsWith("*") ||
    t.startsWith("/*") ||
    t.startsWith("<!--")
  );
}

/**
 * A file is related if its path tokens overlap the wish tokens, OR at
 * least one token from its NON-COMMENT added lines overlaps the wish
 * tokens. The old rule counted comment tokens too, so a backdoor file
 * passed by adding one keyword comment; comment-only overlap no longer
 * counts. Token overlap is a heuristic, not proof: a related file can
 * still carry a new network call, which is why the network flag and
 * the changed-files list in the PR body are the backstop, not churn.
 * Single-file unrelated additions block above a size threshold, and an
 * unrelated file that makes a new network call blocks outright (that is
 * the backdoor shape: unrelated code phoning a new host).
 */
export function assessChurn(
  patch: string,
  filesChanged: string[],
  wishTitle: string,
  wishBody: string,
): ChurnResult {
  const wishTokens = tokensOf(`${wishTitle} ${wishBody}`);
  const added = addedLinesOf(patch);
  const perFile = addedLinesPerFile(patch);
  const unrelatedFiles: string[] = [];
  let unrelatedAddedLines = 0;
  for (const f of filesChanged) {
    const pathTokens = tokensOf(f.replace(/\//g, " "));
    const codeLines = (perFile.get(f) ?? []).filter((l) => !isCommentLine(l));
    const contentTokens = tokensOf(codeLines.join("\n"));
    const related =
      [...pathTokens].some((t) => wishTokens.has(t)) ||
      [...contentTokens].some((t) => wishTokens.has(t));
    if (!related) {
      unrelatedFiles.push(f);
      unrelatedAddedLines += perFile.get(f)?.length ?? 0;
    }
  }
  const singleLargeUnrelated =
    unrelatedFiles.length === 1 && unrelatedAddedLines >= 20;
  const blocked =
    (unrelatedFiles.length >= 2 &&
      added.length > 0 &&
      unrelatedAddedLines > added.length / 2) ||
    singleLargeUnrelated;
  return { unrelatedFiles, unrelatedAddedLines, blocked };
}

// ---------- new-network-call flagging ----------

const NETWORK_CALL =
  /(fetch\s*\(|axios\.\w+\s*\(|https?\.request\s*\(|https?\.get\s*\(|XMLHttpRequest|WebSocket\s*\(|net\.connect\s*\(|socket\.connect\s*\(|tls\.connect\s*\(|curl\s+|new URL\s*\()/;
const HOST_IN_URL = /https?:\/\/([A-Za-z0-9.-]+)/g;
const IP_LITERAL = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

function hostsIn(text: string): Set<string> {
  const out = new Set<string>();
  for (const m of text.matchAll(HOST_IN_URL)) out.add(m[1].toLowerCase());
  for (const m of text.matchAll(IP_LITERAL)) out.add(m[0]);
  return out;
}

/**
 * Baseline hosts come from ACTUAL network-call lines in the base tree,
 * not any URL string anywhere. The old walk counted a host mentioned
 * in a comment as "already used", so fetching an already-mentioned
 * host raised no flag — exactly the gaming the judge demonstrated.
 */
export async function collectBaselineHosts(dir: string): Promise<Set<string>> {
  const hosts = new Set<string>();
  let scanned = 0;
  async function walk(d: string): Promise<void> {
    if (scanned > 500) return;
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (scanned > 500) return;
      if (e.name === ".git" || e.name === "node_modules") continue;
      const p = join(d, e.name);
      if (e.isDirectory()) await walk(p);
      else if (e.isFile()) {
        try {
          const s = await stat(p);
          if (s.size > 1024 * 1024) continue;
          const content = await readFile(p, "utf8");
          scanned += 1;
          for (const line of content.split("\n")) {
            if (!NETWORK_CALL.test(line)) continue;
            for (const h of hostsIn(line)) hosts.add(h);
          }
        } catch {
          // Binary or unreadable; skip.
        }
      }
    }
  }
  await walk(dir);
  return hosts;
}

export function newHostsInDiff(patch: string, baseline: Set<string>): string[] {
  const out: string[] = [];
  for (const line of addedLinesOf(patch)) {
    if (!NETWORK_CALL.test(line)) continue;
    const hosts = hostsIn(line);
    if (hosts.size === 0) {
      // Dynamically constructed URL (variable, template, concatenation):
      // no literal host to compare, so flag it as such rather than
      // silently passing a call whose destination cannot be checked.
      if (!out.includes("dynamic-url")) out.push("dynamic-url");
      continue;
    }
    for (const h of hosts) {
      if (!baseline.has(h) && !out.includes(h)) out.push(h);
    }
  }
  return out;
}

/** New hosts called from a given file's added lines only. */
export function newHostsInFile(
  addedLines: string[],
  baseline: Set<string>,
): string[] {
  const out: string[] = [];
  for (const line of addedLines) {
    if (!NETWORK_CALL.test(line)) continue;
    const hosts = hostsIn(line);
    if (hosts.size === 0) {
      if (!out.includes("dynamic-url")) out.push("dynamic-url");
      continue;
    }
    for (const h of hosts) {
      if (!baseline.has(h) && !out.includes(h)) out.push(h);
    }
  }
  return out;
}

// ---------- full verification ----------

export interface VerifyInput {
  spec: TaskSpec;
  verifyDir: string;
  agentWorktreeDir: string;
  baseCommit: string;
  patch: string;
  filesChanged: string[];
  addedLines: number;
  config: RepoConfig;
  allowDependencies: boolean;
  backend: AgentBackend;
  /** Hosts present in the BASE tree (collected before the patch lands). */
  baselineHosts: Set<string>;
  /** Files outside the worktree modified during the run (weak check). */
  outsideWrites: string[];
  /**
   * Verification commands discovered from the BASE commit BEFORE the
   * agent ran (runner-owned). verifyDiff MUST NEVER re-discover from
   * the patched tree: an agent rewriting `package.json`'s test script
   * to `exit 0` would otherwise grade its own homework.
   */
  commands: DiscoveredCommands;
}

export interface VerifyOutput {
  tier: Tier;
  checks: CheckResult[];
}

export async function verifyDiff(input: VerifyInput): Promise<VerifyOutput> {
  const checks: CheckResult[] = [];
  const { spec, verifyDir, config } = input;
  // Pre-agent commands, passed in by the runner. Never re-discovered
  // from the patched tree (see VerifyInput.commands).
  const commands = input.commands;

  // Tests (if present). No discoverable command -> PARTIAL, not BLOCKED.
  if (commands.test) {
    const r = await runShell(commands.test, verifyDir);
    checks.push({
      name: "tests",
      status: r.passed ? "passed" : "failed",
      detail: r.passed
        ? `test command passed: ${commands.test}`
        : `test command failed: ${commands.test}`,
      output: r.output,
    });
  } else {
    checks.push({
      name: "tests",
      status: "skipped",
      detail: "no test suite discovered (no-test-suite); PR opens as PARTIAL",
    });
  }

  if (commands.lint) {
    const r = await runShell(commands.lint, verifyDir);
    checks.push({
      name: "lint",
      status: r.passed ? "passed" : "failed",
      detail: r.passed ? `lint passed: ${commands.lint}` : `lint failed: ${commands.lint}`,
      output: r.output,
    });
  } else {
    checks.push({
      name: "lint",
      status: "skipped",
      detail: "no lint config discovered",
    });
  }

  if (commands.typecheck) {
    const r = await runShell(commands.typecheck, verifyDir);
    checks.push({
      name: "typecheck",
      status: r.passed ? "passed" : "failed",
      detail: r.passed
        ? `typecheck passed: ${commands.typecheck}`
        : `typecheck failed: ${commands.typecheck}`,
      output: r.output,
    });
  } else {
    checks.push({
      name: "typecheck",
      status: "skipped",
      detail: "no typecheck config discovered",
    });
  }

  // Secret scan on added lines (the whole diff, not just claimed files).
  const added = addedLinesOf(input.patch);
  const secretHits = new Set<string>();
  for (const line of added) {
    for (const h of scanSecrets(line)) secretHits.add(h);
  }
  checks.push({
    name: "secret_scan",
    status: secretHits.size === 0 ? "passed" : "failed",
    detail:
      secretHits.size === 0
        ? "no secret-shaped material in added lines"
        : `secret-shaped material found: ${[...secretHits].join(", ")}`,
  });

  // Diff-size limit: BLOCKED, never trimmed.
  const overLines = input.addedLines > config.diffMaxLines;
  const overFiles = input.filesChanged.length > config.diffMaxFiles;
  checks.push({
    name: "diff_size",
    status: overLines || overFiles ? "failed" : "passed",
    detail: `diff ${input.addedLines} added lines across ${input.filesChanged.length} files (limits: ${config.diffMaxLines} lines, ${config.diffMaxFiles} files)`,
  });

  // Unrelated churn. An unrelated file that phones a NEW host upgrades
  // the churn check to failed: that is the backdoor shape (unrelated
  // code + exfiltration), and it must not reach VERIFIED on flags alone.
  const churn = assessChurn(
    input.patch,
    input.filesChanged,
    spec.wish.title,
    spec.wish.body,
  );
  const perFile = addedLinesPerFile(input.patch);
  const backdoorFiles = churn.unrelatedFiles.filter(
    (f) => newHostsInFile(perFile.get(f) ?? [], input.baselineHosts).length > 0,
  );
  const churnFailed = churn.blocked || backdoorFiles.length > 0;
  checks.push({
    name: "churn",
    status: churnFailed
      ? "failed"
      : churn.unrelatedFiles.length > 0
        ? "flagged"
        : "passed",
    detail:
      backdoorFiles.length > 0
        ? `unrelated files with new outbound calls: ${backdoorFiles.join(", ")}`
        : churn.unrelatedFiles.length === 0
          ? "all changed files relate to the wish"
          : `unrelated files: ${churn.unrelatedFiles.join(", ")} (${churn.unrelatedAddedLines} lines)`,
  });

  // Dependency rules: BLOCKED by default.
  const depViolations = await detectDependencyChanges(
    input.agentWorktreeDir,
    input.baseCommit,
    verifyDir,
    input.filesChanged,
  );
  if (depViolations.length > 0) {
    checks.push({
      name: "dependencies",
      status: input.allowDependencies ? "flagged" : "failed",
      detail: input.allowDependencies
        ? `dependency changes permitted for this run: ${depViolations.join("; ")}`
        : `dependency changes blocked by default: ${depViolations.join("; ")}`,
    });
  } else {
    checks.push({
      name: "dependencies",
      status: "passed",
      detail: "no dependency or lockfile changes",
    });
  }

  // New outbound network calls: flag, not block. Baseline hosts come
  // from the base tree (collected before the patch was applied) — the
  // agent worktree already contains the new code and would mask them.
  const newHosts = newHostsInDiff(input.patch, input.baselineHosts);
  checks.push({
    name: "network_calls",
    status: newHosts.length > 0 ? "flagged" : "passed",
    detail:
      newHosts.length === 0
        ? "no new outbound hosts in added lines"
        : `new hosts called from added lines: ${newHosts.join(", ")}`,
  });

  // Second-model review: advisory only, never blocks.
  let review: { available: boolean; concerns: string[] };
  try {
    review = await input.backend.review(spec, input.patch, verifyDir);
  } catch {
    review = { available: false, concerns: [] };
  }
  checks.push({
    name: "second_model_review",
    status: !review.available
      ? "skipped"
      : review.concerns.length > 0
        ? "flagged"
        : "passed",
    detail: !review.available
      ? "second-model review unavailable for this backend"
      : review.concerns.length === 0
        ? "reviewer raised no concerns"
        : `reviewer concerns: ${review.concerns.join(" | ")}`,
  });

  // Outside-worktree writes: weak check, honestly labeled (§3.3).
  // Flagged, never blocking on its own — confinement needs containers.
  checks.push({
    name: "sandbox_writes",
    status: input.outsideWrites.length > 0 ? "flagged" : "passed",
    detail:
      input.outsideWrites.length === 0
        ? "no files outside the worktree were modified"
        : `files outside the worktree modified: ${input.outsideWrites.slice(0, 10).join(", ")}`,
  });

  const failed = checks.some((c) => c.status === "failed");
  // Only skipped deterministic checks force PARTIAL. The advisory
  // second-model review being unavailable does not downgrade a tier —
  // it is advisory, and "not applicable" is not "missing".
  const skippedDeterministic = checks.some(
    (c) =>
      c.status === "skipped" &&
      (c.name === "tests" || c.name === "lint" || c.name === "typecheck"),
  );
  const tier: Tier = failed ? "BLOCKED" : skippedDeterministic ? "PARTIAL" : "VERIFIED";
  return { tier, checks };
}

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { WishShipConfig } from "./config";
import { writeSpecFile } from "./worktree";

export interface TaskSpec {
  version: number;
  wish: { title: string; body: string; votes: number; url: string };
  repo: {
    name: string;
    baseCommit: string;
    testCommand: string | null;
    lintCommand: string | null;
    typecheckCommand: string | null;
  };
  constraints: string[];
  injectionFlag: boolean;
  injectionPatterns: string[];
  verification: { willRun: string[] };
}

export const DEFAULT_CONSTRAINTS: string[] = [
  "Implement only what the wish asks for; do not refactor unrelated code.",
  "Do not add, remove, or change dependencies or lockfiles.",
  "Do not include secrets, tokens, or credentials in any file.",
  "Do not make network calls to hosts not already used by this codebase.",
  "Add or extend tests covering the change where the repo has a test harness.",
  "Keep the diff small and reviewable.",
  "Do not push, merge, or publish anything. The service opens the PR.",
];

export type BackendStatus = "ok" | "error" | "timeout";

export interface BackendRunResult {
  status: BackendStatus;
  logs: string;
  durationMs: number;
  costUsd: number | null;
}

export interface ReviewResult {
  available: boolean;
  concerns: string[];
}

export interface AgentBackend {
  name: string;
  run(
    spec: TaskSpec,
    worktreeDir: string,
    opts: { timeoutMs: number; env: NodeJS.ProcessEnv },
  ): Promise<BackendRunResult>;
  review(spec: TaskSpec, diff: string, worktreeDir: string): Promise<ReviewResult>;
}

/**
 * Scrubbed environment for the agent process (§3.3). The agent gets no
 * GitHub token, no npm auth, no service credentials, no database URL.
 * The only credentials present are the backend CLI's own config, reached
 * via its own HOME dir — never injected into the worktree env where the
 * agent could print them. Operator passthrough is explicit and can never
 * reintroduce a denylisted name.
 */
const DENYLISTED_ENV = new Set([
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITHUB_APP_ID",
  "GITHUB_APP_PRIVATE_KEY",
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "DATABASE_URL",
  "SESSION_SECRET",
  "ENCRYPTION_KEY",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
]);

export function buildAgentEnv(config: WishShipConfig): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    TERM: "dumb",
    HOME: config.agentHome,
    WISHSHIP_AGENT: "1",
  };
  for (const name of config.agentEnvPassthrough) {
    if (DENYLISTED_ENV.has(name)) continue;
    if (name.startsWith("WISHSHIP_")) continue;
    const value = process.env[name];
    if (value !== undefined) env[name] = value;
  }
  return env;
}

export interface CommandResult {
  code: number | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
}

const OUTPUT_CAP = 1024 * 1024;

/**
 * Run a command with stdout/stderr redirected to temp files (never pipes)
 * and a process-group kill on timeout. Piping stdout would let a
 * pipe-holding descendant stall the wait indefinitely — the Successor
 * fix-round lesson, applied here from the start.
 */
export async function runCommand(
  command: string,
  args: string[],
  opts: {
    cwd: string;
    env: NodeJS.ProcessEnv;
    timeoutMs: number;
    stdin?: string;
    stdoutFile: string;
    stderrFile: string;
  },
): Promise<CommandResult> {
  const started = Date.now();
  const { open } = await import("node:fs/promises");
  const outFd = await open(opts.stdoutFile, "w");
  const errFd = await open(opts.stderrFile, "w");
  try {
    return await new Promise<CommandResult>((resolve) => {
      let timedOut = false;
      const child = spawn(command, args, {
        cwd: opts.cwd,
        env: opts.env,
        detached: true,
        stdio: ["pipe", outFd.fd, errFd.fd],
      });
      const timer = setTimeout(() => {
        timedOut = true;
        try {
          if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
          else child.kill("SIGKILL");
        } catch {
          child.kill("SIGKILL");
        }
      }, opts.timeoutMs);
      timer.unref?.();
      child.on("error", async () => {
        clearTimeout(timer);
        const [stdout, stderr] = await readCapped(opts.stdoutFile, opts.stderrFile);
        resolve({
          code: null,
          timedOut,
          stdout,
          stderr,
          durationMs: Date.now() - started,
        });
      });
      child.on("close", async (code) => {
        clearTimeout(timer);
        const [stdout, stderr] = await readCapped(opts.stdoutFile, opts.stderrFile);
        resolve({
          code,
          timedOut,
          stdout,
          stderr,
          durationMs: Date.now() - started,
        });
      });
      const stdin = child.stdin;
      if (stdin) {
        // A fast-exiting backend (e.g. `exit 0`) may close stdin before we
        // write: without this handler the EPIPE surfaces as an uncaught
        // exception instead of a normal run result. The close handler
        // below still resolves with the real exit code.
        stdin.on("error", () => undefined);
        try {
          if (opts.stdin !== undefined) {
            stdin.write(opts.stdin);
            stdin.end();
          } else {
            stdin.end();
          }
        } catch {
          // Child already gone; close handler resolves.
        }
      }
    });
  } finally {
    await outFd.close().catch(() => undefined);
    await errFd.close().catch(() => undefined);
  }
}

async function readCapped(
  stdoutFile: string,
  stderrFile: string,
): Promise<[string, string]> {
  const read = async (path: string): Promise<string> => {
    try {
      const buf = await readFile(path);
      return buf.length > OUTPUT_CAP
        ? buf.subarray(0, OUTPUT_CAP).toString("utf8") + "\n[output truncated]"
        : buf.toString("utf8");
    } catch {
      return "";
    }
  };
  return [await read(stdoutFile), await read(stderrFile)];
}

function parseCost(stdout: string): number | null {
  const m = stdout.match(/^WISHSHIP_COST:\s*([0-9]+(?:\.[0-9]+)?)\s*$/m);
  return m ? Number(m[1]) : null;
}

/** CLI coding-agent adapter (Claude Code, Codex). Spec via a file. */
export class CliAgentBackend implements AgentBackend {
  readonly name: string;
  private argv: string[];

  constructor(name: string, argv: string[]) {
    this.name = name;
    this.argv = argv;
  }

  async run(
    spec: TaskSpec,
    worktreeDir: string,
    opts: { timeoutMs: number; env: NodeJS.ProcessEnv },
  ): Promise<BackendRunResult> {
    const specPath = await writeSpecFile(worktreeDir, spec);
    const args = this.argv.map((a) => a.replace("{spec}", specPath));
    const [command, ...rest] = args;
    const outFile = join(worktreeDir, ".wishship-agent.out");
    const errFile = join(worktreeDir, ".wishship-agent.err");
    const result = await runCommand(command, rest, {
      cwd: worktreeDir,
      env: opts.env,
      timeoutMs: opts.timeoutMs,
      stdoutFile: outFile,
      stderrFile: errFile,
    });
    // Agent logs live outside the diff: remove them before patch capture.
    const { rm } = await import("node:fs/promises");
    await rm(outFile, { force: true }).catch(() => undefined);
    await rm(errFile, { force: true }).catch(() => undefined);
    await rm(join(worktreeDir, ".wishship"), { recursive: true, force: true }).catch(
      () => undefined,
    );
    if (result.timedOut) {
      return {
        status: "timeout",
        logs: result.stdout + result.stderr,
        durationMs: result.durationMs,
        costUsd: null,
      };
    }
    if (result.code !== 0) {
      return {
        status: "error",
        logs: `exit ${result.code}\n${result.stdout}\n${result.stderr}`,
        durationMs: result.durationMs,
        costUsd: null,
      };
    }
    // CLI adapters do not report usage: cost stays null and the run
    // record says time-bounded only. Never invent a cost.
    return {
      status: "ok",
      logs: result.stdout + result.stderr,
      durationMs: result.durationMs,
      costUsd: null,
    };
  }

  async review(
    spec: TaskSpec,
    diff: string,
    worktreeDir: string,
  ): Promise<ReviewResult> {
    // Advisory second-model review: same backend, review prompt, diff on
    // stdin. If the CLI is missing the review is unavailable, recorded
    // as such, and never blocks — advisory only by design.
    const { mkdtemp, writeFile: wf, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const scratch = await mkdtemp(join(tmpdir(), "wishship-review-"));
    try {
      const diffPath = join(scratch, "diff.patch");
      await wf(diffPath, diff);
      const prompt =
        `Review the diff at ${diffPath} for the wish "${spec.wish.title}". ` +
        `List concrete concerns, one per line, about: backdoors, exfiltration, ` +
        `new network calls, dependency changes, secrets. If none, print OK.`;
      const [command, ...rest] = this.argv.map((a) =>
        a.replace("{spec}", spec.wish.title),
      );
      const result = await runCommand(command, [...rest, prompt], {
        cwd: worktreeDir,
        env: {
          PATH: process.env.PATH ?? "",
          HOME: process.env.HOME ?? "",
        },
        timeoutMs: 5 * 60 * 1000,
        stdoutFile: join(scratch, "out"),
        stderrFile: join(scratch, "err"),
      });
      if (result.code !== 0) return { available: false, concerns: [] };
      const lines = result.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && l !== "OK");
      return { available: true, concerns: lines };
    } catch {
      return { available: false, concerns: [] };
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  }
}

/**
 * Script backend: the operator escape hatch. The command receives the
 * task spec JSON on stdin and runs in the worktree. It may print a
 * `WISHSHIP_COST: <usd>` line for cost reporting. An optional review
 * command receives {spec, diff} JSON on stdin and prints one concern
 * per line on stdout.
 */
export class ScriptBackend implements AgentBackend {
  readonly name = "script";
  private command: string;
  private reviewCommand: string | null;

  constructor(command: string, reviewCommand: string | null = null) {
    this.command = command;
    this.reviewCommand = reviewCommand;
  }

  async run(
    spec: TaskSpec,
    worktreeDir: string,
    opts: { timeoutMs: number; env: NodeJS.ProcessEnv },
  ): Promise<BackendRunResult> {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const scratch = await mkdtemp(join(tmpdir(), "wishship-script-"));
    try {
      const result = await runCommand("/bin/sh", ["-c", this.command], {
        cwd: worktreeDir,
        env: opts.env,
        timeoutMs: opts.timeoutMs,
        stdin: JSON.stringify(spec),
        stdoutFile: join(scratch, "out"),
        stderrFile: join(scratch, "err"),
      });
      if (result.timedOut) {
        return {
          status: "timeout",
          logs: result.stdout + result.stderr,
          durationMs: result.durationMs,
          costUsd: null,
        };
      }
      if (result.code !== 0) {
        return {
          status: "error",
          logs: `exit ${result.code}\n${result.stdout}\n${result.stderr}`,
          durationMs: result.durationMs,
          costUsd: parseCost(result.stdout),
        };
      }
      return {
        status: "ok",
        logs: result.stdout + result.stderr,
        durationMs: result.durationMs,
        costUsd: parseCost(result.stdout),
      };
    } finally {
      const { rm } = await import("node:fs/promises");
      await rm(scratch, { recursive: true, force: true });
    }
  }

  async review(spec: TaskSpec, diff: string): Promise<ReviewResult> {
    if (!this.reviewCommand) return { available: false, concerns: [] };
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const scratch = await mkdtemp(join(tmpdir(), "wishship-review-"));
    try {
      const result = await runCommand("/bin/sh", ["-c", this.reviewCommand], {
        cwd: scratch,
        env: { PATH: process.env.PATH ?? "" },
        timeoutMs: 2 * 60 * 1000,
        stdin: JSON.stringify({ spec, diff }),
        stdoutFile: join(scratch, "out"),
        stderrFile: join(scratch, "err"),
      });
      if (result.code !== 0) return { available: false, concerns: [] };
      return {
        available: true,
        concerns: result.stdout
          .split("\n")
          .map((l) => l.trim())
          .filter(Boolean),
      };
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  }
}

export interface BackendConfig {
  claudeCommand?: string;
  codexCommand?: string;
  scriptCommand?: string;
  scriptReviewCommand?: string | null;
}

export function createBackend(name: string, cfg: BackendConfig): AgentBackend {
  if (name === "claude") {
    const argv = (cfg.claudeCommand ??
      "claude -p Read the task spec at {spec} and implement it in this worktree, following its constraints exactly. Do not push, do not merge, do not access the network except your model API.")
      .split(/\s+/);
    return new CliAgentBackend("claude", argv);
  }
  if (name === "codex") {
    const argv = (cfg.codexCommand ??
      "codex exec Read the task spec at {spec} and implement it in this worktree, following its constraints exactly. Do not push, do not merge.")
      .split(/\s+/);
    return new CliAgentBackend("codex", argv);
  }
  if (name === "script") {
    if (!cfg.scriptCommand) throw new Error("script backend requires a command");
    return new ScriptBackend(cfg.scriptCommand, cfg.scriptReviewCommand ?? null);
  }
  throw new Error(`unknown agent backend: ${name}`);
}

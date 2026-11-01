import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface Worktree {
  dir: string;
  baseCommit: string;
}

async function git(dir: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, {
    cwd: dir,
    env: { PATH: process.env.PATH ?? "" },
    maxBuffer: 10 * 1024 * 1024,
  });
  return stdout;
}

/**
 * Fresh temp worktree per run, cloned at a pinned commit. The remote is
 * removed immediately after clone so the agent literally cannot push:
 * the PR branch is service-created, never agent-pushed (§9 probe 18).
 * The worktree is deleted after the run, success or failure.
 */
export async function createWorktree(
  source: string,
  baseCommit: string,
  root: string,
): Promise<Worktree> {
  const dir = await mkdtemp(join(root, "ws-run-"));
  try {
    await git(dir, ["clone", "--quiet", source, "."]);
    await git(dir, ["checkout", "--quiet", baseCommit]);
    // Strip the remote: no push path exists for the agent, and no
    // credential-bearing remote URL survives in .git/config.
    await git(dir, ["remote", "remove", "origin"]).catch(() => undefined);
    const commit = (await git(dir, ["rev-parse", "HEAD"])).trim();
    return { dir, baseCommit: commit };
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err;
  }
}

export interface CapturedDiff {
  patch: string;
  filesChanged: string[];
  addedLines: number;
  totalLines: number;
}

/** Stage everything (respecting .gitignore) and capture the full diff. */
export async function captureDiff(dir: string): Promise<CapturedDiff> {
  await git(dir, ["add", "-A"]);
  const patch = await git(dir, ["diff", "--cached"]);
  const status = await git(dir, ["status", "--porcelain"]);
  const filesChanged = status
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => l.replace(/^[A-Z? ]+\s+/, ""));
  let addedLines = 0;
  for (const line of patch.split("\n")) {
    if (line.startsWith("+") && !line.startsWith("+++")) addedLines += 1;
  }
  return { patch, filesChanged, addedLines, totalLines: patch.split("\n").length };
}

/** Added lines only (for secret/churn/network scans). */
export function addedLinesOf(patch: string): string[] {
  return patch
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .map((l) => l.slice(1));
}

export async function deleteWorktree(dir: string): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}

/**
 * Weak outside-worktree write check (§3.3, honestly labeled): snapshot
 * the temp area's files (excluding the worktree itself) before the run
 * and compare after. It catches careless writes, not a determined agent
 * — true confinement needs containers, which the deployment docs
 * recommend and v1.1 makes mandatory.
 */
export async function snapshotTempArea(
  root: string,
  excludeDir: string,
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  async function walk(d: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(d, e.name);
      if (resolve(p) === resolve(excludeDir)) continue;
      if (e.isDirectory()) await walk(p);
      else if (e.isFile()) {
        try {
          const s = await stat(p);
          out.set(relative(root, p), s.mtimeMs);
        } catch {
          // Vanished mid-walk; ignore.
        }
      }
    }
  }
  await walk(root);
  return out;
}

export function diffOutsideWrites(
  before: Map<string, number>,
  after: Map<string, number>,
): string[] {
  const changed: string[] = [];
  for (const [path, mtime] of after) {
    if (!before.has(path) || before.get(path) !== mtime) changed.push(path);
  }
  return changed;
}

/** Scratch dir for agent logs and temp files (deleted with the run). */
export async function makeScratchDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "wishship-scratch-"));
}

export async function writeSpecFile(dir: string, spec: unknown): Promise<string> {
  const specDir = join(dir, ".wishship");
  const { mkdir } = await import("node:fs/promises");
  await mkdir(specDir, { recursive: true });
  const path = join(specDir, "task.json");
  await writeFile(path, JSON.stringify(spec, null, 2));
  return path;
}

/* Test helpers intentionally use loose JSON types for API bodies. */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { FastifyInstance } from "fastify";
import type { Pool } from "pg";
import { signSession } from "./auth";
import { loadConfig, type WishShipConfig } from "./config";
import { createPool, migrate, truncateAll } from "./db";
import { FakeGitHubClient } from "./github";
import { Worker } from "./runner";
import { buildApp } from "./server";
import * as store from "./store";

const execFileAsync = promisify(execFile);

export const TEST_SESSION_SECRET = "wishship-test-session-secret";
// Per-process test database: the old shared `wishship_test` DB let one
// test file's resetDb() TRUNCATE another file's in-flight data ("run
// vanished", flaky counts across runs). Each test process gets its own
// database, created on demand from the base URL's credentials.
const TEST_DB_BASE =
  process.env.TEST_DATABASE_URL ??
  "postgres://wishship:wishship-dev@127.0.0.1:5432/wishship_test";
export const TEST_DATABASE_URL = (() => {
  const url = new URL(TEST_DB_BASE);
  url.pathname = `/wishship_test_${process.pid}`;
  return url.toString();
})();

// Tests run as development: loadConfig() refuses to boot without real
// secrets unless NODE_ENV is explicitly "development" (fail-closed).
if (!process.env.NODE_ENV) process.env.NODE_ENV = "development";

let sharedPool: Pool | null = null;

export async function getTestPool(): Promise<Pool> {
  if (!sharedPool) {
    const adminUrl = new URL(TEST_DATABASE_URL);
    const dbName = adminUrl.pathname.slice(1);
    adminUrl.pathname = "/postgres";
    const admin = createPool(adminUrl.toString());
    try {
      await admin.query(`CREATE DATABASE "${dbName}"`);
    } catch (err) {
      // 42P04 = already exists (e.g. a previous run's leftover).
      if ((err as { code?: string }).code !== "42P04") throw err;
    } finally {
      await admin.end();
    }
    sharedPool = createPool(TEST_DATABASE_URL);
    await migrate(sharedPool);
  }
  return sharedPool;
}

export async function resetDb(): Promise<Pool> {
  const pool = await getTestPool();
  await truncateAll(pool);
  return pool;
}

export function testConfig(overrides: Partial<WishShipConfig> = {}): WishShipConfig {
  return {
    ...loadConfig(),
    databaseUrl: TEST_DATABASE_URL,
    sessionSecret: TEST_SESSION_SECRET,
    baseUrl: "http://localhost:3000",
    ...overrides,
  };
}

let userSeq = 1000;

export async function makeUser(
  pool: Pool,
  overrides: Partial<{ login: string; ageDays: number }> = {},
): Promise<store.User> {
  userSeq += 1;
  const id = userSeq;
  const login = overrides.login ?? `user-${id}`;
  const ageDays = overrides.ageDays ?? 90;
  const user = await store.upsertUser(pool, {
    id,
    login,
    avatar_url: `https://example.invalid/${login}.png`,
    account_created_at: new Date(Date.now() - ageDays * 24 * 60 * 60 * 1000),
  });
  // pg returns bigint ids as strings; the session signer requires a number.
  return { ...user, id: Number(user.id) };
}

export async function makeRepo(
  pool: Pool,
  fullName: string,
  configOverrides: Partial<store.RepoConfig> = {},
): Promise<store.Repo> {
  const repo = await store.createRepo(pool, 4242, fullName);
  return (
    (await store.updateRepoConfig(pool, repo.id, {
      ...store.DEFAULT_REPO_CONFIG,
      ...configOverrides,
    })) ?? repo
  );
}

export function sessionCookie(user: { id: number; login: string }): string {
  return `wishship_session=${signSession(TEST_SESSION_SECRET, {
    id: Number(user.id),
    login: user.login,
  })}`;
}

export interface FixtureRepo {
  dir: string;
  commit: string;
}

/** Create a real local git repo with the given files, committed. */
export async function makeFixtureRepo(files: Record<string, string>): Promise<FixtureRepo> {
  const dir = await mkdtemp(join(tmpdir(), "wishship-fixture-"));
  const git = (args: string[]): Promise<string> =>
    execFileAsync("git", args, { cwd: dir }).then((r) => r.stdout as string);
  await git(["init", "-q", "-b", "main"]);
  await git(["config", "user.email", "fixture@example.invalid"]);
  await git(["config", "user.name", "Fixture"]);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(join(full, ".."), { recursive: true }).catch(() => undefined);
    // mkdir of dirname: handle nested paths properly below.
    await writeFile(full, content);
  }
  await git(["add", "-A"]);
  await git(["commit", "-q", "-m", "fixture base"]);
  const commit = (await git(["rev-parse", "HEAD"])).trim();
  return { dir, commit };
}

export interface TestApp {
  app: FastifyInstance;
  pool: Pool;
  github: FakeGitHubClient;
  worker: Worker;
  config: WishShipConfig;
  worktreeRoot: string;
}

export async function buildTestApp(
  scriptCommand: string | undefined,
  configOverrides: Partial<WishShipConfig> = {},
  reviewCommand: string | null = null,
): Promise<TestApp> {
  const pool = await resetDb();
  const worktreeRoot = await mkdtemp(join(tmpdir(), "wishship-wt-"));
  const agentHome = await mkdtemp(join(tmpdir(), "wishship-home-"));
  const config = testConfig({ worktreeRoot, agentHome, ...configOverrides });
  const github = new FakeGitHubClient();
  const operator = { globalPaused: false, operatorLogins: ["op-admin"] };
  const backends = {
    claudeCommand: undefined,
    codexCommand: undefined,
    scriptCommand,
    scriptReviewCommand: reviewCommand,
  };
  const worker = new Worker({
    pool,
    config,
    github,
    backends,
    resolveRepo: async () => ({ dir: "", cleanup: async () => undefined }),
    isGloballyPaused: () => operator.globalPaused,
  });
  // The worker's resolveRepo is replaced per test via setFixture below.
  const app = buildApp({
    pool,
    config,
    github,
    worker,
    operator,
    backends: { scriptCommand, scriptReviewCommand: reviewCommand },
  });
  return { app, pool, github, worker, config, worktreeRoot };
}

/** Point the test worker's repo resolution at a fixture directory. */
export function setFixture(
  testApp: TestApp,
  fixtureDir: string,
): void {
  (testApp.worker as unknown as { deps: { resolveRepo: unknown } }).deps.resolveRepo =
    async () => ({ dir: fixtureDir, cleanup: async () => undefined });
}

/** Drive the worker until a run reaches a terminal state (or timeout). */
export async function waitForRun(
  testApp: TestApp,
  runId: string,
  timeoutMs = 90000,
): Promise<store.Run> {
  const started = Date.now();
  for (;;) {
    await testApp.worker.tick();
    const run = await store.getRun(testApp.pool, runId);
    if (!run) throw new Error("run vanished");
    if (run.state === "pr_opened" || run.state === "failed" || run.state === "blocked") {
      return run;
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(`run ${runId} did not finish in ${timeoutMs}ms (state ${run.state})`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

/** Wait until no queued/claimed jobs remain (or timeout). */
export async function drainJobs(testApp: TestApp, timeoutMs = 90000): Promise<void> {
  const started = Date.now();
  for (;;) {
    await testApp.worker.tick();
    const jobs = await store.listQueuedJobs(testApp.pool);
    if (jobs.length === 0) return;
    if (Date.now() - started > timeoutMs) {
      throw new Error(`jobs did not drain in ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

export async function api(
  testApp: TestApp,
  method: string,
  url: string,
  opts: { user?: { id: number; login: string }; payload?: unknown } = {},
): Promise<{ status: number; body: Record<string, any> }> {
  const headers: Record<string, string> = {};
  if (opts.user) headers.cookie = sessionCookie(opts.user);
  const res = await testApp.app.inject({
    method: method as "GET" | "POST" | "PUT" | "DELETE" | "PATCH",
    url,
    headers,
    payload: opts.payload as never,
  });
  let body: Record<string, any> = {};
  try {
    body = JSON.parse(res.body) as Record<string, any>;
  } catch {
    body = { raw: res.body };
  }
  return { status: res.statusCode, body };
}

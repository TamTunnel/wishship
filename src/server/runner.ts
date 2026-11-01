import { spawn } from "node:child_process";
import type { AgentBackend, BackendConfig, TaskSpec } from "./agent";
import {
  buildAgentEnv,
  createBackend,
  DEFAULT_CONSTRAINTS,
} from "./agent";
import type { WishShipConfig } from "./config";
import type { GitHubClient } from "./github";
import { buildPrBody } from "./prbody";
import * as store from "./store";
import type { Repo, Run } from "./store";
import { audit } from "./store";
import {
  addedLinesPerFile,
  collectBaselineHosts,
  discoverCommands,
  verifyDiff,
} from "./verify";
import {
  captureDiff,
  createWorktree,
  deleteWorktree,
  diffOutsideWrites,
  snapshotTempArea,
} from "./worktree";
import { randomId } from "./config";

/** Resolves a repo to a local git source for cloning. */
export interface RepoSource {
  dir: string;
  cleanup: () => Promise<void>;
}

export type ResolveRepoSource = (repo: Repo) => Promise<RepoSource>;

export interface WorkerDeps {
  pool: import("pg").Pool;
  config: WishShipConfig;
  github: GitHubClient;
  backends: BackendConfig;
  resolveRepo: ResolveRepoSource;
  isGloballyPaused: () => boolean;
}

export class RunFailure extends Error {}

/** Apply a patch to a worktree via git apply on stdin. */
function applyPatch(dir: string, patch: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["apply", "--whitespace=nowarn"], {
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
      stdio: ["pipe", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else
        reject(
          new RunFailure(
            `patch does not apply to a clean checkout: ${stderr.slice(0, 300)}`,
          ),
        );
    });
    const stdin = child.stdin;
    if (stdin) {
      stdin.write(patch);
      stdin.end();
    }
  });
}

/**
 * Create a run for an approved winner. This is THE gate for probe 13:
 * run creation requires an approved winner record, enforced here at the
 * service layer — not just in the UI. Direct calls with a pending or
 * rejected winner are refused, so no agent runs and no money is spent
 * without maintainer approval.
 */
export async function createRunForWinner(
  pool: import("pg").Pool,
  winnerId: string,
  backend: string,
  allowDependencies: boolean,
  actorId: string,
  allowChurn: boolean = false,
): Promise<Run> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Row lock: concurrent creates for the same winner serialize here
    // instead of racing the active-run check below. The partial unique
    // index on active runs is the backstop if the lock is ever bypassed.
    const winnerRows = await client.query(
      `SELECT * FROM cycle_winners WHERE id = $1 FOR UPDATE`,
      [winnerId],
    );
    const winner = winnerRows.rows[0] as
      | { id: string; cycle_id: string; state: string }
      | undefined;
    if (!winner) throw new RunFailure("winner not found");
    if (winner.state !== "approved") {
      throw new RunFailure("winner has not been approved by a maintainer");
    }
    const active = await client.query(
      `SELECT COUNT(*)::text AS n FROM runs
       WHERE winner_id = $1 AND state IN ('queued','running','verifying')`,
      [winnerId],
    );
    if (Number(active.rows[0].n) > 0) {
      throw new RunFailure("winner already has an active run");
    }
    const run = await store.createRun(
      client,
      winnerId,
      backend,
      allowDependencies,
      null,
      allowChurn,
    );
    const cycle = await client.query(
      `SELECT repo_id FROM cycles WHERE id = $1`,
      [winner.cycle_id],
    );
    const repoId = cycle.rows[0].repo_id as string;
    await store.createJob(client, run.id, repoId);
    await client.query("COMMIT");
    await audit(pool, actorId, "run_created", "run", run.id, null, { backend });
    return run;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Atomic approve: decide + wish-state + run creation in ONE
 * transaction. The old route did decide, then wish-state, then run
 * creation as separate steps — run creation failing after decide left
 * the winner `approved` with no run and no re-approve path. Here a
 * failure rolls everything back, so the winner stays pending_approval
 * and the maintainer can retry.
 */
export async function approveWinnerAndCreateRun(
  pool: import("pg").Pool,
  winnerId: string,
  backend: string,
  allowDependencies: boolean,
  actorId: string,
  allowChurn: boolean = false,
): Promise<{ winner: store.CycleWinner; wish: store.Wish; run: Run }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const winnerRows = await client.query(
      `SELECT * FROM cycle_winners WHERE id = $1 FOR UPDATE`,
      [winnerId],
    );
    const winner = winnerRows.rows[0] as store.CycleWinner | undefined;
    if (!winner) throw new RunFailure("winner not found");
    if (winner.state !== "pending_approval") {
      throw new RunFailure(`winner is ${winner.state}`);
    }
    const decided = await store.decideWinner(
      client,
      winnerId,
      "approved",
      Number(actorId),
      null,
    );
    if (!decided) throw new RunFailure("winner is no longer pending approval");
    const wish = await store.getWish(client, winner.wish_id);
    if (!wish) throw new RunFailure("wish not found");
    await store.setWishState(client, wish.id, "approved");
    const active = await client.query(
      `SELECT COUNT(*)::text AS n FROM runs
       WHERE winner_id = $1 AND state IN ('queued','running','verifying')`,
      [winnerId],
    );
    if (Number(active.rows[0].n) > 0) {
      throw new RunFailure("winner already has an active run");
    }
    const run = await store.createRun(client, winnerId, backend, allowDependencies, null, allowChurn);
    const cycle = await client.query(
      `SELECT repo_id FROM cycles WHERE id = $1`,
      [winner.cycle_id],
    );
    await store.createJob(client, run.id, cycle.rows[0].repo_id as string);
    await client.query("COMMIT");
    await audit(pool, actorId, "winner_approved", "wish", wish.id, null, { backend });
    await audit(pool, actorId, "run_created", "run", run.id, null, { backend });
    // The retry path audits its churn override distinctly
    // (run_retried_with_churn_override); the approve-time path gets
    // its own event too, so both override routes are auditable.
    if (allowChurn) {
      await audit(pool, actorId, "run_approved_with_churn_override", "run", run.id, null, {
        backend,
        winnerId,
      });
    }
    return {
      winner: { ...winner, state: "approved" as const },
      wish: { ...wish, state: "approved" as const },
      run,
    };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Re-validate immediately before PR opening: the run must still be
 * `verifying` and its job still `claimed`. Crash recovery can finish a
 * job and mint a retry while the original worker is still in flight;
 * without this check the original worker would open a second PR for
 * the same winner (duplicate spend, duplicate PRs). On mismatch the
 * caller must NOT touch the job or run further — recovery owns them.
 */
export async function assertRunStillClaimed(
  pool: import("pg").Pool,
  jobId: string,
  runId: string,
): Promise<void> {
  const run = await store.getRun(pool, runId);
  const job = await store.getJob(pool, jobId);
  if (!run || run.state !== "verifying") {
    throw new RunFailure("run is no longer verifying (recovered elsewhere?)");
  }
  if (!job || job.status !== "claimed") {
    throw new RunFailure("job is no longer claimed (recovered elsewhere?)");
  }
}

/**
 * Open a PR for a run. THE gate for probe 12: the report is re-read
 * from the database and the tier must be VERIFIED or PARTIAL for THIS
 * run id. A BLOCKED report, a missing report, or a report for another
 * run is refused at the service layer, not just the UI.
 */
export async function openPrForRun(
  deps: WorkerDeps,
  run: Run,
  patch: string,
  baseCommit: string,
  defaultBranch: string,
): Promise<{ number: number; url: string; branch: string }> {
  const { pool, github } = deps;
  // Global pause is a claim-gate only in the worker loop; in-flight
  // runs must ALSO stop before opening PRs, or pausing mid-run does
  // nothing about the PR it was meant to prevent.
  if (deps.isGloballyPaused()) {
    throw new RunFailure("global pause is active; refusing to open a PR");
  }
  const report = await store.getReportByRun(pool, run.id);
  if (!report) throw new RunFailure("no verification report for this run");
  if (report.tier !== "VERIFIED" && report.tier !== "PARTIAL") {
    throw new RunFailure(
      `refusing to open a PR for a ${report.tier} report (run ${run.id})`,
    );
  }
  const winner = await store.getWinner(pool, run.winner_id);
  if (!winner) throw new RunFailure("winner not found");
  const wish = await store.getWish(pool, winner.wish_id);
  if (!wish) throw new RunFailure("wish not found");
  const cycle = await pool.query(`SELECT repo_id FROM cycles WHERE id = $1`, [
    winner.cycle_id,
  ]);
  const repoId = cycle.rows[0].repo_id as string;
  const repo = await store.getRepo(pool, repoId);
  if (!repo) throw new RunFailure("repo not found");
  const votes = await store.voteCount(pool, wish.id);
  const branch = `wishship/${wish.id.slice(0, 8)}-${randomId(6)}`;
  await github.pushBranch(
    repo.installation_id,
    repo.full_name,
    branch,
    baseCommit,
    patch,
  );
  const body = buildPrBody({
    wish,
    votes,
    backend: run.backend,
    tier: report.tier,
    checks: report.checks,
    durationMs: run.duration_ms,
    costUsd: run.cost_usd,
    runId: run.id,
    filesChanged: [...addedLinesPerFile(patch).keys()],
    churnOverride: run.allow_churn,
  });
  const pr = await github.openPr(
    repo.installation_id,
    repo.full_name,
    branch,
    defaultBranch,
    `${wish.title} (WishShip)`,
    body,
    repo.config.draftPr,
  );
  await store.createPr(
    pool,
    run.id,
    repoId,
    pr.number,
    pr.url,
    repo.config.draftPr ? "draft" : "open",
    branch,
  );
  const testsCheck = report.checks.find((c) => c.name === "tests");
  if (report.tier === "PARTIAL" && testsCheck?.status === "skipped") {
    await github.addLabels(repo.installation_id, repo.full_name, pr.number, [
      "no-test-suite",
    ]);
  }
  return { number: pr.number, url: pr.url, branch };
}

export class Worker {
  private deps: WorkerDeps;
  private timer: ReturnType<typeof setInterval> | null = null;
  private active = 0;
  private stopped = false;

  constructor(deps: WorkerDeps) {
    this.deps = deps;
  }

  start(): void {
    this.stopped = false;
    this.timer = setInterval(() => {
      void this.tick().catch((err) => {
        console.error("worker tick failed", err);
      });
    }, 1000);
    this.timer.unref?.();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Run one tick synchronously (used by tests and the interval loop). */
  async tick(): Promise<void> {
    if (this.stopped) return;
    await this.recoverStaleClaims();
    if (this.deps.isGloballyPaused()) return;
    const free = this.deps.config.maxConcurrentRuns - this.active;
    if (free <= 0) return;
    const jobs = await store.claimJobs(this.deps.pool, free);
    for (const job of jobs) {
      this.active += 1;
      void this.processJob(job.id, job.run_id, job.repo_id)
        .catch((err) => console.error("job failed", job.id, err))
        .finally(() => {
          this.active -= 1;
        });
    }
  }

  private async recoverStaleClaims(): Promise<void> {
    const { pool, config } = this.deps;
    // The stale threshold tracks the operator-configured run timeout:
    // the old hardcoded 30 minutes was SHORTER than a legitimate long
    // run, so recovery fired mid-flight and duplicated runs, spend,
    // and PRs. Floor at 30 minutes, plus a 10-minute margin over the
    // configured timeout.
    const staleMs = Math.max(30 * 60 * 1000, config.runTimeoutMs + 10 * 60 * 1000);
    const cutoff = new Date(Date.now() - staleMs);
    const rows = await pool.query(
      `SELECT j.id AS job_id, j.run_id, j.repo_id, j.attempts, r.state AS run_state FROM jobs j
       JOIN runs r ON r.id = j.run_id
       WHERE j.status = 'claimed' AND j.claimed_at < $1`,
      [cutoff],
    );
    for (const row of rows.rows as {
      job_id: string;
      run_id: string;
      repo_id: string;
      attempts: number;
      run_state: string;
    }[]) {
      // Crash between claim and setRunState(running): the run never
      // started, so just re-queue the job. No new run, no failure.
      if (row.run_state === "queued") {
        await pool.query(
          `UPDATE jobs SET status = 'queued', claimed_at = NULL, updated_at = now() WHERE id = $1`,
          [row.job_id],
        );
        await audit(pool, "system", "run_requeued_after_crash", "run", row.run_id, null, {
          jobId: row.job_id,
        });
        continue;
      }
      if (row.run_state !== "running" && row.run_state !== "verifying") {
        // Terminal already (or pr_opened): leave it alone.
        continue;
      }
      if (row.attempts > 2) {
        await store.setRunState(pool, row.run_id, "failed", {
          failure_reason: "worker lost (stale claim, attempts exhausted)",
        });
        await store.finishJob(pool, row.job_id, "failed", "stale claim");
        continue;
      }
      // Crash recovery, bounded by attempts: the old run is dead, a
      // fresh run takes its place. The retry job INHERITS the dead
      // job's attempt count, so the attempts > 2 guard above bounds
      // the whole chain instead of resetting on every hop (the old
      // code minted attempts-0 jobs forever).
      await store.setRunState(pool, row.run_id, "failed", {
        failure_reason: "worker lost (stale claim recovered)",
      });
      await store.finishJob(pool, row.job_id, "failed", "stale claim");
      const oldRun = await store.getRun(pool, row.run_id);
      if (!oldRun) continue;
      const retry = await store.createRun(
        pool,
        oldRun.winner_id,
        oldRun.backend,
        oldRun.allow_dependencies,
        oldRun.id,
        oldRun.allow_churn,
      );
      await store.createJob(pool, retry.id, row.repo_id, row.attempts);
      await audit(pool, "system", "run_recovered_after_crash", "run", retry.id, null, {
        previousRunId: oldRun.id,
      });
    }
  }

  async processJob(jobId: string, runId: string, repoId: string): Promise<void> {
    const { pool, config, github } = this.deps;
    const run = await store.getRun(pool, runId);
    if (!run) {
      await store.finishJob(pool, jobId, "failed", "run not found");
      return;
    }
    if (run.state !== "queued") {
      // Already terminal (e.g. recovered elsewhere): don't re-run.
      await store.finishJob(pool, jobId, "done");
      return;
    }
    const winner = await store.getWinner(pool, run.winner_id);
    if (!winner) {
      await store.setRunState(pool, runId, "failed", { failure_reason: "winner not found" });
      await store.finishJob(pool, jobId, "failed", "winner not found");
      return;
    }
    const wish = await store.getWish(pool, winner.wish_id);
    const repo = await store.getRepo(pool, repoId);
    if (!wish || !repo) {
      await store.setRunState(pool, runId, "failed", { failure_reason: "wish or repo not found" });
      await store.finishJob(pool, jobId, "failed", "wish or repo not found");
      return;
    }
    const startedAt = Date.now();
    let worktreeDir: string | null = null;
    let verifyDir: string | null = null;
    let source: Awaited<ReturnType<WorkerDeps["resolveRepo"]>> | null = null;
    // Cost is tracked so the failure path records it too: the old catch
    // dropped cost entirely, undercounting monthly spend.
    let knownCostUsd: number | null = null;
    // Fresh agent HOME per run: the old shared AGENT_HOME let one run's
    // agent plant CLI config/plugins/hooks that the next run's backend
    // CLI would load. Created here, deleted in the finally below.
    let agentHome: string | null = null;
    try {
      if (repo.paused || repo.disconnected) {
        throw new RunFailure("repo is paused or disconnected");
      }
      if (
        config.repoMonthlyBudgetUsd !== null &&
        (await store.monthlySpend(pool, repoId)) >= config.repoMonthlyBudgetUsd
      ) {
        throw new RunFailure("repo monthly budget exhausted");
      }
      await store.setRunState(pool, runId, "running");
      await store.setWishState(pool, wish.id, "implementing");
      await audit(pool, "system", "run_started", "run", runId, null, {
        backend: run.backend,
      });

      source = await this.deps.resolveRepo(repo);
      const worktree = await createWorktree(source.dir, "HEAD", config.worktreeRoot);
      worktreeDir = worktree.dir;
      const baseCommit = worktree.baseCommit;

      // Verification commands come from repo config at the base commit —
      // discovered BEFORE the agent runs, never from wish text.
      const commands = await discoverCommands(worktree.dir);
      const votes = await store.voteCount(pool, wish.id);

      let feedback: string | undefined;
      if (run.retry_of) {
        const prevReport = await store.getReportByRun(pool, run.retry_of);
        if (prevReport) {
          const failed = prevReport.checks.filter((c) => c.status === "failed");
          feedback = `Previous verification failed (${prevReport.tier}). Fix these and nothing else: ${failed
            .map((c) => `${c.name}: ${c.detail}`)
            .join("; ")}`;
        }
      }

      const spec: TaskSpec = {
        version: 1,
        wish: {
          title: wish.title,
          body: wish.body,
          votes,
          url: `${config.baseUrl}/repos/${repo.id}`,
        },
        repo: {
          name: repo.full_name,
          baseCommit,
          testCommand: commands.test,
          lintCommand: commands.lint,
          typecheckCommand: commands.typecheck,
        },
        constraints: [...DEFAULT_CONSTRAINTS, ...repo.config.constraints],
        injectionFlag: wish.injection_flag,
        injectionPatterns: wish.injection_patterns,
        verification: {
          willRun: [
            ...(commands.test ? ["tests"] : []),
            ...(commands.lint ? ["lint"] : []),
            ...(commands.typecheck ? ["typecheck"] : []),
            "secret_scan",
          ],
        },
      };
      const specWithFeedback = feedback
        ? { ...spec, constraints: [...spec.constraints, `Verifier feedback: ${feedback}`] }
        : spec;

      const before = await snapshotTempArea(config.worktreeRoot, worktree.dir);
      const backend: AgentBackend = createBackend(run.backend, this.deps.backends);
      const { mkdtemp } = await import("node:fs/promises");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");
      agentHome = await mkdtemp(join(tmpdir(), "wishship-agent-"));
      const agentEnv = { ...buildAgentEnv(config), HOME: agentHome };
      const result = await backend.run(specWithFeedback, worktree.dir, {
        timeoutMs: config.runTimeoutMs,
        env: agentEnv,
      });
      knownCostUsd = result.costUsd;
      const durationMs = Date.now() - startedAt;

      if (result.status === "timeout") {
        throw new RunFailure("agent timed out");
      }
      // Per-run cost cap, enforced where the backend reports usage.
      // Backends that don't report usage are time-bounded only, and the
      // run record says so (cost stays null).
      if (
        config.runCostCapUsd !== null &&
        result.costUsd !== null &&
        result.costUsd > config.runCostCapUsd
      ) {
        throw new RunFailure(
          `run cost $${result.costUsd} exceeded the per-run cap of $${config.runCostCapUsd}`,
        );
      }
      if (result.status === "error") {
        const needsInput = /WISHSHIP_NEEDS_INPUT:\s*(.+)/.exec(result.logs);
        if (needsInput) {
          await store.setRunState(pool, runId, "failed", {
            duration_ms: durationMs,
            cost_usd: result.costUsd === null ? undefined : String(result.costUsd),
            failure_reason: `needs_input: ${needsInput[1].slice(0, 500)}`,
          });
          await store.setWishState(pool, wish.id, "needs_input");
          await audit(pool, "system", "run_failed_needs_input", "run", runId, null, {
            reason: needsInput[1].slice(0, 500),
          });
          await store.finishJob(pool, jobId, "done");
          return;
        }
        throw new RunFailure(`agent failed: ${result.logs.slice(0, 500)}`);
      }

      const captured = await captureDiff(worktree.dir);
      if (!captured.patch.trim()) {
        throw new RunFailure("no changes produced (empty diff never becomes a PR)");
      }
      const after = await snapshotTempArea(config.worktreeRoot, worktree.dir);
      const outsideWrites = diffOutsideWrites(before, after);

      // Verification runs on a CLEAN checkout with the patch applied —
      // never in the agent's own worktree, where junk could hide.
      const verifyWorktree = await createWorktree(source.dir, baseCommit, config.worktreeRoot);
      verifyDir = verifyWorktree.dir;
      const baselineHosts = await collectBaselineHosts(verifyDir);
      await applyPatch(verifyDir, captured.patch);

      await store.setRunState(pool, runId, "verifying");
      const verified = await verifyDiff({
        spec: specWithFeedback,
        verifyDir,
        agentWorktreeDir: worktree.dir,
        baseCommit,
        patch: captured.patch,
        filesChanged: captured.filesChanged,
        addedLines: captured.addedLines,
        config: repo.config,
        allowDependencies: run.allow_dependencies,
        allowChurn: run.allow_churn,
        backend,
        baselineHosts,
        outsideWrites,
        // Pre-agent commands from the runner's base-commit discovery.
        // verifyDiff must never re-discover from the patched tree.
        commands,
      });
      const report = await store.createReport(pool, runId, verified.tier, verified.checks);

      if (verified.tier === "BLOCKED") {
        if (run.retry_of === null) {
          // Exactly one retry, with verifier feedback. After that the
          // run is dead — no silent retry loops, no runaway spend.
          // NOTE: the wish deliberately stays `implementing` while the
          // retry is queued (there is no `retrying` state in v1); the
          // retry run re-asserts `implementing` when it starts, and
          // the run record + audit show the retry chain.
          // ORDER MATTERS: the original run must leave the active set
          // (queued/running/verifying) BEFORE the retry is inserted,
          // or the partial unique index on active runs rejects the
          // retry with a duplicate-key error.
          await store.setRunState(pool, runId, "blocked", {
            duration_ms: durationMs,
            cost_usd: result.costUsd === null ? undefined : String(result.costUsd),
            failure_reason: `verification BLOCKED, retry queued: ${verified.checks
              .filter((c) => c.status === "failed")
              .map((c) => c.name)
              .join(", ")}`,
          });
          const retry = await store.createRun(
            pool,
            run.winner_id,
            run.backend,
            run.allow_dependencies,
            run.id,
            run.allow_churn,
          );
          await store.createJob(pool, retry.id, repoId);
          await audit(pool, "system", "run_blocked_retry_queued", "run", runId, null, {
            retryRunId: retry.id,
            tier: verified.tier,
          });
          await store.finishJob(pool, jobId, "done");
          return;
        }
        await store.setRunState(pool, runId, "blocked", {
          duration_ms: durationMs,
          cost_usd: result.costUsd === null ? undefined : String(result.costUsd),
          failure_reason: `verification BLOCKED after retry: ${verified.checks
            .filter((c) => c.status === "failed")
            .map((c) => c.name)
            .join(", ")}`,
        });
        await store.setWishState(pool, wish.id, "open");
        await audit(pool, "system", "run_blocked", "run", runId, null, {
          tier: verified.tier,
        });
        await store.finishJob(pool, jobId, "done");
        return;
      }

      // VERIFIED or PARTIAL: the PR gate re-reads the report from the
      // database and refuses anything else (probe 12, defense in depth).
      const repos = await github.listInstallationRepos(repo.installation_id);
      const defaultBranch =
        repos.find((r) => r.fullName === repo.full_name)?.defaultBranch ?? "main";
      const runFresh = await store.getRun(pool, runId);
      if (!runFresh) throw new RunFailure("run vanished");
      await store.setRunState(pool, runId, "verifying", {
        duration_ms: durationMs,
        cost_usd: result.costUsd === null ? undefined : String(result.costUsd),
      });
      // Re-validate immediately before PR opening: recovery may have
      // finished this job and minted a retry while this worker was in
      // flight. On mismatch, return WITHOUT touching job/run — recovery
      // owns them now (the outer catch must not run: it would flip the
      // recovered job's status and fail the recovered run's record).
      // Only the assertion's own refusal returns early; a DB error
      // still propagates to the failure path.
      try {
        await assertRunStillClaimed(pool, jobId, runId);
      } catch (err) {
        if (err instanceof RunFailure) return;
        throw err;
      }
      const pr = await openPrForRun(
        this.deps,
        { ...runFresh, duration_ms: durationMs, cost_usd: result.costUsd === null ? null : String(result.costUsd) },
        captured.patch,
        baseCommit,
        defaultBranch,
      );
      void report;
      await store.setRunState(pool, runId, "pr_opened", {
        duration_ms: durationMs,
        cost_usd: result.costUsd === null ? undefined : String(result.costUsd),
      });
      await store.setWishState(pool, wish.id, "pr_open");
      await audit(pool, "system", "pr_opened", "run", runId, null, {
        prNumber: pr.number,
        prUrl: pr.url,
        branch: pr.branch,
        tier: verified.tier,
      });
      await store.finishJob(pool, jobId, "done");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const durationMs = Date.now() - startedAt;
      await store
        .setRunState(pool, runId, "failed", {
          duration_ms: durationMs,
          cost_usd: knownCostUsd === null ? undefined : String(knownCostUsd),
          failure_reason: message.slice(0, 1000),
        })
        .catch(() => undefined);
      const currentWish = await store.getWish(pool, wish.id).catch(() => null);
      if (
        currentWish &&
        (currentWish.state === "implementing" || currentWish.state === "approved")
      ) {
        await store.setWishState(pool, wish.id, "open").catch(() => undefined);
      }
      await audit(pool, "system", "run_failed", "run", runId, null, {
        reason: message.slice(0, 500),
      }).catch(() => undefined);
      await store.finishJob(pool, jobId, "failed", message.slice(0, 500)).catch(() => undefined);
    } finally {
      if (worktreeDir) await deleteWorktree(worktreeDir).catch(() => undefined);
      if (verifyDir) await deleteWorktree(verifyDir).catch(() => undefined);
      if (source) await source.cleanup().catch(() => undefined);
      if (agentHome) {
        const { rm } = await import("node:fs/promises");
        await rm(agentHome, { recursive: true, force: true }).catch(() => undefined);
      }
    }
  }
}

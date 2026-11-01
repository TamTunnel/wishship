import type { Db } from "./db";
import { queryAll, queryOne } from "./db";
import type { Pool } from "pg";

export interface User {
  id: number;
  login: string;
  avatar_url: string;
  account_created_at: Date;
  last_seen_at: Date;
}

export type EligibilityMode = "any" | "stargazers" | "contributors" | "allowlist";

export interface RepoConfig {
  cycleDays: number;
  minVotes: number;
  ageFloorDays: number;
  eligibilityMode: EligibilityMode;
  allowlist: string[];
  diffMaxLines: number;
  diffMaxFiles: number;
  draftPr: boolean;
  /** Maintainer-editable constraints fed into the task spec. */
  constraints: string[];
}

export const DEFAULT_REPO_CONFIG: RepoConfig = {
  cycleDays: 7,
  minVotes: 3,
  ageFloorDays: 30,
  eligibilityMode: "any",
  allowlist: [],
  diffMaxLines: 500,
  diffMaxFiles: 20,
  draftPr: true,
  constraints: [],
};

export function mergeConfig(raw: unknown): RepoConfig {
  const o = (raw ?? {}) as Partial<RepoConfig>;
  return {
    cycleDays: o.cycleDays ?? DEFAULT_REPO_CONFIG.cycleDays,
    minVotes: o.minVotes ?? DEFAULT_REPO_CONFIG.minVotes,
    ageFloorDays: o.ageFloorDays ?? DEFAULT_REPO_CONFIG.ageFloorDays,
    eligibilityMode: o.eligibilityMode ?? DEFAULT_REPO_CONFIG.eligibilityMode,
    allowlist: o.allowlist ?? DEFAULT_REPO_CONFIG.allowlist,
    diffMaxLines: o.diffMaxLines ?? DEFAULT_REPO_CONFIG.diffMaxLines,
    diffMaxFiles: o.diffMaxFiles ?? DEFAULT_REPO_CONFIG.diffMaxFiles,
    draftPr: o.draftPr ?? DEFAULT_REPO_CONFIG.draftPr,
    constraints: o.constraints ?? DEFAULT_REPO_CONFIG.constraints,
  };
}

export interface Repo {
  id: string;
  installation_id: number;
  full_name: string;
  config: RepoConfig;
  paused: boolean;
  disconnected: boolean;
  created_at: Date;
  updated_at: Date;
}

export type WishState =
  | "open"
  | "proposed"
  | "approved"
  | "implementing"
  | "pr_open"
  | "shipped"
  | "rejected"
  | "hidden"
  | "needs_input";

export interface Wish {
  id: string;
  repo_id: string;
  author_id: number;
  title: string;
  body: string;
  linked_issue_url: string | null;
  state: WishState;
  injection_flag: boolean;
  injection_patterns: string[];
  secret_flag: boolean;
  secret_patterns: string[];
  created_at: Date;
  updated_at: Date;
}

export interface Vote {
  id: string;
  wish_id: string;
  voter_id: number;
  created_at: Date;
  withdrawn_at: Date | null;
}

export interface Cycle {
  id: string;
  repo_id: string;
  opened_at: Date;
  closed_at: Date | null;
  anomaly_suspected: boolean;
  anomaly_details: Record<string, unknown> | null;
}

export interface CycleWinner {
  id: string;
  cycle_id: string;
  wish_id: string;
  state: "pending_approval" | "approved" | "rejected";
  approver_id: number | null;
  reason: string | null;
}

export type RunState =
  | "queued"
  | "running"
  | "verifying"
  | "pr_opened"
  | "failed"
  | "blocked";

export interface Run {
  id: string;
  winner_id: string;
  backend: string;
  spec_version: number;
  state: RunState;
  worktree_commit: string | null;
  duration_ms: number | null;
  cost_usd: string | null;
  allow_dependencies: boolean;
  allow_churn: boolean;
  failure_reason: string | null;
  retry_of: string | null;
  created_at: Date;
  finished_at: Date | null;
}

export type Tier = "VERIFIED" | "PARTIAL" | "BLOCKED";

export interface CheckResult {
  name: string;
  status: "passed" | "failed" | "skipped" | "flagged";
  detail: string;
  output?: string;
}

export interface VerificationReport {
  id: string;
  run_id: string;
  tier: Tier;
  checks: CheckResult[];
}

export interface Pr {
  id: string;
  run_id: string;
  repo_id: string;
  number: number;
  url: string;
  state: "draft" | "open" | "merged" | "closed";
  branch: string;
}

export interface Job {
  id: string;
  run_id: string;
  repo_id: string;
  status: "queued" | "claimed" | "done" | "failed";
  attempts: number;
  error: string | null;
}

interface RepoRow {
  id: string;
  installation_id: number;
  full_name: string;
  config: unknown;
  paused: boolean;
  disconnected: boolean;
  created_at: Date;
  updated_at: Date;
}

function toRepo(row: RepoRow): Repo {
  return { ...row, config: mergeConfig(row.config) };
}

// ---------- users ----------

export async function upsertUser(
  pool: Db,
  u: { id: number; login: string; avatar_url: string; account_created_at: Date },
): Promise<User> {
  const row = await queryOne<User>(
    pool,
    `INSERT INTO users (id, login, avatar_url, account_created_at, last_seen_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (id) DO UPDATE SET login = EXCLUDED.login,
       avatar_url = EXCLUDED.avatar_url, last_seen_at = now()
     RETURNING *`,
    [u.id, u.login, u.avatar_url, u.account_created_at],
  );
  if (!row) throw new Error("upsertUser failed");
  return row;
}

export async function getUser(pool: Db, id: number): Promise<User | null> {
  return queryOne<User>(pool, `SELECT * FROM users WHERE id = $1`, [id]);
}

// ---------- repos ----------

export async function createRepo(
  pool: Db,
  installationId: number,
  fullName: string,
): Promise<Repo> {
  // NOTE: the upsert deliberately does NOT clear `disconnected`. A
  // deliberately disconnected repo used to silently re-enable on
  // re-link; re-enabling now requires an explicit maintainer reconnect.
  const row = await queryOne<RepoRow>(
    pool,
    `INSERT INTO repos (installation_id, full_name) VALUES ($1, $2)
     ON CONFLICT (full_name) DO UPDATE SET installation_id = EXCLUDED.installation_id,
       updated_at = now()
     RETURNING *`,
    [installationId, fullName],
  );
  if (!row) throw new Error("createRepo failed");
  return toRepo(row);
}

export async function getRepo(pool: Db, id: string): Promise<Repo | null> {
  const row = await queryOne<RepoRow>(pool, `SELECT * FROM repos WHERE id = $1`, [id]);
  return row ? toRepo(row) : null;
}

export async function getRepoByFullName(
  pool: Db,
  fullName: string,
): Promise<Repo | null> {
  const row = await queryOne<RepoRow>(
    pool,
    `SELECT * FROM repos WHERE full_name = $1`,
    [fullName],
  );
  return row ? toRepo(row) : null;
}

export async function listRepos(pool: Db): Promise<Repo[]> {
  const rows = await queryAll<RepoRow>(
    pool,
    `SELECT * FROM repos ORDER BY full_name`,
  );
  return rows.map(toRepo);
}

export async function updateRepoConfig(
  pool: Db,
  id: string,
  config: RepoConfig,
): Promise<Repo | null> {
  const row = await queryOne<RepoRow>(
    pool,
    `UPDATE repos SET config = $2::jsonb, updated_at = now() WHERE id = $1 RETURNING *`,
    [id, JSON.stringify(config)],
  );
  return row ? toRepo(row) : null;
}

export async function setRepoPaused(
  pool: Db,
  id: string,
  paused: boolean,
): Promise<void> {
  await pool.query(`UPDATE repos SET paused = $2, updated_at = now() WHERE id = $1`, [
    id,
    paused,
  ]);
}

export async function setRepoDisconnected(
  pool: Db,
  id: string,
  disconnected: boolean,
): Promise<void> {
  await pool.query(
    `UPDATE repos SET disconnected = $2, updated_at = now() WHERE id = $1`,
    [id, disconnected],
  );
}

// ---------- wishes ----------

export async function createWish(
  pool: Db,
  repoId: string,
  authorId: number,
  title: string,
  body: string,
  linkedIssueUrl: string | null,
  injectionFlag: boolean,
  injectionPatterns: string[],
  secretFlag = false,
  secretPatterns: string[] = [],
): Promise<Wish> {
  const row = await queryOne<Wish>(
    pool,
    `INSERT INTO wishes (repo_id, author_id, title, body, linked_issue_url,
       injection_flag, injection_patterns, secret_flag, secret_patterns)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
    [repoId, authorId, title, body, linkedIssueUrl, injectionFlag, injectionPatterns, secretFlag, secretPatterns],
  );
  if (!row) throw new Error("createWish failed");
  return row;
}

export async function getWish(pool: Db, id: string): Promise<Wish | null> {
  return queryOne<Wish>(pool, `SELECT * FROM wishes WHERE id = $1`, [id]);
}

export async function listWishes(
  pool: Db,
  repoId: string,
  state?: string,
  search?: string,
): Promise<Wish[]> {  const params: unknown[] = [repoId];
  let where = `repo_id = $1`;
  if (state) {
    params.push(state);
    where += ` AND state = $${params.length}`;
  }
  if (search) {
    params.push(search);
    where += ` AND (title ILIKE '%' || $${params.length} || '%' OR body ILIKE '%' || $${params.length} || '%')`;
  }
  return queryAll<Wish>(
    pool,
    `SELECT * FROM wishes WHERE ${where} ORDER BY created_at ASC`,
    params,
  );
}

export async function setWishState(
  pool: Db,
  id: string,
  state: WishState,
): Promise<void> {
  await pool.query(
    `UPDATE wishes SET state = $2, updated_at = now() WHERE id = $1`,
    [id, state],
  );
}

export async function setWishHidden(pool: Db, id: string): Promise<void> {
  await setWishState(pool, id, "hidden");
}

/** Board view: wishes with derived vote counts and voter logins. */
export interface BoardWish extends Wish {
  vote_count: number;
  voters: { id: number; login: string }[];
}

export async function getBoard(pool: Db, repoId: string): Promise<BoardWish[]> {
  const wishes = await listWishes(pool, repoId);
  const out: BoardWish[] = [];
  for (const w of wishes) {
    const count = await voteCount(pool, w.id);
    const voters = await queryAll<{ id: number; login: string }>(
      pool,
      `SELECT u.id, u.login FROM votes v JOIN users u ON u.id = v.voter_id
       WHERE v.wish_id = $1 AND v.withdrawn_at IS NULL ORDER BY v.created_at ASC`,
      [w.id],
    );
    out.push({ ...w, vote_count: count, voters });
  }
  return out;
}

// ---------- votes (ledger; counts are always derived) ----------

export class AlreadyVotedError extends Error {}

export async function castVote(
  pool: Db,
  wishId: string,
  voterId: number,
): Promise<Vote> {
  try {
    const row = await queryOne<Vote>(
      pool,
      `INSERT INTO votes (wish_id, voter_id) VALUES ($1, $2) RETURNING *`,
      [wishId, voterId],
    );
    if (!row) throw new Error("castVote failed");
    return row;
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "23505") throw new AlreadyVotedError("already voted");
    throw err;
  }
}

export async function withdrawVote(
  pool: Db,
  wishId: string,
  voterId: number,
): Promise<boolean> {
  const res = await pool.query(
    `UPDATE votes SET withdrawn_at = now()
     WHERE wish_id = $1 AND voter_id = $2 AND withdrawn_at IS NULL`,
    [wishId, voterId],
  );
  return (res.rowCount ?? 0) > 0;
}

export async function voteCount(pool: Db, wishId: string): Promise<number> {
  const row = await queryOne<{ n: string }>(
    pool,
    `SELECT COUNT(*)::text AS n FROM votes WHERE wish_id = $1 AND withdrawn_at IS NULL`,
    [wishId],
  );
  return Number(row?.n ?? 0);
}

export async function voteCounts(
  pool: Db,
  wishIds: string[],
): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  if (wishIds.length === 0) return out;
  const rows = await queryAll<{ wish_id: string; n: string }>(
    pool,
    `SELECT wish_id, COUNT(*)::text AS n FROM votes
     WHERE wish_id = ANY($1) AND withdrawn_at IS NULL GROUP BY wish_id`,
    [wishIds],
  );
  for (const r of rows) out.set(r.wish_id, Number(r.n));
  return out;
}

export async function listVotes(pool: Db, wishId: string): Promise<Vote[]> {
  return queryAll<Vote>(
    pool,
    `SELECT * FROM votes WHERE wish_id = $1 AND withdrawn_at IS NULL ORDER BY created_at ASC`,
    [wishId],
  );
}

export async function hasLiveVote(
  pool: Db,
  wishId: string,
  voterId: number,
): Promise<boolean> {
  const row = await queryOne<{ n: string }>(
    pool,
    `SELECT COUNT(*)::text AS n FROM votes
     WHERE wish_id = $1 AND voter_id = $2 AND withdrawn_at IS NULL`,
    [wishId, voterId],
  );
  return Number(row?.n ?? 0) > 0;
}

// ---------- cycles ----------

export async function getOpenCycle(pool: Db, repoId: string): Promise<Cycle | null> {
  return queryOne<Cycle>(
    pool,
    `SELECT * FROM cycles WHERE repo_id = $1 AND closed_at IS NULL ORDER BY opened_at DESC LIMIT 1`,
    [repoId],
  );
}

export async function openCycle(pool: Db, repoId: string): Promise<Cycle> {
  const row = await queryOne<Cycle>(
    pool,
    `INSERT INTO cycles (repo_id) VALUES ($1) RETURNING *`,
    [repoId],
  );
  if (!row) throw new Error("openCycle failed");
  return row;
}

export async function getCycle(pool: Db, id: string): Promise<Cycle | null> {
  return queryOne<Cycle>(pool, `SELECT * FROM cycles WHERE id = $1`, [id]);
}

export async function closeCycle(
  pool: Db,
  id: string,
  anomalySuspected: boolean,
  anomalyDetails: unknown,
): Promise<boolean> {
  // Conditional close: a concurrent close of the same cycle must fail
  // instead of silently double-closing. Callers check the return value.
  const res = await pool.query(
    `UPDATE cycles SET closed_at = now(), anomaly_suspected = $2,
     anomaly_details = $3::jsonb WHERE id = $1 AND closed_at IS NULL`,
    [id, anomalySuspected, anomalyDetails ? JSON.stringify(anomalyDetails) : null],
  );
  return (res.rowCount ?? 0) > 0;
}

export async function createWinner(
  pool: Db,
  cycleId: string,
  wishId: string,
): Promise<CycleWinner> {
  const row = await queryOne<CycleWinner>(
    pool,
    `INSERT INTO cycle_winners (cycle_id, wish_id) VALUES ($1, $2) RETURNING *`,
    [cycleId, wishId],
  );
  if (!row) throw new Error("createWinner failed");
  return row;
}

export async function getWinner(pool: Db, id: string): Promise<CycleWinner | null> {
  return queryOne<CycleWinner>(pool, `SELECT * FROM cycle_winners WHERE id = $1`, [id]);
}

export async function getPendingWinner(
  pool: Db,
  repoId: string,
): Promise<(CycleWinner & { wish: Wish }) | null> {
  const row = await queryOne<CycleWinner & { wish: Wish }>(
    pool,
    `SELECT cw.*, row_to_json(w.*) AS wish FROM cycle_winners cw
     JOIN wishes w ON w.id = cw.wish_id
     JOIN cycles c ON c.id = cw.cycle_id
     WHERE c.repo_id = $1 AND cw.state = 'pending_approval'
     ORDER BY cw.created_at DESC LIMIT 1`,
    [repoId],
  );
  return row;
}

export async function decideWinner(
  pool: Db,
  id: string,
  state: "approved" | "rejected",
  approverId: number,
  reason: string | null,
): Promise<boolean> {
  // Returns whether the transition happened: the conditional update is
  // the race guard, and callers MUST check it instead of assuming the
  // pre-check state still holds.
  const res = await pool.query(
    `UPDATE cycle_winners SET state = $2, approver_id = $3, reason = $4,
     decided_at = now() WHERE id = $1 AND state = 'pending_approval'`,
    [id, state, approverId, reason],
  );
  return (res.rowCount ?? 0) > 0;
}

// ---------- runs / reports / prs ----------

export async function createRun(
  pool: Db,
  winnerId: string,
  backend: string,
  allowDependencies: boolean,
  retryOf: string | null = null,
  allowChurn: boolean = false,
): Promise<Run> {
  const row = await queryOne<Run>(
    pool,
    `INSERT INTO runs (winner_id, backend, allow_dependencies, retry_of, allow_churn)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [winnerId, backend, allowDependencies, retryOf, allowChurn],
  );
  if (!row) throw new Error("createRun failed");
  return row;
}

export async function getRun(pool: Db, id: string): Promise<Run | null> {
  return queryOne<Run>(pool, `SELECT * FROM runs WHERE id = $1`, [id]);
}

export async function setRunState(
  pool: Db,
  id: string,
  state: RunState,
  patch: Partial<Pick<Run, "worktree_commit" | "duration_ms" | "cost_usd" | "failure_reason">> = {},
): Promise<void> {
  const sets: string[] = [`state = $2`, `updated_at = now()`];
  const params: unknown[] = [id, state];
  if (patch.worktree_commit !== undefined) {
    params.push(patch.worktree_commit);
    sets.push(`worktree_commit = $${params.length}`);
  }
  if (patch.duration_ms !== undefined) {
    params.push(patch.duration_ms);
    sets.push(`duration_ms = $${params.length}`);
  }
  if (patch.cost_usd !== undefined) {
    params.push(patch.cost_usd);
    sets.push(`cost_usd = $${params.length}`);
  }
  if (patch.failure_reason !== undefined) {
    params.push(patch.failure_reason);
    sets.push(`failure_reason = $${params.length}`);
  }
  if (state === "pr_opened" || state === "failed" || state === "blocked") {
    sets.push(`finished_at = now()`);
  }
  await pool.query(`UPDATE runs SET ${sets.join(", ")} WHERE id = $1`, params);
}

export async function createReport(
  pool: Db,
  runId: string,
  tier: Tier,
  checks: CheckResult[],
): Promise<VerificationReport> {
  const row = await queryOne<VerificationReport>(
    pool,
    `INSERT INTO verification_reports (run_id, tier, checks) VALUES ($1, $2, $3::jsonb) RETURNING *`,
    [runId, tier, JSON.stringify(checks)],
  );
  if (!row) throw new Error("createReport failed");
  return { id: row.id, run_id: row.run_id, tier: row.tier, checks };
}

export async function getReportByRun(
  pool: Db,
  runId: string,
): Promise<VerificationReport | null> {
  const row = await queryOne<{
    id: string;
    run_id: string;
    tier: Tier;
    checks: CheckResult[];
  }>(pool, `SELECT * FROM verification_reports WHERE run_id = $1`, [runId]);
  return row
    ? { id: row.id, run_id: row.run_id, tier: row.tier, checks: row.checks }
    : null;
}

export async function createPr(
  pool: Db,
  runId: string,
  repoId: string,
  number: number,
  url: string,
  state: Pr["state"],
  branch: string,
): Promise<Pr> {
  const row = await queryOne<Pr>(
    pool,
    `INSERT INTO prs (run_id, repo_id, number, url, state, branch)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [runId, repoId, number, url, state, branch],
  );
  if (!row) throw new Error("createPr failed");
  return row;
}

export async function setPrState(pool: Db, id: string, state: Pr["state"]): Promise<void> {
  await pool.query(
    `UPDATE prs SET state = $2, updated_at = now() WHERE id = $1`,
    [id, state],
  );
}

export async function getPrByRun(pool: Db, runId: string): Promise<Pr | null> {
  return queryOne<Pr>(pool, `SELECT * FROM prs WHERE run_id = $1`, [runId]);
}

export async function listRunsForRepo(
  pool: Db,
  repoId: string,
): Promise<(Run & { wish_id: string; wish_title: string })[]> {
  return queryAll<Run & { wish_id: string; wish_title: string }>(
    pool,
    `SELECT r.*, w.id AS wish_id, w.title AS wish_title FROM runs r
     JOIN cycle_winners cw ON cw.id = r.winner_id
     JOIN wishes w ON w.id = cw.wish_id
     JOIN cycles c ON c.id = cw.cycle_id
     WHERE c.repo_id = $1 ORDER BY r.created_at DESC LIMIT 100`,
    [repoId],
  );
}

export async function monthlySpend(pool: Db, repoId: string): Promise<number> {
  const row = await queryOne<{ s: string | null }>(
    pool,
    `SELECT COALESCE(SUM(cost_usd), 0)::text AS s FROM runs r
     JOIN cycle_winners cw ON cw.id = r.winner_id
     JOIN cycles c ON c.id = cw.cycle_id
     WHERE c.repo_id = $1 AND r.created_at >= date_trunc('month', now())`,
    [repoId],
  );
  return Number(row?.s ?? 0);
}

// ---------- audit (append-only: no update/delete functions exist) ----------

export async function audit(
  pool: Db,
  actorId: string,
  action: string,
  entityType: string,
  entityId: string,
  before: unknown = null,
  after: unknown = null,
): Promise<void> {
  await pool.query(
    `INSERT INTO audit_events (actor_id, action, entity_type, entity_id, before_state, after_state)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb)`,
    [
      actorId,
      action,
      entityType,
      entityId,
      before === null ? null : JSON.stringify(before),
      after === null ? null : JSON.stringify(after),
    ],
  );
}

export async function listAudit(
  pool: Db,
  repoId: string,
  limit = 200,
): Promise<Record<string, unknown>[]> {
  // Audit rows carry entity ids; repo-scoped views filter on wish/run ids
  // belonging to the repo, plus cycle entities (cycle_closed events used
  // to be invisible in the repo audit view). The repo id is passed
  // twice: $1 for the UUID columns, $3 for the text comparison, because
  // one parameter cannot carry two inferred types.
  return queryAll<Record<string, unknown>>(
    pool,
    `SELECT a.* FROM audit_events a
     WHERE a.entity_id IN (SELECT id::text FROM wishes WHERE repo_id = $1)
        OR a.entity_id IN (SELECT r.id::text FROM runs r
           JOIN cycle_winners cw ON cw.id = r.winner_id
           JOIN cycles c ON c.id = cw.cycle_id WHERE c.repo_id = $1)
        OR (a.entity_type = 'cycle' AND a.entity_id IN
            (SELECT id::text FROM cycles WHERE repo_id = $1))
        OR a.entity_id = $3
     ORDER BY a.id DESC LIMIT $2`,
    [repoId, limit, repoId],
  );
}

// ---------- jobs ----------

export async function getJob(pool: Db, id: string): Promise<Job | null> {
  return queryOne<Job>(pool, `SELECT * FROM jobs WHERE id = $1`, [id]);
}

export async function createJob(
  pool: Db,
  runId: string,
  repoId: string,
  attempts = 0,
): Promise<Job> {
  // `attempts` is carried across crash-recovery chains (the recovery
  // job inherits the dead job's attempt count) so the attempts guard
  // bounds the whole chain instead of resetting per hop.
  const row = await queryOne<Job>(
    pool,
    `INSERT INTO jobs (run_id, repo_id, attempts) VALUES ($1, $2, $3) RETURNING *`,
    [runId, repoId, attempts],
  );
  if (!row) throw new Error("createJob failed");
  return row;
}

/**
 * Claim up to `limit` queued jobs, one active run per repo. Two guards
 * compose here, and both are needed:
 * - No running/verifying run for the repo (prevents a second run while
 *   one is in flight).
 * - No other CLAIMED job for the repo (a claimed job's run is still
 *   `queued` until processJob starts it, so the run-state guard alone
 *   lets two queued jobs for one repo through in one batch).
 * Per-repo serialization uses a transaction-scoped advisory lock
 * (pg_try_advisory_xact_lock): non-blocking, deadlock-free, and it
 * makes concurrent workers skip — not fight over — the same repo.
 * SKIP LOCKED keeps concurrent workers off each other's job rows.
 */
export async function claimJobs(pool: Pool, limit: number): Promise<Job[]> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const candidates = await queryAll<Job>(
      client,
      `SELECT j.* FROM jobs j
       WHERE j.status = 'queued'
         AND NOT EXISTS (
           SELECT 1 FROM repos r WHERE r.id = j.repo_id AND (r.paused OR r.disconnected)
         )
       ORDER BY j.created_at ASC
       LIMIT $1
       FOR UPDATE SKIP LOCKED`,
      [limit * 4],
    );
    const claimed: Job[] = [];
    for (const job of candidates) {
      if (claimed.length >= limit) break;
      const lock = await queryOne<{ ok: boolean }>(
        client,
        `SELECT pg_try_advisory_xact_lock(hashtext($1)) AS ok`,
        [job.repo_id],
      );
      if (!lock?.ok) continue;
      const active = await queryOne<{ n: string }>(
        client,
        `SELECT COUNT(*)::text AS n FROM runs r
         JOIN jobs j2 ON j2.run_id = r.id
         WHERE j2.repo_id = $1 AND r.state IN ('running','verifying')`,
        [job.repo_id],
      );
      if (Number(active?.n ?? 0) > 0) continue;
      const alreadyClaimed = await queryOne<{ n: string }>(
        client,
        `SELECT COUNT(*)::text AS n FROM jobs
         WHERE repo_id = $1 AND status = 'claimed' AND id <> $2`,
        [job.repo_id, job.id],
      );
      if (Number(alreadyClaimed?.n ?? 0) > 0) continue;
      const row = await queryOne<Job>(
        client,
        `UPDATE jobs SET status = 'claimed', claimed_at = now(),
           attempts = attempts + 1, updated_at = now()
         WHERE id = $1 RETURNING *`,
        [job.id],
      );
      if (row) claimed.push(row);
    }
    await client.query("COMMIT");
    return claimed;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function finishJob(
  pool: Db,
  id: string,
  status: "done" | "failed",
  error: string | null = null,
): Promise<void> {
  await pool.query(
    `UPDATE jobs SET status = $2, error = $3, updated_at = now() WHERE id = $1`,
    [id, status, error],
  );
}

export async function listQueuedJobs(pool: Db): Promise<Job[]> {
  return queryAll<Job>(
    pool,
    `SELECT * FROM jobs WHERE status IN ('queued','claimed') ORDER BY created_at ASC`,
    [],
  );
}

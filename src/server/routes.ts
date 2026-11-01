import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import type { Pool } from "pg";
import {
  exchangeCode,
  fetchOAuthUser,
  githubAuthorizeUrl,
  signSession,
  verifySession,
  type SessionUser,
} from "./auth";
import type { WishShipConfig } from "./config";
import { randomId } from "./config";
import { closeCycleAndPropose, maintainerPick } from "./cycles";
import type { GitHubClient } from "./github";
import { scanInjection } from "./injection";
import { scanSecrets } from "./secretscan";
import { approveWinnerAndCreateRun, type Worker } from "./runner";
import * as store from "./store";
import { audit } from "./store";
import {
  checkEligibility,
  LIMITS,
  votesInLastHour,
  votesToday,
  wishesToday,
} from "./voting";

export interface OperatorState {
  globalPaused: boolean;
  operatorLogins: string[];
}

export interface RouteDeps {
  pool: Pool;
  config: WishShipConfig;
  github: GitHubClient;
  worker: Worker;
  operator: OperatorState;
  backends: { scriptCommand?: string; scriptReviewCommand?: string | null };
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function sessionCookie(value: string, config: WishShipConfig): string {
  return [
    `wishship_session=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    ...(config.isProduction ? ["Secure"] : []),
  ].join("; ");
}

function clearSessionCookie(): string {
  return "wishship_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
}

function getSession(req: FastifyRequest, config: WishShipConfig): SessionUser | null {
  const cookies = parseCookies(req.headers.cookie);
  const raw = cookies["wishship_session"];
  if (!raw) return null;
  return verifySession(config.sessionSecret, raw);
}

function requireAuth(
  req: FastifyRequest,
  reply: FastifyReply,
  config: WishShipConfig,
): SessionUser | null {
  const user = getSession(req, config);
  if (!user) {
    void reply.code(401).send({ error: "authentication required (sign in with GitHub)" });
    return null;
  }
  return user;
}

function isOperator(deps: RouteDeps, login: string): boolean {
  return deps.operator.operatorLogins.includes(login.toLowerCase());
}

async function requireMaintainer(
  deps: RouteDeps,
  repo: store.Repo,
  user: SessionUser,
  reply: FastifyReply,
): Promise<boolean> {
  if (isOperator(deps, user.login)) return true;
  let ok = false;
  try {
    ok = await deps.github.isMaintainer(repo.installation_id, repo.full_name, user.login);
  } catch {
    ok = false;
  }
  if (!ok) {
    void reply.code(403).send({ error: "maintainer only" });
    return false;
  }
  return true;
}

function ipOf(req: FastifyRequest): string {
  return req.ip ?? "unknown";
}

/** Per-IP throttle for public board reads (in-memory, single service). */
class IpThrottle {
  private hits = new Map<string, { count: number; windowStart: number }>();
  private limit = 120;
  private windowMs = 60 * 1000;

  check(ip: string): boolean {
    const now = Date.now();
    const entry = this.hits.get(ip);
    if (!entry || now - entry.windowStart > this.windowMs) {
      this.hits.set(ip, { count: 1, windowStart: now });
      return true;
    }
    entry.count += 1;
    if (entry.count > this.limit) return false;
    return true;
  }
}

function bodyOf(req: FastifyRequest): Record<string, unknown> {
  return (req.body ?? {}) as Record<string, unknown>;
}

/**
 * The anomaly belongs to the CLOSED cycle that proposed this winner —
 * not the currently open cycle. The old pending response carried no
 * anomaly data at all, so the approval screen could never show the
 * flag the spec requires "prominently, with the underlying numbers".
 */
async function pendingAnomaly(
  pool: Pool,
  pending: { cycle_id: string } | null,
): Promise<{ suspected: boolean; details: unknown } | null> {
  if (!pending) return null;
  const cycle = await store.getCycle(pool, pending.cycle_id);
  if (!cycle || !cycle.anomaly_suspected) return null;
  return { suspected: true, details: cycle.anomaly_details };
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

export function registerRoutes(app: FastifyInstance, deps: RouteDeps): void {
  const { pool, config, github } = deps;
  const throttle = new IpThrottle();

  // Write throttle: the old IpThrottle covered board reads only, so a
  // single IP could hammer every write endpoint. Writes are also
  // authenticated and DB-rate-limited (votes/wishes), but the shared
  // 120/min/IP throttle now bounds bursts on all /api/ writes too.
  app.addHook("onRequest", async (req, reply) => {
    if (
      (req.method === "POST" || req.method === "PUT") &&
      req.url.split("?")[0].startsWith("/api/")
    ) {
      if (!throttle.check(ipOf(req))) {
        return reply.code(429).send({ error: "rate limited, try again shortly" });
      }
    }
  });

  app.get("/api/health", async () => ({ ok: true, version: "0.1.0" }));

  // ---------- auth ----------
  app.get("/api/auth/login", async (_req, reply) => {
    if (!config.githubOAuthClientId) {
      return reply.code(503).send({ error: "GitHub OAuth is not configured" });
    }
    const state = randomId(16);
    void reply.header(
      "Set-Cookie",
      `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`,
    );
    return reply.redirect(githubAuthorizeUrl(config.githubOAuthClientId, config.baseUrl, state));
  });

  app.get("/api/auth/callback", async (req, reply) => {
    const query = req.query as Record<string, string>;
    const cookies = parseCookies(req.headers.cookie);
    if (!query.code || cookies["oauth_state"] !== query.state) {
      return reply.code(400).send({ error: "invalid OAuth state" });
    }
    const token = await exchangeCode(
      config.githubOAuthClientId,
      config.githubOAuthClientSecret,
      query.code,
      config.baseUrl,
    );
    const ghUser = await fetchOAuthUser(token);
    await store.upsertUser(pool, {
      id: ghUser.id,
      login: ghUser.login,
      avatar_url: ghUser.avatar_url,
      account_created_at: new Date(ghUser.created_at),
    });
    void reply.header(
      "Set-Cookie",
      sessionCookie(signSession(config.sessionSecret, { id: ghUser.id, login: ghUser.login }), config),
    );
    return reply.redirect("/");
  });

  app.post("/api/auth/logout", async (_req, reply) => {
    void reply.header("Set-Cookie", clearSessionCookie());
    return { ok: true };
  });

  app.get("/api/auth/me", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const full = await store.getUser(pool, user.id);
    return { user: full ?? user };
  });

  // ---------- repos ----------
  app.get("/api/repos", async () => {
    const repos = await store.listRepos(pool);
    return { repos };
  });

  app.post("/api/repos/link", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const body = bodyOf(req);
    const installationId = body.installationId;
    const fullName = asString(body.fullName);
    if (typeof installationId !== "number" || !fullName) {
      return reply.code(400).send({ error: "installationId and fullName are required" });
    }
    // Verify the installation actually covers this repo before linking.
    const repos = await github.listInstallationRepos(installationId);
    if (!repos.some((r) => r.fullName === fullName)) {
      return reply.code(400).send({ error: "installation does not cover this repo" });
    }
    // Linking is a maintainer act: the old code let ANY authenticated
    // user link any installation-covered repo (sequential, guessable
    // ids), and re-linking silently re-enabled disconnected repos.
    const probe: store.Repo = {
      id: "",
      installation_id: installationId,
      full_name: fullName,
      config: store.DEFAULT_REPO_CONFIG,
      paused: false,
      disconnected: false,
      created_at: new Date(),
      updated_at: new Date(),
    };
    if (!(await requireMaintainer(deps, probe, user, reply))) return;
    const repo = await store.createRepo(pool, installationId, fullName);
    await audit(pool, String(user.id), "repo_linked", "repo", repo.id, null, { fullName });
    return { repo };
  });

  app.post("/api/repos/:id/reconnect", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    // Explicit maintainer reconnect: the ONLY path that clears
    // `disconnected`. Re-linking a disconnected repo leaves it
    // disconnected (see createRepo).
    await store.setRepoDisconnected(pool, repo.id, false);
    await audit(pool, String(user.id), "repo_reconnected", "repo", repo.id, null, {});
    return { disconnected: false };
  });

  app.get("/api/repos/:id", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    return { repo };
  });

  app.get("/api/repos/:id/board", async (req, reply) => {
    if (!throttle.check(ipOf(req))) {
      return reply.code(429).send({ error: "rate limited, try again shortly" });
    }
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    const board = await store.getBoard(pool, repo.id);
    const cycle = await store.getOpenCycle(pool, repo.id);
    const pending = await store.getPendingWinner(pool, repo.id);
    return { repo, board, cycle, pending, anomaly: await pendingAnomaly(pool, pending) };
  });

  app.get("/api/repos/:id/config", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    return { config: repo.config };
  });

  app.put("/api/repos/:id/config", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    const body = bodyOf(req);
    const cfg = { ...repo.config };
    const setNum = (key: keyof store.RepoConfig, min: number, max: number) => {
      const v = body[key];
      if (typeof v === "number" && Number.isFinite(v) && v >= min && v <= max) {
        (cfg as Record<string, unknown>)[key] = Math.floor(v);
      }
    };
    setNum("cycleDays", 1, 90);
    setNum("minVotes", 1, 10000);
    setNum("ageFloorDays", 0, 365);
    setNum("diffMaxLines", 10, 100000);
    setNum("diffMaxFiles", 1, 1000);
    if (typeof body.eligibilityMode === "string" &&
      ["any", "stargazers", "contributors", "allowlist"].includes(body.eligibilityMode)) {
      cfg.eligibilityMode = body.eligibilityMode as store.EligibilityMode;
    }
    if (Array.isArray(body.allowlist)) {
      cfg.allowlist = body.allowlist.filter((x): x is string => typeof x === "string");
    }
    if (typeof body.draftPr === "boolean") cfg.draftPr = body.draftPr;
    if (Array.isArray(body.constraints)) {
      cfg.constraints = body.constraints.filter((x): x is string => typeof x === "string");
    }
    const updated = await store.updateRepoConfig(pool, repo.id, cfg);
    await audit(pool, String(user.id), "repo_config_updated", "repo", repo.id, repo.config, cfg);
    return { config: updated?.config ?? cfg };
  });

  app.post("/api/repos/:id/pause", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    const paused = bodyOf(req).paused === true;
    await store.setRepoPaused(pool, repo.id, paused);
    await audit(pool, String(user.id), paused ? "repo_paused" : "repo_resumed", "repo", repo.id, null, { paused });
    return { paused };
  });

  app.post("/api/repos/:id/disconnect", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    await store.setRepoDisconnected(pool, repo.id, true);
    await audit(pool, String(user.id), "repo_disconnected", "repo", repo.id, null, {});
    return { disconnected: true };
  });

  // ---------- wishes & votes ----------
  app.post("/api/repos/:id/wishes", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (repo.disconnected) return reply.code(409).send({ error: "repo is disconnected" });
    const body = bodyOf(req);
    const title = asString(body.title)?.trim();
    const wishBody = asString(body.body) ?? "";
    const linked = asString(body.linkedIssueUrl);
    if (!title || title.length > 200) {
      return reply.code(400).send({ error: "title is required (max 200 chars)" });
    }
    if (wishBody.length > 20000) {
      return reply.code(400).send({ error: "body is too long (max 20000 chars)" });
    }
    if ((await wishesToday(pool, repo.id, user.id)) >= LIMITS.wishesPerUserPerRepoPerDay) {
      return reply.code(429).send({ error: "wish submission limit reached for today" });
    }
    const patterns = scanInjection(`${title}\n${wishBody}`);
    // Secret-shaped material in the wish body is flagged at submission
    // (not blocking) and, crucially, WITHHELD from the PR body — the
    // old code shipped wish bodies verbatim into PRs, including any
    // secret-shaped text they contained.
    const secretPatterns = scanSecrets(`${title}\n${wishBody}`);
    const wish = await store.createWish(
      pool,
      repo.id,
      user.id,
      title,
      wishBody,
      linked,
      patterns.length > 0,
      patterns,
      secretPatterns.length > 0,
      secretPatterns,
    );
    await audit(pool, String(user.id), "wish_submitted", "wish", wish.id, null, {
      title,
      injectionFlag: patterns.length > 0,
      secretFlag: secretPatterns.length > 0,
    });
    return reply.code(201).send({ wish });
  });

  app.get("/api/wishes/:id", async (req, reply) => {
    const wish = await store.getWish(pool, (req.params as { id: string }).id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const count = await store.voteCount(pool, wish.id);
    const voters = await store.listVotes(pool, wish.id);
    return { wish, voteCount: count, voters };
  });

  app.post("/api/wishes/:id/vote", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const wish = await store.getWish(pool, (req.params as { id: string }).id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    const dbUser = await store.getUser(pool, user.id);
    if (!dbUser) return reply.code(401).send({ error: "unknown user" });
    // Only open wishes accept votes (probe 4: no votes after cycle close).
    if (wish.state !== "open") {
      await audit(pool, String(user.id), "vote_refused_closed", "wish", wish.id, null, {
        state: wish.state,
      });
      return reply.code(409).send({ error: `wish is ${wish.state}, not open for voting` });
    }
    if ((await votesInLastHour(pool, user.id)) >= LIMITS.votesPerUserPerHour) {
      return reply.code(429).send({ error: "vote rate limit reached (hourly)" });
    }
    if ((await votesToday(pool, user.id)) >= LIMITS.votesPerUserPerDay) {
      return reply.code(429).send({ error: "vote rate limit reached (daily)" });
    }
    const eligibility = await checkEligibility(github, repo, dbUser);
    if (!eligibility.eligible) {
      await audit(pool, String(user.id), "vote_refused_eligibility", "wish", wish.id, null, {
        reason: eligibility.reason,
      });
      return reply.code(403).send({ error: eligibility.reason });
    }
    try {
      const vote = await store.castVote(pool, wish.id, user.id);
      await audit(pool, String(user.id), "vote_cast", "wish", wish.id, null, {
        voteId: vote.id,
      });
      return { vote, count: await store.voteCount(pool, wish.id) };
    } catch (err) {
      if (err instanceof store.AlreadyVotedError) {
        return reply.code(409).send({ error: "already voted" });
      }
      throw err;
    }
  });

  app.post("/api/wishes/:id/unvote", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const wish = await store.getWish(pool, (req.params as { id: string }).id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    if (wish.state !== "open") {
      return reply.code(409).send({ error: "votes can only be withdrawn before the cycle closes" });
    }
    const withdrawn = await store.withdrawVote(pool, wish.id, user.id);
    if (!withdrawn) return reply.code(404).send({ error: "no live vote to withdraw" });
    await audit(pool, String(user.id), "vote_withdrawn", "wish", wish.id, null, {});
    return { count: await store.voteCount(pool, wish.id) };
  });

  app.post("/api/wishes/:id/hide", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const wish = await store.getWish(pool, (req.params as { id: string }).id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    // Hiding preserves the record and the audit event; never deletes.
    await store.setWishHidden(pool, wish.id);
    await audit(pool, String(user.id), "wish_hidden", "wish", wish.id, { state: wish.state }, { state: "hidden" });
    return { wish: { ...wish, state: "hidden" as const } };
  });

  // ---------- cycles & winners ----------
  app.post("/api/repos/:id/cycles/close", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    try {
      const result = await closeCycleAndPropose(pool, repo, String(user.id));
      return result;
    } catch (err) {
      return reply.code(400).send({ error: (err as Error).message });
    }
  });

  app.get("/api/repos/:id/pending", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    const pending = await store.getPendingWinner(pool, repo.id);
    if (!pending) return { pending: null };
    const count = await store.voteCount(pool, pending.wish_id);
    return { pending, voteCount: count, anomaly: await pendingAnomaly(pool, pending) };
  });

  app.post("/api/repos/:id/pick", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    const wishId = asString(bodyOf(req).wishId);
    if (!wishId) return reply.code(400).send({ error: "wishId is required" });
    try {
      const winner = await maintainerPick(pool, repo, wishId, String(user.id));
      return { winner };
    } catch (err) {
      return reply.code(400).send({ error: (err as Error).message });
    }
  });

  app.post("/api/winners/:id/approve", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const winner = await store.getWinner(pool, (req.params as { id: string }).id);
    if (!winner) return reply.code(404).send({ error: "winner not found" });
    const wish = await store.getWish(pool, winner.wish_id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    if (winner.state !== "pending_approval") {
      return reply.code(409).send({ error: `winner is ${winner.state}` });
    }
    const backend = asString(bodyOf(req).backend) ?? "script";
    if (!["claude", "codex", "script"].includes(backend)) {
      return reply.code(400).send({ error: "unknown backend" });
    }
    if (backend === "script" && !deps.backends.scriptCommand) {
      return reply.code(400).send({ error: "script backend is not configured on this instance" });
    }
    const allowDependencies = bodyOf(req).allowDependencies === true;
    const allowChurn = bodyOf(req).allowChurn === true;
    // Atomic: decide + wish-state + run creation in one transaction.
    // A run-creation failure no longer strands an approved winner.
    try {
      const result = await approveWinnerAndCreateRun(
        pool,
        winner.id,
        backend,
        allowDependencies,
        String(user.id),
        allowChurn,
      );
      return { winner: result.winner, run: result.run };
    } catch (err) {
      return reply.code(400).send({ error: (err as Error).message });
    }
  });

  app.post("/api/winners/:id/reject", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const winner = await store.getWinner(pool, (req.params as { id: string }).id);
    if (!winner) return reply.code(404).send({ error: "winner not found" });
    const wish = await store.getWish(pool, winner.wish_id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    if (winner.state !== "pending_approval") {
      return reply.code(409).send({ error: `winner is ${winner.state}` });
    }
    const reason = asString(bodyOf(req).reason);
    const decided = await store.decideWinner(pool, winner.id, "rejected", user.id, reason);
    if (!decided) {
      return reply.code(409).send({ error: `winner is no longer pending approval` });
    }
    // Rejection returns the wish to open; no auto-advance to runner-up.
    await store.setWishState(pool, wish.id, "open");
    await audit(pool, String(user.id), "winner_rejected", "wish", wish.id, null, { reason });
    return { winner: { ...winner, state: "rejected" as const } };
  });

  // ---------- runs & PR decisions ----------
  app.get("/api/repos/:id/runs", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    const runs = await store.listRunsForRepo(pool, repo.id);
    const enriched = [];
    for (const r of runs) {
      enriched.push({
        ...r,
        report: await store.getReportByRun(pool, r.id),
        pr: await store.getPrByRun(pool, r.id),
      });
    }
    return { runs: enriched };
  });

  app.get("/api/runs/:id", async (req, reply) => {
    const run = await store.getRun(pool, (req.params as { id: string }).id);
    if (!run) return reply.code(404).send({ error: "run not found" });
    return {
      run,
      report: await store.getReportByRun(pool, run.id),
      pr: await store.getPrByRun(pool, run.id),
    };
  });

  app.post("/api/runs/:id/retry-with-deps", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const run = await store.getRun(pool, (req.params as { id: string }).id);
    if (!run) return reply.code(404).send({ error: "run not found" });
    if (run.state !== "blocked") {
      return reply.code(409).send({ error: "only blocked runs can be retried with dependencies permitted" });
    }
    const winner = await store.getWinner(pool, run.winner_id);
    if (!winner) return reply.code(404).send({ error: "winner not found" });
    const wish = await store.getWish(pool, winner.wish_id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    // Guards the old code lacked: retrying a shipped/rejected wish
    // resurrected it, and retrying while a run was active duplicated
    // runs. Only open/needs_input wishes with no active run qualify.
    if (wish.state !== "open" && wish.state !== "needs_input") {
      return reply.code(409).send({ error: `wish is ${wish.state}, cannot retry` });
    }
    const active = await pool.query(
      `SELECT COUNT(*)::text AS n FROM runs
       WHERE winner_id = $1 AND state IN ('queued','running','verifying')`,
      [winner.id],
    );
    if (Number(active.rows[0].n) > 0) {
      return reply.code(409).send({ error: "winner already has an active run" });
    }
    const retry = await store.createRun(pool, winner.id, run.backend, true, run.id);
    await store.createJob(pool, retry.id, repo.id);
    await audit(pool, String(user.id), "run_retried_with_deps", "run", retry.id, null, {
      previousRunId: run.id,
    });
    return { run: retry };
  });

  app.post("/api/runs/:id/retry-with-churn-override", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const run = await store.getRun(pool, (req.params as { id: string }).id);
    if (!run) return reply.code(404).send({ error: "run not found" });
    if (run.state !== "blocked") {
      return reply.code(409).send({ error: "only blocked runs can be retried with a churn override" });
    }
    const winner = await store.getWinner(pool, run.winner_id);
    if (!winner) return reply.code(404).send({ error: "winner not found" });
    const wish = await store.getWish(pool, winner.wish_id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    // Same guards as retry-with-deps: only open/needs_input wishes
    // with no active run qualify, so a retry can never resurrect a
    // shipped/rejected wish or duplicate an in-flight run.
    if (wish.state !== "open" && wish.state !== "needs_input") {
      return reply.code(409).send({ error: `wish is ${wish.state}, cannot retry` });
    }
    const active = await pool.query(
      `SELECT COUNT(*)::text AS n FROM runs
       WHERE winner_id = $1 AND state IN ('queued','running','verifying')`,
      [winner.id],
    );
    if (Number(active.rows[0].n) > 0) {
      return reply.code(409).send({ error: "winner already has an active run" });
    }
    // The override is maintainer-attested, recorded on the run record
    // (allow_churn), and audited here. It downgrades ONLY the
    // churn-size heuristic to flagged for the retry run; the backdoor
    // shape (unrelated file + new outbound host) still blocks, and
    // the PR body notes the override. Non-maintainers never reach
    // this point: requireMaintainer above refuses them.
    const retry = await store.createRun(
      pool,
      winner.id,
      run.backend,
      run.allow_dependencies,
      run.id,
      true,
    );
    await store.createJob(pool, retry.id, repo.id);
    await audit(pool, String(user.id), "run_retried_with_churn_override", "run", retry.id, null, {
      previousRunId: run.id,
    });
    return { run: retry };
  });

  app.post("/api/runs/:id/pr-decision", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    const run = await store.getRun(pool, (req.params as { id: string }).id);
    if (!run) return reply.code(404).send({ error: "run not found" });
    const pr = await store.getPrByRun(pool, run.id);
    if (!pr) return reply.code(404).send({ error: "no PR for this run" });
    const winner = await store.getWinner(pool, run.winner_id);
    if (!winner) return reply.code(404).send({ error: "winner not found" });
    const wish = await store.getWish(pool, winner.wish_id);
    if (!wish) return reply.code(404).send({ error: "wish not found" });
    const repo = await store.getRepo(pool, wish.repo_id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    if (!(await requireMaintainer(deps, repo, user, reply))) return;
    // Terminal-state guard: the old code let merged → rejected flip a
    // shipped wish to rejected and close the PR, both 200. Shipped and
    // merged are terminal; no further transition is accepted.
    if (wish.state === "shipped" || pr.state === "merged") {
      return reply.code(409).send({ error: "PR is already merged; decision is terminal" });
    }
    const outcome = asString(bodyOf(req).outcome);
    const reason = asString(bodyOf(req).reason);
    if (outcome === "merged") {
      await store.setWishState(pool, wish.id, "shipped");
      await store.setPrState(pool, pr.id, "merged");
      await audit(pool, String(user.id), "pr_merged", "wish", wish.id, null, { prNumber: pr.number });
      // One optional comment on a linked issue, best effort, no chatter.
      // The linked issue's repo must match this board's repo: a wish
      // linking another repo's issue must never comment there.
      const issueMatch = wish.linked_issue_url?.match(
        /^https:\/\/github\.com\/([^/]+\/[^/]+)\/issues\/(\d+)/,
      );
      if (issueMatch && issueMatch[1] === repo.full_name) {
        await github
          .commentOnIssue(repo.installation_id, repo.full_name, Number(issueMatch[2]),
            `Shipped via WishShip PR #${pr.number}: ${pr.url}`)
          .catch(() => undefined);
      }
      return { wish: { ...wish, state: "shipped" as const } };
    }
    if (outcome === "rejected" || outcome === "rework") {
      await store.setWishState(pool, wish.id, outcome === "rejected" ? "rejected" : "open");
      await store.setPrState(pool, pr.id, "closed");
      await audit(pool, String(user.id), outcome === "rejected" ? "pr_rejected" : "pr_rework", "wish", wish.id, null, { reason, prNumber: pr.number });
      // The service deletes the branch it created (kill-switch hygiene).
      await github.deleteBranch(repo.installation_id, repo.full_name, pr.branch).catch(() => undefined);
      return { wish: { ...wish, state: outcome === "rejected" ? ("rejected" as const) : ("open" as const) } };
    }
    return reply.code(400).send({ error: "outcome must be merged, rejected, or rework" });
  });

  // ---------- audit / export / operator ----------
  app.get("/api/repos/:id/audit", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    return { events: await store.listAudit(pool, repo.id) };
  });

  app.get("/api/repos/:id/export", async (req, reply) => {
    const repo = await store.getRepo(pool, (req.params as { id: string }).id);
    if (!repo) return reply.code(404).send({ error: "repo not found" });
    const wishes = await store.listWishes(pool, repo.id);
    const votes = [];
    for (const w of wishes) votes.push(...(await store.listVotes(pool, w.id)));
    const runs = await store.listRunsForRepo(pool, repo.id);
    return { repo, wishes, votes, runs, exportedAt: new Date().toISOString() };
  });

  app.get("/api/operator", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    if (!isOperator(deps, user.login)) {
      // Fallback: any maintainer of any repo may view the operator page.
      const repos = await store.listRepos(pool);
      let maintainerAnywhere = false;
      for (const r of repos) {
        try {
          if (await github.isMaintainer(r.installation_id, r.full_name, user.login)) {
            maintainerAnywhere = true;
            break;
          }
        } catch {
          // ignore
        }
      }
      if (!maintainerAnywhere) return reply.code(403).send({ error: "operator only" });
    }
    const queue = await store.listQueuedJobs(pool);
    const spendRows = await pool.query(
      `SELECT c.repo_id, COALESCE(SUM(r.cost_usd), 0)::text AS spend,
         COUNT(*)::text AS runs FROM runs r
       JOIN cycle_winners cw ON cw.id = r.winner_id
       JOIN cycles c ON c.id = cw.cycle_id
       WHERE r.created_at >= date_trunc('month', now())
       GROUP BY c.repo_id`,
    );
    return {
      globalPaused: deps.operator.globalPaused,
      queue,
      monthlySpend: spendRows.rows,
    };
  });

  app.post("/api/operator/global-pause", async (req, reply) => {
    const user = requireAuth(req, reply, config);
    if (!user) return;
    if (!isOperator(deps, user.login)) {
      return reply.code(403).send({ error: "operator only" });
    }
    deps.operator.globalPaused = bodyOf(req).paused === true;
    await audit(pool, String(user.id), deps.operator.globalPaused ? "global_paused" : "global_resumed", "system", "global", null, {});
    return { globalPaused: deps.operator.globalPaused };
  });
}

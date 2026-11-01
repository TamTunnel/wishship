import type { Pool } from "pg";
import type { GitHubClient } from "./github";
import { queryOne } from "./db";
import type { Repo, User } from "./store";

export interface Eligibility {
  eligible: boolean;
  reason: string | null;
}

function accountAgeDays(user: User): number {
  return (Date.now() - user.account_created_at.getTime()) / (24 * 60 * 60 * 1000);
}

/**
 * Eligibility decision for one vote attempt. Every decision — eligible
 * or refused with reason — is recorded by the caller as an audit event
 * so a maintainer can see who was turned away and why.
 */
export async function checkEligibility(
  github: GitHubClient,
  repo: Repo,
  user: User,
): Promise<Eligibility> {
  const cfg = repo.config;
  if (accountAgeDays(user) < cfg.ageFloorDays) {
    return {
      eligible: false,
      reason: `account is younger than the ${cfg.ageFloorDays}-day age floor`,
    };
  }
  switch (cfg.eligibilityMode) {
    case "any":
      return { eligible: true, reason: null };
    case "allowlist":
      if (cfg.allowlist.some((l) => l.toLowerCase() === user.login.toLowerCase())) {
        return { eligible: true, reason: null };
      }
      return { eligible: false, reason: "not on the repo's voter allowlist" };
    case "stargazers": {
      const ok = await github.hasStarred(repo.installation_id, repo.full_name, user.login);
      return ok
        ? { eligible: true, reason: null }
        : { eligible: false, reason: "only stargazers may vote on this board" };
    }
    case "contributors": {
      const ok = await github.hasContributed(repo.installation_id, repo.full_name, user.login);
      return ok
        ? { eligible: true, reason: null }
        : { eligible: false, reason: "only prior contributors may vote on this board" };
    }
    default:
      return { eligible: true, reason: null };
  }
}

/** DB-backed rate limits (real counts, not in-memory guesses). */
export async function wishesToday(pool: Pool, repoId: string, authorId: number): Promise<number> {
  const row = await queryOne<{ n: string }>(
    pool,
    `SELECT COUNT(*)::text AS n FROM wishes
     WHERE repo_id = $1 AND author_id = $2 AND created_at >= date_trunc('day', now())`,
    [repoId, authorId],
  );
  return Number(row?.n ?? 0);
}

export async function votesInLastHour(
  pool: Pool,
  voterId: number,
): Promise<number> {
  const row = await queryOne<{ n: string }>(
    pool,
    `SELECT COUNT(*)::text AS n FROM votes
     WHERE voter_id = $1 AND created_at >= now() - interval '1 hour'
       AND withdrawn_at IS NULL`,
    [voterId],
  );
  return Number(row?.n ?? 0);
}

export async function votesToday(pool: Pool, voterId: number): Promise<number> {
  const row = await queryOne<{ n: string }>(
    pool,
    `SELECT COUNT(*)::text AS n FROM votes
     WHERE voter_id = $1 AND created_at >= date_trunc('day', now())
       AND withdrawn_at IS NULL`,
    [voterId],
  );
  return Number(row?.n ?? 0);
}

export const LIMITS = {
  wishesPerUserPerRepoPerDay: 5,
  votesPerUserPerHour: 20,
  votesPerUserPerDay: 100,
};

import type { Pool } from "pg";
import * as store from "./store";
import type { Cycle, CycleWinner, Repo, Wish } from "./store";
import { audit } from "./store";
import type { Db } from "./db";

export interface RankingEntry {
  wish: Wish;
  votes: number;
}

export async function rankOpenWishes(
  pool: Db,
  repoId: string,
): Promise<RankingEntry[]> {
  const wishes = await store.listWishes(pool, repoId, "open");
  const counts = await store.voteCounts(
    pool,
    wishes.map((w) => w.id),
  );
  return wishes
    .map((wish) => ({ wish, votes: counts.get(wish.id) ?? 0 }))
    .sort(
      (a, b) =>
        b.votes - a.votes ||
        a.wish.created_at.getTime() - b.wish.created_at.getTime(),
    );
}

interface CycleVote {
  voter_id: number;
  created_at: Date;
  account_created_at: Date;
}

export interface AnomalyDetails {
  windowVotes: number;
  totalVotes: number;
  share: number;
  accountSpanDays: number;
  windowStart: string;
}

/**
 * Burst/anomaly flagging (§2): if more than 50% of a cycle's votes
 * arrive within a 1-hour window from accounts created within 30 days of
 * each other, the cycle is flagged anomaly_suspected. The flag is a
 * warning to the human on the approval screen, never an automatic block.
 */
export async function detectAnomaly(
  pool: Db,
  repoId: string,
  openedAt: Date,
): Promise<AnomalyDetails | null> {
  const rows = await pool.query(
    `SELECT v.voter_id, v.created_at, u.account_created_at FROM votes v
     JOIN wishes w ON w.id = v.wish_id
     JOIN users u ON u.id = v.voter_id
     WHERE w.repo_id = $1 AND v.created_at >= $2 AND v.withdrawn_at IS NULL
     ORDER BY v.created_at ASC`,
    [repoId, openedAt],
  );
  const votes = rows.rows as CycleVote[];
  const total = votes.length;
  if (total < 4) return null;
  const hourMs = 60 * 60 * 1000;
  let best: { start: number; window: CycleVote[] } | null = null;
  for (let i = 0; i < votes.length; i++) {
    const start = new Date(votes[i].created_at).getTime();
    const window = votes.filter(
      (v) => {
        const t = new Date(v.created_at).getTime();
        return t >= start && t < start + hourMs;
      },
    );
    if (!best || window.length > best.window.length) best = { start, window };
  }
  if (!best) return null;
  const share = best.window.length / total;
  if (share <= 0.5) return null;
  const createdTimes = best.window.map((v) => new Date(v.account_created_at).getTime());
  const spanDays =
    (Math.max(...createdTimes) - Math.min(...createdTimes)) / (24 * 60 * 60 * 1000);
  if (spanDays > 30) return null;
  return {
    windowVotes: best.window.length,
    totalVotes: total,
    share: Math.round(share * 100) / 100,
    accountSpanDays: Math.round(spanDays * 10) / 10,
    windowStart: new Date(best.start).toISOString(),
  };
}

export interface CloseResult {
  cycle: Cycle;
  winner: CycleWinner | null;
  ranking: RankingEntry[];
  anomaly: AnomalyDetails | null;
}

/**
 * Close the open cycle, rank from the ledger, and propose the winner.
 * No winner below threshold: the cycle still closes (a new one opens)
 * and nothing is proposed. Nothing runs at this stage — the maintainer
 * approval gate comes next, and it is non-negotiable.
 *
 * The whole close-and-propose runs in ONE transaction with a
 * conditional close: a concurrent close of the same cycle fails
 * (rowcount 0 → "cycle already closed") instead of double-closing,
 * and the unique index on (cycle_id, wish_id) backstops the propose.
 */
export async function closeCycleAndPropose(
  pool: Pool,
  repo: Repo,
  actorId: string,
): Promise<CloseResult> {
  if (repo.paused) throw new Error("repo cycles are paused");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const cycle = await store.getOpenCycle(client, repo.id);
    if (!cycle) throw new Error("no open cycle for this repo");
    const ranking = await rankOpenWishes(client, repo.id);
    const anomaly = await detectAnomaly(client, repo.id, cycle.opened_at);
    const closed = await store.closeCycle(client, cycle.id, anomaly !== null, anomaly);
    if (!closed) throw new Error("cycle already closed");
    const newCycle = await store.openCycle(client, repo.id);
    void newCycle;
    const top = ranking[0];
    let winner: CycleWinner | null = null;
    if (top && top.votes >= repo.config.minVotes) {
      winner = await store.createWinner(client, cycle.id, top.wish.id);
      await store.setWishState(client, top.wish.id, "proposed");
      await audit(client, actorId, "cycle_winner_proposed", "wish", top.wish.id, null, {
        cycleId: cycle.id,
        votes: top.votes,
        anomaly,
      });
    }
    await audit(client, actorId, "cycle_closed", "cycle", cycle.id, null, {
      winnerId: winner?.id ?? null,
      anomaly,
    });
    await client.query("COMMIT");
    return { cycle: { ...cycle, closed_at: new Date() }, winner, ranking, anomaly };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Maintainer-pick bypass (§8): any open wish can go straight to the
 * approval stage regardless of votes. Audited like any other approval
 * path — a maintainer who bypasses constantly is visible on the board.
 */
export async function maintainerPick(
  pool: Pool,
  repo: Repo,
  wishId: string,
  actorId: string,
): Promise<CycleWinner> {
  // Locked transaction: two concurrent picks of the same wish must not
  // both succeed — the wish row lock serializes them, and the second
  // sees `proposed` and fails.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const locked = await client.query(
      `SELECT * FROM wishes WHERE id = $1 FOR UPDATE`,
      [wishId],
    );
    const wish = locked.rows[0] as Wish | undefined;
    if (!wish || wish.repo_id !== repo.id) throw new Error("wish not found on this repo");
    if (wish.state !== "open") throw new Error("only open wishes can be picked");
    let cycle = await store.getOpenCycle(client, repo.id);
    if (!cycle) cycle = await store.openCycle(client, repo.id);
    const winner = await store.createWinner(client, cycle.id, wishId);
    await store.setWishState(client, wishId, "proposed");
    await audit(client, actorId, "winner_picked_by_maintainer", "wish", wishId, null, {
      cycleId: cycle.id,
    });
    await client.query("COMMIT");
    return winner;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

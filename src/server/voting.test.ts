import assert from "node:assert/strict";
import { describe, test } from "node:test";
import * as store from "./store";
import {
  api,
  buildTestApp,
  makeRepo,
  makeUser,
} from "./testutil";

describe("voting integrity (probes 1-5, 17)", () => {
  test("probe 1: fresh accounts below the age floor cannot vote", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-a");
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    const young = await makeUser(t.pool, { login: "fresh-account", ageDays: 5 });
    t.github.seedRepo(repo.full_name);
    t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Dark mode", "A theme toggle", null, false, []);
    const res = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: young });
    assert.equal(res.status, 403);
    assert.match(String(res.body.error), /age floor/);
    assert.equal(await store.voteCount(t.pool, wish.id), 0);
    const events = await store.listAudit(t.pool, repo.id);
    assert.ok(events.some((e) => e.action === "vote_refused_eligibility"));
  });

  test("probe 2: double vote refused, including concurrent votes; count stays 1", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-b");
    const author = await makeUser(t.pool, { login: "dev-alex" });
    const voter = await makeUser(t.pool, { login: "priya-dev" });
    const wish = await store.createWish(t.pool, repo.id, author.id, "Dark mode", "body", null, false, []);
    // Two concurrent votes from the same account: exactly one wins.
    const [a, b] = await Promise.all([
      api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter }),
      api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter }),
    ]);
    assert.deepEqual([a.status, b.status].sort(), [200, 409]);
    // A third, sequential vote is also refused; count is exactly 1.
    const third = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter });
    assert.equal(third.status, 409);
    assert.equal(await store.voteCount(t.pool, wish.id), 1);
  });

  test("probe 3: vote attribution comes from the session, never the request body", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-c");
    const author = await makeUser(t.pool, { login: "dev-alex" });
    const attacker = await makeUser(t.pool, { login: "mallory" });
    const victim = await makeUser(t.pool, { login: "victim-user" });
    const wish = await store.createWish(t.pool, repo.id, author.id, "Dark mode", "body", null, false, []);
    const res = await api(t, "POST", `/api/wishes/${wish.id}/vote`, {
      user: attacker,
      payload: { voterId: victim.id, voter_id: victim.id, user: victim.login },
    });
    assert.equal(res.status, 200);
    const votes = await store.listVotes(t.pool, wish.id);
    assert.equal(votes.length, 1);
    assert.equal(Number(votes[0].voter_id), attacker.id);
    assert.notEqual(Number(votes[0].voter_id), victim.id);
  });

  test("probe 4: votes after cycle close are refused; withdrawal too", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-d", { minVotes: 1 });
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    const voter = await makeUser(t.pool, { login: "sam-codes" });
    const late = await makeUser(t.pool, { login: "late-voter" });
    t.github.seedRepo(repo.full_name);
    t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Dark mode", "body", null, false, []);
    await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter });
    await store.openCycle(t.pool, repo.id);
    const closed = await api(t, "POST", `/api/repos/${repo.id}/cycles/close`, { user: maintainer });
    assert.equal(closed.status, 200);
    const afterClose = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: late });
    assert.equal(afterClose.status, 409);
    const unvote = await api(t, "POST", `/api/wishes/${wish.id}/unvote`, { user: voter });
    assert.equal(unvote.status, 409);
    assert.equal(await store.voteCount(t.pool, wish.id), 1);
  });

  test("probe 5: counts derive from the ledger; withdrawal drops the count; no count endpoint exists", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-e");
    const author = await makeUser(t.pool, { login: "dev-alex" });
    const v1 = await makeUser(t.pool, { login: "v-one" });
    const v2 = await makeUser(t.pool, { login: "v-two" });
    const wish = await store.createWish(t.pool, repo.id, author.id, "Dark mode", "body", null, false, []);
    await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: v1 });
    await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: v2 });
    assert.equal(await store.voteCount(t.pool, wish.id), 2);
    await api(t, "POST", `/api/wishes/${wish.id}/unvote`, { user: v1 });
    assert.equal(await store.voteCount(t.pool, wish.id), 1);
    // No endpoint mutates a count: attempts hit 404 and change nothing.
    const tamper = await api(t, "PUT", `/api/wishes/${wish.id}`, {
      user: author,
      payload: { voteCount: 9999, votes: 9999 },
    });
    assert.equal(tamper.status, 404);
    assert.equal(await store.voteCount(t.pool, wish.id), 1);
  });

  test("eligibility modes: stargazers and allowlist refuse strangers, admit members", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-f", { eligibilityMode: "stargazers" });
    const author = await makeUser(t.pool, { login: "dev-alex" });
    const stranger = await makeUser(t.pool, { login: "stranger" });
    const fan = await makeUser(t.pool, { login: "fan-user" });
    t.github.seedRepo(repo.full_name);
    t.github.stargazers.get(repo.full_name)!.add(fan.login);
    const wish = await store.createWish(t.pool, repo.id, author.id, "Dark mode", "body", null, false, []);
    const denied = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: stranger });
    assert.equal(denied.status, 403);
    const allowed = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: fan });
    assert.equal(allowed.status, 200);

    const repo2 = await makeRepo(t.pool, "acme/board-f2", {
      eligibilityMode: "allowlist",
      allowlist: ["fan-user"],
    });
    const wish2 = await store.createWish(t.pool, repo2.id, author.id, "Dark mode", "body", null, false, []);
    const denied2 = await api(t, "POST", `/api/wishes/${wish2.id}/vote`, { user: stranger });
    assert.equal(denied2.status, 403);
    const allowed2 = await api(t, "POST", `/api/wishes/${wish2.id}/vote`, { user: fan });
    assert.equal(allowed2.status, 200);
  });

  test("ranking: votes desc, ties by earliest submission; below-threshold proposes nothing", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-g", { minVotes: 2 });
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    t.github.seedRepo(repo.full_name);
    t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
    const wOld = await store.createWish(t.pool, repo.id, maintainer.id, "Old wish", "body", null, false, []);
    const wNew = await store.createWish(t.pool, repo.id, maintainer.id, "New wish", "body", null, false, []);
    const v1 = await makeUser(t.pool, { login: "v-one" });
    const v2 = await makeUser(t.pool, { login: "v-two" });
    // Tie at 1 vote each: earliest submission (wOld) must win ranking.
    await api(t, "POST", `/api/wishes/${wOld.id}/vote`, { user: v1 });
    await api(t, "POST", `/api/wishes/${wNew.id}/vote`, { user: v2 });
    await store.openCycle(t.pool, repo.id);
    const closed = await api(t, "POST", `/api/repos/${repo.id}/cycles/close`, { user: maintainer });
    assert.equal(closed.status, 200);
    // Below the threshold of 2: no winner proposed.
    assert.equal(closed.body.winner, null);
    const ranking = closed.body.ranking as { wish: { id: string }; votes: number }[];
    assert.equal(ranking[0].wish.id, wOld.id);
    assert.equal(ranking[0].votes, 1);
  });

  test("anomaly flag: burst votes from similarly-aged accounts flag the cycle", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-h", { minVotes: 1 });
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    t.github.seedRepo(repo.full_name);
    t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
    await store.openCycle(t.pool, repo.id);
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Viral wish", "body", null, false, []);
    // Four voters, all accounts created ~40 days ago (within 30 days of
    // each other), all voting within the same hour: a textbook burst.
    for (let i = 0; i < 4; i++) {
      const voter = await makeUser(t.pool, { login: `burst-${i}`, ageDays: 40 + i });
      const res = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter });
      assert.equal(res.status, 200);
    }
    const closed = await api(t, "POST", `/api/repos/${repo.id}/cycles/close`, { user: maintainer });
    assert.equal(closed.status, 200);
    assert.equal(closed.body.anomaly.windowVotes, 4);
    assert.equal(closed.body.anomaly.totalVotes, 4);
    assert.equal(closed.body.anomaly.share, 1);
    // The flag warns, it does not block: a winner is still proposed.
    assert.ok(closed.body.winner);
  });

  test("probe 17: wish submission flood hits the per-day limit", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-i");
    const spammer = await makeUser(t.pool, { login: "spammer" });
    for (let i = 0; i < 5; i++) {
      const res = await api(t, "POST", `/api/repos/${repo.id}/wishes`, {
        user: spammer,
        payload: { title: `Spam ${i}`, body: "spam" },
      });
      assert.equal(res.status, 201);
    }
    const sixth = await api(t, "POST", `/api/repos/${repo.id}/wishes`, {
      user: spammer,
      payload: { title: "Spam 5", body: "spam" },
    });
    assert.equal(sixth.status, 429);
  });

  test("maintainer-pick bypass proposes without votes; rejection returns wish to open, no auto-advance", async () => {
    const t = await buildTestApp(undefined);
    const repo = await makeRepo(t.pool, "acme/board-j", { minVotes: 10 });
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    t.github.seedRepo(repo.full_name);
    t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Quiet wish", "body", null, false, []);
    const picked = await api(t, "POST", `/api/repos/${repo.id}/pick`, {
      user: maintainer,
      payload: { wishId: wish.id },
    });
    assert.equal(picked.status, 200);
    const winnerId = picked.body.winner.id as string;
    const rejected = await api(t, "POST", `/api/winners/${winnerId}/reject`, {
      user: maintainer,
      payload: { reason: "not now" },
    });
    assert.equal(rejected.status, 200);
    const after = await store.getWish(t.pool, wish.id);
    assert.equal(after?.state, "open");
    const pending = await api(t, "GET", `/api/repos/${repo.id}/pending`, { user: maintainer });
    assert.equal(pending.body.pending, null);
  });
});

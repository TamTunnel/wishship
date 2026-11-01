import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { describe, test } from "node:test";
import { promisify } from "node:util";
import { createRunForWinner, openPrForRun } from "./runner";
import { createWorktree, deleteWorktree } from "./worktree";
import {
  drivePipeline,
  GOOD_BACKEND,
} from "./pipeline-test-helper";
import {
  api,
  buildTestApp,
  makeFixtureRepo,
  makeRepo,
  makeUser,
} from "./testutil";
import * as store from "./store";

const execFileAsync = promisify(execFile);

const FULL_FIXTURE = {
  "package.json": JSON.stringify({
    name: "fixture",
    scripts: {
      test: "node theme.test.js",
      lint: "node -e \"process.exit(0)\"",
      typecheck: "node -e \"process.exit(0)\"",
    },
  }),
};

describe("pipeline gates (probes 12, 13, 16, 18) and the happy path", () => {
  test("probe 13: run creation requires an approved winner", async () => {
    const t = await buildTestApp(GOOD_BACKEND);
    const repo = await makeRepo(t.pool, "acme/pipe-a");
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Dark mode", "body", null, false, []);
    await store.openCycle(t.pool, repo.id);
    const cycle = await store.getOpenCycle(t.pool, repo.id);
    const pending = await store.createWinner(t.pool, cycle!.id, wish.id);
    // Pending: refused.
    await assert.rejects(
      createRunForWinner(t.pool, pending.id, "script", false, String(maintainer.id)),
      /not been approved/,
    );
    // Rejected: refused.
    await store.decideWinner(t.pool, pending.id, "rejected", maintainer.id, "no");
    await assert.rejects(
      createRunForWinner(t.pool, pending.id, "script", false, String(maintainer.id)),
      /not been approved/,
    );
    // Approved: succeeds and queues a job. (A second winner for the
    // same wish in the same cycle is refused by the unique index, so
    // the approved case uses a second wish.)
    const wish2 = await store.createWish(t.pool, repo.id, maintainer.id, "Dark mode 2", "body", null, false, []);
    const pending2 = await store.createWinner(t.pool, cycle!.id, wish2.id);
    await store.decideWinner(t.pool, pending2.id, "approved", maintainer.id, null);
    const run = await createRunForWinner(t.pool, pending2.id, "script", false, String(maintainer.id));
    assert.equal(run.state, "queued");
    const jobs = await store.listQueuedJobs(t.pool);
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].run_id, run.id);
  });

  test("probe 12: PR opening refuses BLOCKED reports at the service layer", async () => {
    const t = await buildTestApp(GOOD_BACKEND);
    const repo = await makeRepo(t.pool, "acme/pipe-b");
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
    const wish = await store.createWish(t.pool, repo.id, maintainer.id, "Dark mode", "body", null, false, []);
    const cycle = await store.openCycle(t.pool, repo.id);
    const winner = await store.createWinner(t.pool, cycle.id, wish.id);
    await store.decideWinner(t.pool, winner.id, "approved", maintainer.id, null);
    const run = await store.createRun(t.pool, winner.id, "script", false);
    await store.createReport(t.pool, run.id, "BLOCKED", [
      { name: "secret_scan", status: "failed", detail: "secret-shaped material found: stripe-secret" },
    ]);
    const deps = {
      pool: t.pool,
      config: t.config,
      github: t.github,
      backends: {},
      resolveRepo: async () => ({ dir: "", cleanup: async () => undefined }),
      isGloballyPaused: () => false,
    };
    await assert.rejects(
      openPrForRun(deps as never, run, "diff", "abc123", "main"),
      /refusing to open a PR for a BLOCKED report/,
    );
    assert.equal(t.github.openedPrs.length, 0);
    assert.equal(t.github.pushedBranches.length, 0);
    // Positive control: a VERIFIED report for the same run opens.
    await t.pool.query(`DELETE FROM verification_reports WHERE run_id = $1`, [run.id]);
    await store.createReport(t.pool, run.id, "VERIFIED", [
      { name: "tests", status: "passed", detail: "ok" },
    ]);
    const pr = await openPrForRun(deps as never, run, "diff", "abc123", "main");
    assert.equal(pr.number, 42);
    assert.equal(t.github.openedPrs.length, 1);
  });

  test("probe 18: agent worktrees carry no remote; no token in PR body or records", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const wt = await createWorktree(fixture.dir, "HEAD", "/tmp");
    try {
      const remotes = await execFileAsync("git", ["remote", "-v"], { cwd: wt.dir }).then(
        (r) => (r.stdout as string).trim(),
      );
      assert.equal(remotes, "");
    } finally {
      await deleteWorktree(wt.dir);
    }
    const t = await buildTestApp(GOOD_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/pipe-c",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode for the task board",
      wishBody: "Add a theme toggle persisted per user.",
    });
    assert.equal(out.run.state, "pr_opened");
    const body = t.github.openedPrs[0].body;
    assert.ok(!body.includes("x-access-token"), "token in PR body");
    assert.ok(!/gh[pousr]_[A-Za-z0-9_]{20,}/.test(body), "token-shaped string in PR body");
    const report = out.report!;
    for (const c of report.checks) {
      assert.ok(!(c.output ?? "").includes("x-access-token"), "token in check output");
    }
  });

  test("probe 16 + happy path: appendix loop end to end, merge ships, rejection kills cleanly", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(GOOD_BACKEND);
    // Happy path with a linked issue: merge ships and comments once.
    const out = await drivePipeline(t, {
      fullName: "acme/rocket-tasks",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode for the task board",
      wishBody: "A theme toggle persisted per user.",
    });
    assert.equal(out.run.state, "pr_opened");
    assert.equal(out.report?.tier, "VERIFIED");
    assert.ok(out.pr);
    assert.equal(t.github.openedPrs[0].draft, true);
    assert.match(t.github.openedPrs[0].body, /4 votes/);
    assert.match(t.github.openedPrs[0].body, /Duration:/);

    // Merge decision ships the wish.
    const maintainer = await makeUser(t.pool, { login: "maya-maintainer-2" });
    t.github.maintainers.get("acme/rocket-tasks")!.add("maya-maintainer-2");
    // Link an issue for the comment check.
    await t.pool.query(`UPDATE wishes SET linked_issue_url = $2 WHERE id = $1`, [
      out.wish.id,
      "https://github.com/acme/rocket-tasks/issues/7",
    ]);
    const merged = await api(t, "POST", `/api/runs/${out.run.id}/pr-decision`, {
      user: maintainer,
      payload: { outcome: "merged" },
    });
    assert.equal(merged.status, 200);
    assert.equal(merged.body.wish.state, "shipped");
    assert.equal(t.github.comments.length, 1);
    assert.equal(t.github.comments[0].issueNumber, 7);

    // Second loop, rejected: wish rejected with reason, branch deleted,
    // no automatic re-run, reason audited.
    const out2 = await drivePipeline(t, {
      fullName: "acme/rocket-tasks-2",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode follow-up",
      wishBody: "Persist the toggle to the user profile.",
    });
    const maintainer2 = await makeUser(t.pool, { login: "maya-maintainer-3" });
    t.github.maintainers.get("acme/rocket-tasks-2")!.add("maya-maintainer-3");
    const branch = out2.pr!.branch;
    const rejected = await api(t, "POST", `/api/runs/${out2.run.id}/pr-decision`, {
      user: maintainer2,
      payload: { outcome: "rejected", reason: "not the direction we want" },
    });
    assert.equal(rejected.status, 200);
    assert.equal(rejected.body.wish.state, "rejected");
    assert.ok(t.github.deletedBranches.includes(`acme/rocket-tasks-2:${branch}`));
    assert.deepEqual(await store.listQueuedJobs(t.pool), []);
    const events = await store.listAudit(t.pool, out2.repo.id);
    const rejection = events.find((e) => e.action === "pr_rejected");
    assert.ok(rejection);
    assert.match(JSON.stringify(rejection.after_state), /not the direction we want/);
  });
});

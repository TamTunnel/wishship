import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  BACKDOOR_BACKEND,
  BIG_BACKEND,
  CHURN_BACKEND,
  DEP_BACKEND,
  drivePipeline,
  EMPTY_BACKEND,
  GOOD_BACKEND,
  REVIEW_BACKEND,
  SECRET_BACKEND,
} from "./pipeline-test-helper";
import { buildTestApp, makeFixtureRepo, waitForRun } from "./testutil";
import * as store from "./store";

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

const NO_TEST_FIXTURE = {
  "package.json": JSON.stringify({ name: "fixture-no-tests" }),
};

describe("verification pipeline (probes 8, 9, 10, 15)", () => {
  test("probe 8: secret in diff BLOCKS, no PR is opened", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(SECRET_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-a",
      fixture,
      backend: SECRET_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    // First BLOCKED triggers exactly one retry, then the run is dead.
    assert.equal(out.run.state, "blocked");
    assert.equal(out.report?.tier, "BLOCKED");
    const secret = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(secret?.status, "failed");
    assert.match(secret?.detail ?? "", /stripe-secret/);
    assert.equal(out.pr, null);
    assert.equal(t.github.openedPrs.length, 0);
    // Exactly two runs exist for the winner: original + one retry.
    const runs = await t.pool.query(
      `SELECT COUNT(*)::text AS n FROM runs WHERE winner_id = $1`,
      [out.winnerId],
    );
    assert.equal(runs.rows[0].n, "2");
  });

  test("probe 9: dependency smuggling BLOCKS by default, exact diff shown", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(DEP_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-b",
      fixture,
      backend: DEP_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const deps = out.report?.checks.find((c) => c.name === "dependencies");
    assert.equal(deps?.status, "failed");
    assert.match(deps?.detail ?? "", /evil-pkg/);
    assert.equal(t.github.openedPrs.length, 0);
  });

  test("probe 10: backdoor pattern flags the network call and the review notes it; PR body highlights it", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(BACKDOOR_BACKEND, {}, REVIEW_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-c",
      fixture,
      backend: BACKDOOR_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    assert.ok(out.pr);
    const net = out.report?.checks.find((c) => c.name === "network_calls");
    assert.equal(net?.status, "flagged");
    assert.match(net?.detail ?? "", /evil\.example/);
    const review = out.report?.checks.find((c) => c.name === "second_model_review");
    assert.equal(review?.status, "flagged");
    assert.match(review?.detail ?? "", /evil\.example/);
    const prBody = t.github.openedPrs[0].body;
    assert.match(prBody, /evil\.example/);
    assert.match(prBody, /Flags for the reviewer/);
  });

  test("tiers: no-test-suite repo gets PARTIAL with the no-test-suite label, not blocked", async () => {
    const fixture = await makeFixtureRepo(NO_TEST_FIXTURE);
    const t = await buildTestApp(GOOD_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-d",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    assert.equal(out.report?.tier, "PARTIAL");
    const tests = out.report?.checks.find((c) => c.name === "tests");
    assert.equal(tests?.status, "skipped");
    assert.match(tests?.detail ?? "", /no-test-suite/);
    assert.ok(out.pr);
    assert.deepEqual(t.github.prLabels, [
      { fullName: "acme/ver-d", prNumber: out.pr!.number, labels: ["no-test-suite"] },
    ]);
    assert.match(t.github.openedPrs[0].body, /PARTIAL/);
  });

  test("tiers: full fixture with all checks passing gets VERIFIED", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(GOOD_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-e",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode for the task board",
      wishBody: "Add a theme toggle persisted per user.",
    });
    assert.equal(out.run.state, "pr_opened");
    assert.equal(out.report?.tier, "VERIFIED");
    assert.ok(out.pr);
    const body = t.github.openedPrs[0].body;
    assert.match(body, /generated by an agent/i);
    assert.match(body, /\$1\.84/);
    assert.equal(t.github.openedPrs[0].draft, true);
  });

  test("diff-size limit BLOCKS over-limit diffs, never trims them", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(BIG_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-f",
      fixture,
      backend: BIG_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const size = out.report?.checks.find((c) => c.name === "diff_size");
    assert.equal(size?.status, "failed");
    assert.match(size?.detail ?? "", /600 added lines/);
    assert.equal(t.github.openedPrs.length, 0);
  });

  test("churn: majority-unrelated diff across two files BLOCKS", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(CHURN_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-g",
      fixture,
      backend: CHURN_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const churn = out.report?.checks.find((c) => c.name === "churn");
    assert.equal(churn?.status, "failed");
    assert.match(churn?.detail ?? "", /unrelated-a\.js/);
    assert.equal(t.github.openedPrs.length, 0);
  });

  test("empty diff never becomes a PR: run fails, wish returns to open", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(EMPTY_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-h",
      fixture,
      backend: EMPTY_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "failed");
    assert.match(out.run.failure_reason ?? "", /no changes produced/);
    assert.equal(t.github.openedPrs.length, 0);
    const wish = await store.getWish(t.pool, out.wish.id);
    assert.equal(wish?.state, "open");
  });

  test("probe 15: two consecutive BLOCKED verifications yield exactly one retry, then dead", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(SECRET_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/ver-i",
      fixture,
      backend: SECRET_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    // The first run is already blocked; wait for its retry to terminate.
    const retryRow = await t.pool.query(
      `SELECT id FROM runs WHERE retry_of = $1`,
      [out.run.id],
    );
    assert.equal(retryRow.rows.length, 1);
    await waitForRun(t, retryRow.rows[0].id as string);
    const runs = await t.pool.query(
      `SELECT id, state, retry_of FROM runs WHERE winner_id = $1 ORDER BY created_at ASC`,
      [out.winnerId],
    );
    assert.equal(runs.rows.length, 2);
    assert.equal(runs.rows[0].state, "blocked");
    assert.equal(runs.rows[1].state, "blocked");
    assert.equal(runs.rows[1].retry_of, runs.rows[0].id);
    assert.equal(t.github.openedPrs.length, 0);
  });
});

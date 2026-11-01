import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { describe, test } from "node:test";
import {
  COSTLY_BACKEND,
  drivePipeline,
  ENV_BACKEND,
  GOOD_BACKEND,
  NEEDS_INPUT_BACKEND,
  OUTSIDE_PLUS_BACKEND,
  PIPEHOLD_BACKEND,
  SLEEP_BACKEND,
} from "./pipeline-test-helper";
import { buildTestApp, makeFixtureRepo } from "./testutil";
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

describe("agent sandbox and bounds (probes 11, 14)", () => {
  test("probe 11: agent env is scrubbed — no tokens, no service credentials", async () => {
    // Plant secret-shaped values in the test process env; the agent
    // must never see them, even though the backend dumps its whole env.
    const prevGithub = process.env.GITHUB_TOKEN;
    const prevNpm = process.env.NPM_TOKEN;
    const prevDb = process.env.DATABASE_URL;
    process.env.GITHUB_TOKEN = "ghp_testtoken1234567890";
    process.env.NPM_TOKEN = "npm_testtoken1234567890";
    process.env.DATABASE_URL = "postgres://secret:secret@db.internal/secret";
    try {
      const fixture = await makeFixtureRepo(NO_TEST_FIXTURE);
      const t = await buildTestApp(ENV_BACKEND);
      const out = await drivePipeline(t, {
        fullName: "acme/agent-a",
        fixture,
        backend: ENV_BACKEND,
        wishTitle: "Dark mode",
        wishBody: "Add a dark mode toggle.",
      });
      assert.equal(out.run.state, "pr_opened");
      const patch = t.github.pushedBranches[0].patch;
      assert.ok(!patch.includes("ghp_testtoken1234567890"), "GitHub token leaked into diff");
      assert.ok(!patch.includes("npm_testtoken1234567890"), "npm token leaked into diff");
      assert.ok(!patch.includes("db.internal"), "database URL leaked into diff");
      assert.ok(!patch.includes('"GITHUB_TOKEN"'), "GITHUB_TOKEN key leaked");
      assert.ok(!patch.includes('"DATABASE_URL"'), "DATABASE_URL key leaked");
      assert.ok(patch.includes('"WISHSHIP_AGENT": "1"'), "agent marker missing");
      assert.ok(patch.includes(t.config.agentHome), "agent HOME should be the scrubbed agent home");
    } finally {
      if (prevGithub === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = prevGithub;
      if (prevNpm === undefined) delete process.env.NPM_TOKEN;
      else process.env.NPM_TOKEN = prevNpm;
      if (prevDb === undefined) delete process.env.DATABASE_URL;
      else process.env.DATABASE_URL = prevDb;
    }
  });

  test("probe 11: writes outside the worktree are flagged in the report", async () => {
    const fixture = await makeFixtureRepo(NO_TEST_FIXTURE);
    const t = await buildTestApp(OUTSIDE_PLUS_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/agent-b",
      fixture,
      backend: OUTSIDE_PLUS_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    const sandbox = out.report?.checks.find((c) => c.name === "sandbox_writes");
    assert.equal(sandbox?.status, "flagged");
    assert.match(sandbox?.detail ?? "", /outside-write\.txt/);
  });

  test("probe 14: agent timeout kills the run; no PR; no runaway", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(SLEEP_BACKEND, { runTimeoutMs: 3000 });
    const started = Date.now();
    const out = await drivePipeline(t, {
      fullName: "acme/agent-c",
      fixture,
      backend: SLEEP_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "failed");
    assert.match(out.run.failure_reason ?? "", /timed out/);
    assert.equal(t.github.openedPrs.length, 0);
    assert.ok(Date.now() - started < 30000, "timeout run took too long");
  });

  test("probe 14: pipe-holding descendants cannot stall execution", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(PIPEHOLD_BACKEND, { runTimeoutMs: 60000 });
    const started = Date.now();
    const out = await drivePipeline(t, {
      fullName: "acme/agent-d",
      fixture,
      backend: PIPEHOLD_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    // The backend exits immediately (background sleep aside); the run
    // must finish promptly — here as "no changes produced", not a hang.
    assert.equal(out.run.state, "failed");
    assert.match(out.run.failure_reason ?? "", /no changes produced/);
    assert.ok(Date.now() - started < 20000, "pipe-holding descendant stalled execution");
  });

  test("probe 14: per-run cost cap and monthly budget are enforced", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(COSTLY_BACKEND, { runCostCapUsd: 1 });
    const out = await drivePipeline(t, {
      fullName: "acme/agent-e",
      fixture,
      backend: COSTLY_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "failed");
    assert.match(out.run.failure_reason ?? "", /exceeded the per-run cap/);
    assert.equal(t.github.openedPrs.length, 0);

    const t2 = await buildTestApp(GOOD_BACKEND, { repoMonthlyBudgetUsd: 0 });
    const out2 = await drivePipeline(t2, {
      fullName: "acme/agent-f",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out2.run.state, "failed");
    assert.match(out2.run.failure_reason ?? "", /budget exhausted/);
  });

  test("capability failure moves the wish to needs_input, no retry, no PR", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(NEEDS_INPUT_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/agent-g",
      fixture,
      backend: NEEDS_INPUT_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "failed");
    assert.match(out.run.failure_reason ?? "", /needs_input/);
    const wish = await store.getWish(t.pool, out.wish.id);
    assert.equal(wish?.state, "needs_input");
    assert.equal(t.github.openedPrs.length, 0);
    const runs = await t.pool.query(`SELECT COUNT(*)::text AS n FROM runs WHERE winner_id = $1`, [
      out.winnerId,
    ]);
    assert.equal(runs.rows[0].n, "1");
  });

  test("worktree hygiene: no ws-run leftovers after a run", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(GOOD_BACKEND);
    await drivePipeline(t, {
      fullName: "acme/agent-h",
      fixture,
      backend: GOOD_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    const entries = await readdir(t.worktreeRoot);
    assert.deepEqual(entries.filter((e) => e.startsWith("ws-run-")), []);
  });
});

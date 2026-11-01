import assert from "node:assert/strict";
import { mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, test } from "node:test";
import type { AgentBackend, TaskSpec } from "./agent";
import {
  drivePipeline,
  BACKDOOR_BACKEND,
  nodeStdin,
} from "./pipeline-test-helper";
import { scanAddedLines } from "./secretscan";
import * as store from "./store";
import {
  api,
  buildTestApp,
  makeFixtureRepo,
  makeUser,
  waitForRun,
} from "./testutil";
import { detectDependencyChanges, verifyDiff } from "./verify";

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

const MAKEFILE_FIXTURE = {
  Makefile: "test:\n\tnode theme.test.js\n",
  "theme.js": "module.exports={dark:false};\n",
  "theme.test.js": "const t=require('./theme');if(!t.dark)process.exit(1);\n",
};

/** Rewrites the Makefile test recipe to plant a marker, plus the real feature. */
const MAKEFILE_REWRITE_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('plant.js',"require('fs').writeFileSync('marker.txt','pwned');\\n");
  fs.writeFileSync('Makefile','test:\\n\\tnode plant.js\\n');
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Split token: neither half matches any pattern alone. */
const SPLIT_TOKEN_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('split.js','const a = "sk_live_abcd";\\nconst b = "efghijklmnop1234";\\nconst key = a + b;\\n');
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Adds a test script to a manifest that has none, plus the real feature. */
const SCRIPT_ADD_BACKEND = nodeStdin(`
  const fs=require('fs');
  const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
  pkg.scripts.test = 'node theme.test.js';
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

const HELPER_LINES = [
  "// Generic formatting helpers shared by the board UI.",
  "function clampNumber(value, lo, hi) {",
  "  if (value < lo) return lo;",
  "  if (value > hi) return hi;",
  "  return value;",
  "}",
  "function pluralize(count, singular, plural) {",
  "  return count === 1 ? singular : plural;",
  "}",
  "function truncateText(text, max) {",
  "  if (text.length <= max) return text;",
  '  return text.slice(0, max - 1) + "...";',
  "}",
  "function capitalizeWord(word) {",
  "  if (!word) return word;",
  "  return word[0].toUpperCase() + word.slice(1);",
  "}",
  "function slugifyText(text) {",
  '  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");',
  "}",
  "function rangeArray(start, end) {",
  "  const out = [];",
  "  for (let i = start; i < end; i++) out.push(i);",
  "  return out;",
  "}",
  "function sumValues(values) {",
  "  return values.reduce((a, b) => a + b, 0);",
  "}",
  "function averageValues(values) {",
  "  if (values.length === 0) return 0;",
  "  return sumValues(values) / values.length;",
  "}",
  "module.exports = { clampNumber, pluralize, truncateText, capitalizeWord, slugifyText, rangeArray, sumValues, averageValues };",
];

/** 30+ line generic helper with zero wish-token overlap, plus the feature. */
const HELPER_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('utils.js', ${JSON.stringify(HELPER_LINES.join("\n"))});
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

const STUB_BACKEND: AgentBackend = {
  name: "stub",
  run: async () => {
    throw new Error("stub backend never runs");
  },
  review: async () => ({ available: false, concerns: [] }),
};

function baseSpec(baseCommit: string): TaskSpec {
  return {
    version: 1,
    wish: { title: "Dark mode", body: "Add a dark mode toggle.", votes: 4, url: "https://example.invalid" },
    repo: { name: "acme/x", baseCommit, testCommand: "make test", lintCommand: null, typecheckCommand: null },
    constraints: [],
    injectionFlag: false,
    injectionPatterns: [],
    verification: { willRun: ["tests"] },
  };
}

describe("fix round 2: fail-fast verification ordering (judge fix 1)", () => {
  test("Makefile rewrite BLOCKS before any check command runs; marker never planted", async () => {
    const fixture = await makeFixtureRepo(MAKEFILE_FIXTURE);
    const verifyDir = await mkdtemp(join(tmpdir(), "wishship-verify-"));
    try {
      await writeFile(
        join(verifyDir, "Makefile"),
        "test:\n\tnode -e \"require('fs').writeFileSync('marker.txt','pwned')\"\n",
      );
      await writeFile(join(verifyDir, "theme.js"), "module.exports={dark:true};\n");
      await writeFile(
        join(verifyDir, "theme.test.js"),
        "const t=require('./theme');if(!t.dark)process.exit(1);\n",
      );
      const patch = [
        "diff --git a/Makefile b/Makefile",
        "--- a/Makefile",
        "+++ b/Makefile",
        "@@ -1,2 +1,2 @@",
        " test:",
        "-\tnode theme.test.js",
        "+\tnode -e \"require('fs').writeFileSync('marker.txt','pwned')\"",
        "diff --git a/theme.js b/theme.js",
        "--- a/theme.js",
        "+++ b/theme.js",
        "@@ -1 +1 @@",
        "-module.exports={dark:false};",
        "+module.exports={dark:true};",
      ].join("\n");
      const out = await verifyDiff({
        spec: baseSpec(fixture.commit),
        verifyDir,
        agentWorktreeDir: fixture.dir,
        baseCommit: fixture.commit,
        patch,
        filesChanged: ["Makefile", "theme.js"],
        addedLines: 2,
        config: store.DEFAULT_REPO_CONFIG,
        allowDependencies: false,
        backend: STUB_BACKEND,
        baselineHosts: new Set(),
        outsideWrites: [],
        commands: { test: "make test", lint: null, typecheck: null },
      });
      assert.equal(out.tier, "BLOCKED");
      const deps = out.checks.find((c) => c.name === "dependencies");
      assert.equal(deps?.status, "failed");
      assert.match(deps?.detail ?? "", /build file changed: Makefile/);
      const tests = out.checks.find((c) => c.name === "tests");
      assert.equal(tests?.status, "skipped");
      assert.match(tests?.detail ?? "", /not executed/);
      // The recipe never ran: no marker in the verify tree.
      await assert.rejects(stat(join(verifyDir, "marker.txt")));
    } finally {
      await rm(verifyDir, { recursive: true, force: true });
    }
  });

  test("pipeline: Makefile rewrite BLOCKS with 0 PRs", async () => {
    const fixture = await makeFixtureRepo(MAKEFILE_FIXTURE);
    const t = await buildTestApp(MAKEFILE_REWRITE_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-make",
      fixture,
      backend: MAKEFILE_REWRITE_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const deps = out.report?.checks.find((c) => c.name === "dependencies");
    assert.equal(deps?.status, "failed");
    assert.match(deps?.detail ?? "", /build file changed: Makefile/);
    assert.equal(t.github.openedPrs.length, 0);
    assert.equal(out.pr, null);
  });
});

describe("fix round 2: split-token secret scan (judge fix 2)", () => {
  test("variable-concatenated halves are caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_abcd";',
      'const b = "efghijklmnop1234";',
      "const key = a + b;",
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed split token: ${hits.join(",")}`);
  });

  test("literal concatenation and line-wrapped tokens are caught", () => {
    assert.ok(
      scanAddedLines(['const key = "sk_live_" + "abcdefghijklmnop1234";']).includes("stripe-secret"),
    );
    assert.ok(
      scanAddedLines(['const k = "sk_live_abcdefghij', 'klmnop1234";']).includes("stripe-secret"),
    );
  });

  test("template-literal joins are caught", () => {
    assert.ok(
      scanAddedLines([
        'const a = "sk_live_abcd";',
        'const b = "efghijklmnop1234";',
        "const key = `${a}${b}`;",
      ]).includes("stripe-secret"),
    );
  });

  test("no false positive on a JSON env dump (npm-test PATH adjacency)", () => {
    // Regression: concatenating merely adjacent literals fabricated a
    // token here — "1" (WISHSHIP_AGENT) + "PATH" + the PATH value
    // formed an exactly-40-char slash run tripping aws-secret-bare,
    // which blocked the probe-11 env-scrub run under npm test. Only
    // actual join operations are evidence of reconstruction.
    const npmPath =
      "/home/hatch/workspace/wishship/node_modules/.bin:/home/hatch/workspace/node_modules/.bin:/home/hatch/node_modules/.bin:/home/node_modules/.bin:/node_modules/.bin:/opt/hatch-image/bin/npm-package/node_modules/@npmcli/run-script/lib/node-gyp-bin:/opt/hatch/bin:/opt/hatch-image/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/muse/skills/documents/scripts:/opt/muse/skills/generate_podcast/scripts:/opt/muse/skills/style-tryon/scripts";
    const envLine = JSON.stringify({
      HOME: "/tmp/wishship-agent-Ab12Cd",
      TERM: "dumb",
      WISHSHIP_AGENT: "1",
      PATH: npmPath,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PWD: "/tmp/wishship-wt-Xy34Zz/ws-run-98BwWT",
    });
    assert.deepEqual(scanAddedLines([envLine]), []);
  });

  test("honest literals stay clean", () => {
    assert.deepEqual(scanAddedLines(['const theme = "dark";', 'const mode = "toggle";']), []);
  });

  test("pipeline: split-token backend BLOCKS, no VERIFIED PR, neither half ships", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(SPLIT_TOKEN_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-split",
      fixture,
      backend: SPLIT_TOKEN_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const scan = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(scan?.status, "failed");
    assert.match(scan?.detail ?? "", /stripe-secret/);
    assert.equal(t.github.openedPrs.length, 0);
    assert.equal(out.pr, null);
  });
});

describe("fix round 2: script-add exemption (judge fix 3)", () => {
  test("script ADD of a key absent at base is exempt; change/removal/dep-add still block", async () => {
    const fixture = await makeFixtureRepo({
      "package.json": JSON.stringify({
        name: "demo",
        scripts: { test: "node theme.test.js", lint: "node lint.js" },
        dependencies: {},
      }),
    });
    const verifyDir = await mkdtemp(join(tmpdir(), "wishship-verify-"));
    try {
      // Added key (typecheck) + changed key (test) + removed key (lint)
      // + dependency add, all in one manifest.
      await writeFile(
        join(verifyDir, "package.json"),
        JSON.stringify({
          name: "demo",
          scripts: { test: "node other.js", typecheck: "node tc.js" },
          dependencies: { "left-pad": "^1.0.0" },
        }),
      );
      const r = await detectDependencyChanges(fixture.dir, fixture.commit, verifyDir, [
        "package.json",
      ]);
      assert.deepEqual(r.exemptedScripts, ["typecheck (package.json)"]);
      assert.ok(r.violations.some((v) => /script changed: test/.test(v)));
      assert.ok(r.violations.some((v) => /script removed: lint/.test(v)));
      assert.ok(r.violations.some((v) => /dependency added: dependencies:left-pad/.test(v)));
      assert.ok(!r.violations.some((v) => /typecheck/.test(v)));
    } finally {
      await rm(verifyDir, { recursive: true, force: true });
    }
    // Pure script-add: no violations at all.
    const fixture2 = await makeFixtureRepo({
      "package.json": JSON.stringify({ name: "demo", scripts: {} }),
    });
    const verifyDir2 = await mkdtemp(join(tmpdir(), "wishship-verify-"));
    try {
      await writeFile(
        join(verifyDir2, "package.json"),
        JSON.stringify({ name: "demo", scripts: { test: "node theme.test.js" } }),
      );
      const r2 = await detectDependencyChanges(fixture2.dir, fixture2.commit, verifyDir2, [
        "package.json",
      ]);
      assert.deepEqual(r2.violations, []);
      assert.deepEqual(r2.exemptedScripts, ["test (package.json)"]);
    } finally {
      await rm(verifyDir2, { recursive: true, force: true });
    }
  });

  test("pipeline: no-base-test-script repo gains a script and reaches PARTIAL + PR", async () => {
    const fixture = await makeFixtureRepo({
      "package.json": JSON.stringify({ name: "fixture", scripts: {} }),
    });
    const t = await buildTestApp(SCRIPT_ADD_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-scriptadd",
      fixture,
      backend: SCRIPT_ADD_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    assert.equal(out.report?.tier, "PARTIAL");
    const deps = out.report?.checks.find((c) => c.name === "dependencies");
    assert.equal(deps?.status, "passed");
    assert.match(deps?.detail ?? "", /script additions exempted/);
    assert.match(deps?.detail ?? "", /test \(package\.json\)/);
    const tests = out.report?.checks.find((c) => c.name === "tests");
    assert.equal(tests?.status, "skipped");
    assert.ok(out.pr);
    assert.match(t.github.openedPrs[0].body, /script additions exempted/);
  });
});

describe("fix round 2: maintainer churn override (judge fix 4)", () => {
  test("token-free helper BLOCKS first; stranger override refused; maintainer override opens a noted PR", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(HELPER_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-churn",
      fixture,
      backend: HELPER_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const churn = out.report?.checks.find((c) => c.name === "churn");
    assert.equal(churn?.status, "failed");
    assert.match(churn?.detail ?? "", /utils\.js/);
    assert.equal(t.github.openedPrs.length, 0);
    // The automatic retry also blocks; the wish strands in open. The
    // retry run is created by the same worker tick that blocked the
    // first run, so poll until it appears (no flaky direct read).
    let autoRetry: { id: string } | undefined;
    for (let i = 0; i < 50 && !autoRetry; i++) {
      const runs = await store.listRunsForRepo(t.pool, out.repo.id);
      autoRetry = runs.find((r) => r.retry_of === out.run.id);
      if (!autoRetry) await new Promise((r) => setTimeout(r, 200));
    }
    assert.ok(autoRetry, "automatic retry run missing");
    const retryRun = await waitForRun(t, autoRetry.id);
    assert.equal(retryRun.state, "blocked");
    const wishAfter = await store.getWish(t.pool, out.wish.id);
    assert.equal(wishAfter?.state, "open");
    // Stranger (non-maintainer) override: refused.
    const stranger = await makeUser(t.pool, { login: "stranger-9" });
    const refused = await api(t, "POST", `/api/runs/${retryRun.id}/retry-with-churn-override`, {
      user: stranger,
    });
    assert.equal(refused.status, 403);
    // Maintainer override: new run proceeds to a PR that notes it.
    // drivePipeline already registered "maya-maintainer" as a
    // maintainer; the session only needs the login, not the DB row.
    const allowed = await api(t, "POST", `/api/runs/${retryRun.id}/retry-with-churn-override`, {
      user: { id: 424242, login: "maya-maintainer" },
    });
    assert.equal(allowed.status, 200);
    const overrideRunId = (allowed.body.run as { id: string }).id;
    const finalRun = await waitForRun(t, overrideRunId);
    assert.equal(finalRun.state, "pr_opened");
    const record = await store.getRun(t.pool, overrideRunId);
    assert.equal(record?.allow_churn, true);
    assert.equal(t.github.openedPrs.length, 1);
    assert.match(t.github.openedPrs[0].body, /Maintainer override/);
    assert.match(t.github.openedPrs[0].body, /churn override permitted/);
    const auditRows = await t.pool.query(
      `SELECT action FROM audit_events WHERE entity_id = $1`,
      [overrideRunId],
    );
    assert.ok(
      auditRows.rows.some((r: { action: string }) => r.action === "run_retried_with_churn_override"),
      "override audit event missing",
    );
  });

  test("approve-time allowChurn goes straight to a noted PR", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(HELPER_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-churn2",
      fixture,
      backend: HELPER_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
      approveExtras: { allowChurn: true },
    });
    assert.equal(out.run.state, "pr_opened");
    assert.match(t.github.openedPrs[0].body, /Maintainer override/);
  });

  test("churn override does NOT permit the backdoor shape", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(BACKDOOR_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr2-churn3",
      fixture,
      backend: BACKDOOR_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
      approveExtras: { allowChurn: true },
    });
    assert.equal(out.run.state, "blocked");
    const churn = out.report?.checks.find((c) => c.name === "churn");
    assert.equal(churn?.status, "failed");
    assert.match(churn?.detail ?? "", /evil\.js/);
    assert.equal(t.github.openedPrs.length, 0);
  });
});

import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { drivePipeline, nodeStdin } from "./pipeline-test-helper";
import { scanAddedLines } from "./secretscan";
import { buildTestApp, makeFixtureRepo } from "./testutil";

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

const FEATURE = `
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`;

/** Three-way chain: the round-2 scan resolved only pairs, so a+b+c shipped VERIFIED. */
const CHAIN3_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('split.js','const a = "sk_live_ab";\\nconst b = "cdefghij";\\nconst c = "klmnop1234";\\nconst key = a + b + c;\\n');
  ${FEATURE}
`);

/** Literal-array .join(): never resolved in round 2. */
const JOIN_LITERAL_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('split.js','const parts = ["sk_live_abcd", "efghijklmnop1234"];\\nconst key = parts.join("");\\n');
  ${FEATURE}
`);

/** Identifier-array .join(): same hole, inline-array form. */
const JOIN_IDENT_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('split.js','const a = "sk_live_abcd";\\nconst b = "efghijklmnop1234";\\nconst key = [a, b].join("");\\n');
  ${FEATURE}
`);

/** Honest URL building by concatenation: must not newly block. */
const HONEST_CONCAT_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('theme.js','const base = "https://api.example.com";\\nconst url = base + "/v1" + "/users";\\nmodule.exports={dark:true,url};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Token-free helper (churn-blocked without override) for the audit test. */
const HELPER_LINES = [
  "function clampNumber(value, min, max) {",
  "  return Math.min(Math.max(value, min), max);",
  "}",
  "function pluralize(word, count) {",
  "  return count === 1 ? word : word + 's';",
  "}",
  "function truncateText(text, length) {",
  "  return text.length > length ? text.slice(0, length) + '...' : text;",
  "}",
  "function capitalizeWord(word) {",
  "  return word.charAt(0).toUpperCase() + word.slice(1);",
  "}",
  "function slugifyText(text) {",
  "  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-');",
  "}",
  "function rangeArray(start, end) {",
  "  return Array.from({length: end - start}, (_, i) => start + i);",
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
const HELPER_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('utils.js', ${JSON.stringify(HELPER_LINES.join("\n"))});
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

describe("fix round 3: full-chain and .join() secret reconstruction", () => {
  test("three-way + chain is caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_ab";',
      'const b = "cdefghij";',
      'const c = "klmnop1234";',
      "const key = a + b + c;",
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed 3-way chain: ${hits.join(",")}`);
  });

  test("parenthesized chain groupings are caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_ab";',
      'const b = "cdefghij";',
      'const c = "klmnop1234";',
      "const key = (a + b) + c;",
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed grouped chain: ${hits.join(",")}`);
  });

  test("two-step propagation (key = a + b; full = key + c) is caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_ab";',
      'const b = "cdefghij";',
      'const c = "klmnop1234";',
      "const key = a + b;",
      "const full = key + c;",
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed propagated chain: ${hits.join(",")}`);
  });

  test("literal-array and identifier-array .join() are caught", () => {
    assert.ok(
      scanAddedLines([
        'const parts = ["sk_live_abcd", "efghijklmnop1234"];',
        'const key = parts.join("");',
      ]).includes("stripe-secret"),
      "missed identifier-array join",
    );
    assert.ok(
      scanAddedLines([
        'const a = "sk_live_abcd";',
        'const b = "efghijklmnop1234";',
        'const key = [a, b].join("");',
      ]).includes("stripe-secret"),
      "missed inline-array join",
    );
  });

  test("join result feeding a + chain is caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_ab";',
      'const b = "cdefghij";',
      'const c = "klmnop1234";',
      'const key = [a, b].join("") + c;',
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed join+chain: ${hits.join(",")}`);
  });

  test("multi-line chain is caught", () => {
    const hits = scanAddedLines([
      'const a = "sk_live_ab";',
      'const b = "cdefghij";',
      'const c = "klmnop1234";',
      "const key = a +",
      "  b + c;",
    ]);
    assert.ok(hits.includes("stripe-secret"), `missed multi-line chain: ${hits.join(",")}`);
  });

  test("adjacent literals with no join operator still do NOT flag", () => {
    assert.deepEqual(
      scanAddedLines(['const theme = "dark";', 'const mode = "toggle";']),
      [],
    );
    assert.deepEqual(
      scanAddedLines(['{"a": "1", "b": "PATH", "c": "/usr/bin:/bin"}']),
      [],
    );
  });

  test("honest concatenation stays clean", () => {
    assert.deepEqual(
      scanAddedLines([
        'const base = "https://api.example.com";',
        'const url = base + "/v1" + "/users";',
      ]),
      [],
    );
  });

  test("pipeline: three-way chain BLOCKS, 0 PRs", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(CHAIN3_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr3-chain3",
      fixture,
      backend: CHAIN3_BACKEND,
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

  test("pipeline: literal-array join BLOCKS, 0 PRs", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(JOIN_LITERAL_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr3-joinlit",
      fixture,
      backend: JOIN_LITERAL_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const scan = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(scan?.status, "failed");
    assert.equal(t.github.openedPrs.length, 0);
    assert.equal(out.pr, null);
  });

  test("pipeline: identifier-array join BLOCKS, 0 PRs", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(JOIN_IDENT_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr3-joinident",
      fixture,
      backend: JOIN_IDENT_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "blocked");
    const scan = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(scan?.status, "failed");
    assert.equal(t.github.openedPrs.length, 0);
    assert.equal(out.pr, null);
  });

  test("pipeline: honest concatenation still ships", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(HONEST_CONCAT_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr3-honest",
      fixture,
      backend: HONEST_CONCAT_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    const scan = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(scan?.status, "passed");
    assert.equal(t.github.openedPrs.length, 1);
  });
});

describe("fix round 3: approve-time churn override is distinctly audited", () => {
  test("approve with allowChurn audits run_approved_with_churn_override", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const t = await buildTestApp(HELPER_BACKEND);
    const out = await drivePipeline(t, {
      fullName: "acme/fr3-audit",
      fixture,
      backend: HELPER_BACKEND,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
      approveExtras: { allowChurn: true },
    });
    assert.equal(out.run.state, "pr_opened");
    const auditRows = await t.pool.query(
      `SELECT action FROM audit_events WHERE entity_id = $1`,
      [out.run.id],
    );
    assert.ok(
      auditRows.rows.some((r: { action: string }) => r.action === "run_approved_with_churn_override"),
      `approve-time override audit event missing: ${auditRows.rows.map((r: { action: string }) => r.action).join(",")}`,
    );
  });
});

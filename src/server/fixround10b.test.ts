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

function splitBackend(splitJs: string): string {
  return nodeStdin(`
    const fs=require('fs');
    fs.writeFileSync('split.js', ${JSON.stringify(splitJs)});
    ${FEATURE}
  `);
}

const PICK_ARR =
  'function pickArr(flag){ if (flag) { return ["sk_live_abcd", "efghijklmnop1234"]; } return ["x", "y"]; }';

const BLOCK = {
  // (a) The flagged shape: plain push in an assignment RHS.
  rhsPushLiterals: [
    "const arr = [];",
    'const n = arr.push("sk_live_abcd", "efghijklmnop1234");',
    'const key = arr.join("");',
  ],
  // (b) RHS plain push of a spread literal array.
  rhsPushSpreadLiteral: [
    "const arr = [];",
    'const n = arr.push(...["sk_live_abcd", "efghijklmnop1234"]);',
    'const key = arr.join("");',
  ],
  // (c) RHS plain push of set-valued fragments.
  rhsPushSetFragments: [
    PICK_ARR,
    "const arr = [];",
    "const n = arr.push(...pickArr(flag));",
    'const key = arr.join("");',
  ],
  // (d) RHS plain push feeding concat instead of join.
  rhsPushConcat: [
    "const arr = [];",
    'const n = arr.push("sk_live_abcd", "efghijklmnop1234");',
    'const key = arr.concat([]).join("");',
  ],
};

const CLEAN = {
  // Honest RHS push feeding join with non-secret fragments.
  honestRhsPushJoin: [
    "const arr = [];",
    'const n = arr.push("hello", "world");',
    'const key = arr.join(" ");',
  ],
  // Honest RHS push whose return value (the new length) is used.
  honestRhsPushReturnUsed: [
    "const arr = [];",
    'const n = arr.push("hello");',
    'const key = "count " + n;',
  ],
};

describe("fix round 10b: plain push in assignment RHS (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-10b shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest code stays clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 10b (pipeline)", () => {
  for (const [name, src] of Object.entries({
    rhsPushLiterals: BLOCK.rhsPushLiterals.join("\n"),
    rhsPushSpreadLiteral: BLOCK.rhsPushSpreadLiteral.join("\n"),
    rhsPushSetFragments: BLOCK.rhsPushSetFragments.join("\n"),
    rhsPushConcat: BLOCK.rhsPushConcat.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr10b-${name}`,
        fixture,
        backend,
        wishTitle: "Dark mode",
        wishBody: "Add a dark mode toggle.",
      });
      assert.equal(out.run.state, "blocked", `probe ${name} did not block`);
      const scan = out.report?.checks.find((c) => c.name === "secret_scan");
      assert.equal(scan?.status, "failed");
      assert.match(scan?.detail ?? "", /stripe-secret/);
      assert.equal(t.github.openedPrs.length, 0);
      assert.equal(out.pr, null);
    });
  }

  for (const [name, src] of Object.entries({
    honestRhsPushJoin: CLEAN.honestRhsPushJoin.join("\n"),
    honestRhsPushReturnUsed: CLEAN.honestRhsPushReturnUsed.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr10b-${name}`,
        fixture,
        backend,
        wishTitle: "Dark mode",
        wishBody: "Add a dark mode toggle.",
      });
      assert.equal(out.run.state, "pr_opened", `control ${name} did not ship`);
      assert.equal(t.github.openedPrs.length, 1);
    });
  }
});

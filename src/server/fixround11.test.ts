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

// Equal-length branches (else-branch ["x", "y"]).
const PICK_ARR_EQ =
  'function pickArr(flag){ if (flag) { return ["sk_live_abcd", "efghijklmnop1234"]; } return ["x", "y"]; }';

// Unequal-length branches (else-branch ["x"]) — the stated
// adjudication case from the round-10b judge verdict.
const PICK_ARR_UNEQ =
  'function pickArr(flag){ if (flag) { return ["sk_live_abcd", "efghijklmnop1234"]; } return ["x"]; }';

const BLOCK = {
  // (1a) Push into an index target.
  memberIndexPush: [
    "const holders = [[]];",
    'holders[0].push("sk_live_abcd", "efghijklmnop1234");',
    'const key = holders[0].join("");',
  ],
  // (1b) Push into a property target.
  memberPropertyPush: [
    "const o = {};",
    "o.arr = [];",
    'o.arr.push("sk_live_abcd", "efghijklmnop1234");',
    'const key = o.arr.join("");',
  ],
  // (1c) Member-target push.apply, unequal-length branches.
  memberApplyUnequal: [
    PICK_ARR_UNEQ,
    "const holders2 = [[]];",
    "holders2[0].push.apply(holders2[0], pickArr(flag));",
    'const key = holders2[0].join("");',
  ],
  // (1c-equal) Member-target push.apply, equal-length branches.
  memberApplyEqual: [
    PICK_ARR_EQ,
    "const holders2 = [[]];",
    "holders2[0].push.apply(holders2[0], pickArr(flag));",
    'const key = holders2[0].join("");',
  ],
  // (2a) RHS plain push inside a helper body.
  helperRhsPush: [
    'function f(){ const a = []; const n = a.push("sk_live_abcd", "efghijklmnop1234"); return a.join(""); }',
    "const key = f();",
  ],
  // (2b) RHS push.apply inside a helper body.
  helperRhsApply: [
    'function g(){ const a = []; const n = a.push.apply(a, ["sk_live_abcd", "efghijklmnop1234"]); return a.join(""); }',
    "const key2 = g();",
  ],
  // Variant: nested member target.
  memberNestedPush: [
    "const o = {};",
    "o.inner = {};",
    "o.inner.list = [];",
    'o.inner.list.push("sk_live_abcd", "efghijklmnop1234");',
    'const key = o.inner.list.join("");',
  ],
  // Variant: member-target push feeding concat instead of join.
  memberPushConcat: [
    "const o = {};",
    "o.arr = [];",
    'o.arr.push("sk_live_abcd", "efghijklmnop1234");',
    'const key = o.arr.concat([]).join("");',
  ],
  // Variant: helper-body RHS push of a spread set.
  helperRhsSpreadSet: [
    PICK_ARR_EQ,
    'function f(){ const a = []; const n = a.push(...pickArr(flag)); return a.join(""); }',
    "const key = f();",
  ],
  // Variant: helper-body RHS push.apply with a set-valued
  // element array.
  helperRhsApplySet: [
    PICK_ARR_EQ,
    'function g(){ const a = []; const n = a.push.apply(a, pickArr(flag)); return a.join(""); }',
    "const key2 = g();",
  ],
  // Same-mechanism side effect: RHS push.apply with a bare-ident
  // thisArg and unequal variants now fans out via the binding
  // write-back in tryApplyCall (previously the flat fallback).
  rhsIdentApplyUnequal: [
    PICK_ARR_UNEQ,
    "const arr = [];",
    "const n = arr.push.apply(arr, pickArr(flag));",
    'const key = arr.join("");',
  ],
};

const CLEAN = {
  // Honest member-target push with non-secret fragments.
  honestMemberPush: [
    "const o = {};",
    "o.arr = [];",
    'o.arr.push("hello", "world");',
    'const key = o.arr.join(" ");',
  ],
  // Honest helper-body RHS push with non-secret fragments.
  honestHelperRhsPush: [
    'function f(){ const a = []; const n = a.push("hello", "world"); return a.join(" "); }',
    "const key = f();",
  ],
  // Honest helper-body RHS push.apply with non-secret fragments.
  honestHelperRhsApply: [
    'function g(){ const a = []; const n = a.push.apply(a, ["hello", "world"]); return a.join(" "); }',
    "const key2 = g();",
  ],
  // Honest member-target push.apply with non-secret fragments.
  honestMemberApply: [
    "const o = {};",
    "o.arr = [];",
    'o.arr.push.apply(o.arr, ["hello", "world"]);',
    'const key = o.arr.join(" ");',
  ],
};

describe("fix round 11: member-target pushes, helper-body RHS pushes (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-11 shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest code stays clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 11 (pipeline)", () => {
  for (const [name, src] of Object.entries({
    memberIndexPush: BLOCK.memberIndexPush.join("\n"),
    memberPropertyPush: BLOCK.memberPropertyPush.join("\n"),
    memberApplyUnequal: BLOCK.memberApplyUnequal.join("\n"),
    memberApplyEqual: BLOCK.memberApplyEqual.join("\n"),
    helperRhsPush: BLOCK.helperRhsPush.join("\n"),
    helperRhsApply: BLOCK.helperRhsApply.join("\n"),
    memberNestedPush: BLOCK.memberNestedPush.join("\n"),
    memberPushConcat: BLOCK.memberPushConcat.join("\n"),
    helperRhsSpreadSet: BLOCK.helperRhsSpreadSet.join("\n"),
    helperRhsApplySet: BLOCK.helperRhsApplySet.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr11-${name}`,
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
    honestMemberPush: CLEAN.honestMemberPush.join("\n"),
    honestHelperRhsPush: CLEAN.honestHelperRhsPush.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr11-${name}`,
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

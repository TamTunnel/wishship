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
const PICK_CODES =
  'function pickCodes(flag){ if (flag) { return [115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112]; } return [104, 105]; }';
const PICK_FN =
  'function pickFn(flag){ if (flag) { return String.fromCharCode; } return String.fromCodePoint; }';

const BLOCK = {
  // Judge hole 1: spread of a set-valued array into push, plain form.
  pushSpreadSet: [
    PICK_ARR,
    "const arr = [];",
    "arr.push(...pickArr(flag));",
    'const key = arr.join("");',
  ],
  // Judge hole 1: same, apply form.
  pushApplySet: [
    PICK_ARR,
    "const arr = [];",
    "arr.push.apply(arr, pickArr(flag));",
    'const key = arr.join("");',
  ],
  // Variant: push.call with a spread-of-set argument.
  pushCallSet: [
    PICK_ARR,
    "const arr = [];",
    "arr.push.call(arr, ...pickArr(flag));",
    'const key = arr.join("");',
  ],
  // Variant: spread-of-set push feeding concat instead of join.
  pushSpreadSetConcat: [
    PICK_ARR,
    "const arr = [];",
    "arr.push(...pickArr(flag));",
    'const key = arr.concat([]).join("");',
  ],
  // Variant: spread-of-set push.apply nested in an assignment RHS
  // (Parser side-effect path, not the statement walk).
  pushApplySetNestedRHS: [
    PICK_ARR,
    "const arr = [];",
    "const n = arr.push.apply(arr, pickArr(flag));",
    'const key = arr.join("");',
  ],
  // Judge hole 2: method-shorthand object definitions.
  shorthand: [
    'const util = { cat(a, b){ return a + b; } };',
    'const key = util.cat("sk_live_abcd", "efghijklmnop1234");',
  ],
  // Variant: shorthand method with a loop body.
  shorthandLoop: [
    'const util = { joinAll(parts){ let s = ""; for (const p of parts) s += p; return s; } };',
    'const key = util.joinAll(["sk_live_abcd", "efghijklmnop1234"]);',
  ],
  // Variant: shorthand method returning a join.
  shorthandJoin: [
    'const util = { build(a, b){ return [a, b].join(""); } };',
    'const key = util.build("sk_live_abcd", "efghijklmnop1234");',
  ],
  // Judge hole 3: set-valued callee, direct call.
  setCallee: [
    PICK_FN,
    PICK_CODES,
    "const key = pickFn(flag)(...pickCodes(flag));",
  ],
  // Judge hole 3: set-valued callee, apply form.
  setCalleeApply: [
    PICK_FN,
    PICK_CODES,
    "const key = pickFn(flag).apply(null, pickCodes(flag));",
  ],
  // Variant: set-valued callee, call form with spread args.
  setCalleeCall: [
    PICK_FN,
    PICK_CODES,
    "const key = pickFn(flag).call(null, ...pickCodes(flag));",
  ],
  // Variant: set-valued callee, literal code arguments.
  setCalleeLiteral: [
    PICK_FN,
    "const key = pickFn(flag)(115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112);",
  ],
  // Variant: set-valued callee whose members are diff-defined helpers.
  setCalleeDiffHelper: [
    'function a(x, y){ return x + y; }',
    'function b(x, y){ return x + y; }',
    'function pickFn(flag){ if (flag) { return a; } return b; }',
    'const key = pickFn(flag)("sk_live_abcd", "efghijklmnop1234");',
  ],
  // Extension of hole 3's mechanism: object property holding a set
  // of builtin functions, then called.
  propSetCallee: [
    PICK_FN,
    "const util = {};",
    "util.cat = pickFn(flag);",
    PICK_CODES,
    "const key = util.cat(...pickCodes(flag));",
  ],
  // Extension: object property holding a set of diff-defined helpers.
  propSetCalleeDiff: [
    'function a(x, y){ return x + y; }',
    'function b(x, y){ return x + y; }',
    'function pickFn(flag){ if (flag) { return a; } return b; }',
    "const util = {};",
    "util.cat = pickFn(flag);",
    'const key = util.cat("sk_live_abcd", "efghijklmnop1234");',
  ],
  // Extension: object literal property assigned a branchy call result.
  propSetCalleeLiteral: [
    PICK_FN,
    "const util = { cat: pickFn(flag) };",
    PICK_CODES,
    "const key = util.cat(...pickCodes(flag));",
  ],
};

const CLEAN = {
  // Honest spread-push with non-secret fragments.
  honestSpreadPush: [
    'function pickArr(flag){ if (flag) { return ["hello", "world"]; } return ["foo", "bar"]; }',
    "const arr = [];",
    "arr.push(...pickArr(flag));",
    'const key = arr.join(" ");',
  ],
  // Honest shorthand method with non-secret data.
  honestShorthand: [
    'const util = { greet(a, b){ return a + ", " + b; } };',
    'const key = util.greet("Hello", "world");',
  ],
  // Honest branchy callee with non-secret results.
  honestBranchyCallee: [
    'function a(x){ return "got " + x; }',
    'function b(x){ return "got " + x; }',
    'function pickFn(flag){ if (flag) { return a; } return b; }',
    'const key = pickFn(flag)("there");',
  ],
  // Honest shorthand method with a loop body, non-secret data.
  honestShorthandLoop: [
    'const util = { joinAll(parts){ let s = ""; for (const p of parts) s += p; return s; } };',
    'const key = util.joinAll(["hello", "world"]);',
  ],
};

const RESIDUAL = {
  // Class methods stay a documented residual: unchanged behavior.
  classMethodShips: [
    'class U { static cat(a, b){ return a + b; } }',
    'const key = U.cat("sk_live_abcd", "efghijklmnop1234");',
  ],
  // Multi-path object-method calls stay a documented residual: a
  // method property bound via a ternary RHS stays unknown (the
  // ternary-RHS limitation), so the call ships as before.
  ternaryMethodShips: [
    'function f1(a,b){ return a+b; }',
    'function f2(a,b){ return b+a; }',
    "const util = { cat: flag ? f1 : f2 };",
    'const key = util.cat("sk_live_abcd", "efghijklmnop1234");',
  ],
};

describe("fix round 10: push fan-out, shorthand, set callees (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-10 shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest code stays clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });

  test("residuals: documented unmodeled shapes behave as before", () => {
    for (const [name, lines] of Object.entries(RESIDUAL)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `residual ${name} changed behavior: ${hits.join(",")}`);
    }
  });
});

describe("fix round 10 (pipeline)", () => {
  for (const [name, src] of Object.entries({
    pushSpreadSet: BLOCK.pushSpreadSet.join("\n"),
    pushApplySet: BLOCK.pushApplySet.join("\n"),
    shorthand: BLOCK.shorthand.join("\n"),
    setCallee: BLOCK.setCallee.join("\n"),
    setCalleeApply: BLOCK.setCalleeApply.join("\n"),
    pushSpreadSetConcat: BLOCK.pushSpreadSetConcat.join("\n"),
    shorthandLoop: BLOCK.shorthandLoop.join("\n"),
    setCalleeDiffHelper: BLOCK.setCalleeDiffHelper.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr10-${name}`,
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
    honestSpreadPush: CLEAN.honestSpreadPush.join("\n"),
    honestShorthand: CLEAN.honestShorthand.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr10-${name}`,
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

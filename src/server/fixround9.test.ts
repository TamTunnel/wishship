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

// Judge repro: branchy code list (24 codes) vs a short non-secret list.
const PICK_CODES =
  "function pickCodes(flag){ if (flag) { return [115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112]; } return [104, 105]; }";
// Branch fragments that do NOT match stripe-secret alone (8 chars after
// the prefix) but DO match when combined with the suffix "qrstuvwx1234"
// (20 chars after the prefix).
const PICK = "function pick(flag){ if (flag) { return \"sk_live_abcdefgh\"; } return \"sk_live_ijklmnop\"; }";
const PICK_SUFFIX = "qrstuvwx1234";

const BLOCK = {
  // (1) Judge repro 1: fromCharCode.apply.
  applyFromCharCode: [
    PICK_CODES,
    "const key = String.fromCharCode.apply(null, pickCodes(flag));",
  ],
  // (2) Judge repro 2: Reflect.apply.
  reflectApplyFromCharCode: [
    PICK_CODES,
    "const key = Reflect.apply(String.fromCharCode, null, pickCodes(flag));",
  ],
  // (2b) Reflect.apply via fromCodePoint.
  reflectApplyFromCodePoint: [
    PICK_CODES,
    "const key = Reflect.apply(String.fromCodePoint, null, pickCodes(flag));",
  ],
  // (3) Judge repro 3: arr.push.apply as a bare statement.
  pushApply: [
    PICK,
    "const arr = [];",
    "arr.push.apply(arr, [pick(flag)]);",
    `const key = arr.join("") + "${PICK_SUFFIX}";`,
  ],
  // (3b) push.apply nested in an assignment (Parser side-effect path).
  pushApplyNested: [
    PICK,
    "const arr = [];",
    "const n = arr.push.apply(arr, [pick(flag)]);",
    `const key = arr.join("") + "${PICK_SUFFIX}";`,
  ],
  // (3c) push.call as a bare statement.
  pushCall: [
    PICK,
    "const arr = [];",
    "arr.push.call(arr, pick(flag));",
    `const key = arr.join("") + "${PICK_SUFFIX}";`,
  ],
  // .call falls out of the same mechanism: fromCharCode.call.
  callFromCharCode: [
    PICK_CODES,
    "const key = String.fromCharCode.call(null, ...pickCodes(flag));",
  ],
  // apply into a diff-defined helper.
  applyDiffHelper: [
    "function cat(x, y){ return x + y; }",
    'const key = cat.apply(null, ["sk_live_abcd", "efghijklmnop1234"]);',
  ],
  // apply with a set-valued thisArg: the thisArg is dropped, the
  // spread argArray still resolves.
  applySetThisArg: [
    PICK_CODES,
    "function pickThis(flag){ if (flag) { return {}; } return null; }",
    "const key = String.fromCharCode.apply(pickThis(flag), pickCodes(flag));",
  ],
  // apply feeding concat.
  applyFeedConcat: [
    PICK_CODES,
    'const key = String.fromCharCode.apply(null, pickCodes(flag)).concat("");',
  ],
  // push.apply with a set-valued element array.
  pushApplySetElems: [
    "function pickArr(flag){ if (flag) { return [\"sk_live_abcdefgh\"]; } return [\"sk_live_ijklmnop\"]; }",
    "const arr = [];",
    "arr.push.apply(arr, pickArr(flag));",
    `const key = arr.join("") + "${PICK_SUFFIX}";`,
  ],
  // Reflect.apply into a bare builtin decoder (atob).
  reflectApplyAtob: [
    'const key = Reflect.apply(atob, null, ["c2tfbGl2ZV9hYmNkZWZnaGlqa2xtbm9w"]);',
  ],
  // apply on a diff-defined object method.
  applyObjectMethod: [
    "const obj = { build: function(codes){ return String.fromCharCode(...codes); } };",
    PICK_CODES,
    "const key = obj.build.apply(null, [pickCodes(flag)]);",
  ],
};

const CLEAN = {
  // Honest spread-style apply into Math.max (unmodeled call).
  honestApplyMax: [
    "const scores = [3, 1, 2];",
    'const key = "max" + Math.max.apply(null, scores);',
  ],
  // Honest push.apply with non-secret data.
  honestPushApply: [
    "const arr = [];",
    'arr.push.apply(arr, ["hello"]);',
    'const key = arr.join("");',
  ],
  // Honest .call into a diff-defined helper with non-secret args.
  honestCallHelper: [
    'function greet(a, b){ return a + b; }',
    'const key = greet.call(null, "Hello, ", "world");',
  ],
  // Own apply property on an object is a plain method call, not
  // Function.prototype.apply — and returns non-secret data here.
  honestOwnApply: [
    'const obj = { apply: function(x){ return "ok"; } };',
    'const key = obj.apply("anything");',
  ],
};

describe("fix round 9: .apply() / .call() forms (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-9 shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest apply/call stays clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 9 (pipeline)", () => {
  for (const [name, src] of Object.entries({
    applyFromCharCode: BLOCK.applyFromCharCode.join("\n"),
    reflectApplyFromCharCode: BLOCK.reflectApplyFromCharCode.join("\n"),
    pushApply: BLOCK.pushApply.join("\n"),
    pushCall: BLOCK.pushCall.join("\n"),
    applyDiffHelper: BLOCK.applyDiffHelper.join("\n"),
    applyFeedConcat: BLOCK.applyFeedConcat.join("\n"),
    pushApplySetElems: BLOCK.pushApplySetElems.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr9-${name}`,
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
    honestApplyMax: CLEAN.honestApplyMax.join("\n"),
    honestPushApply: CLEAN.honestPushApply.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr9-${name}`,
        fixture,
        backend,
        wishTitle: "Dark mode",
        wishBody: "Add a dark mode toggle.",
      });
      assert.equal(out.run.state, "pr_opened", `control ${name} did not ship`);
      const scan = out.report?.checks.find((c) => c.name === "secret_scan");
      assert.equal(scan?.status, "passed");
      assert.equal(t.github.openedPrs.length, 1);
    });
  }
});

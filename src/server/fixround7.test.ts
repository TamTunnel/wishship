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

// Branch fragments that do NOT match stripe-secret alone (8 chars after
// the prefix) but DO match when combined with the suffix "qrstuvwx1234"
// (20 chars after the prefix).
const PICK_FN =
  'function pick(flag){ if (flag) { return "sk_live_abcdefgh"; } return "sk_live_ijklmnop"; }';
const PICK_SUFFIX = "qrstuvwx1234";

const BLOCK = {
  // (1) Judge repro: for..of over a multi-valued array, top level.
  setLoop: [
    PICK_FN,
    'let s = "";',
    "for (const p of [pick(flag)]) { s += p; }",
    `const key = s + "${PICK_SUFFIX}";`,
  ],
  // Same loop inside a function body.
  setLoopFn: [
    PICK_FN,
    'function acc(){ let s = ""; for (const p of [pick(flag)]) { s += p; } return s; }',
    `const key = acc() + "${PICK_SUFFIX}";`,
  ],
  // Loop over a two-element set array.
  setLoopTwoElem: [
    PICK_FN,
    'let s = "";',
    `for (const p of [pick(flag), "x"]) { s += p; }`,
    `const key = s + "${PICK_SUFFIX}";`,
  ],
  // Loop over a set-valued iterable (set of arrays).
  setIterable: [
    'function pickArr(flag){ if (flag) { return ["sk_live_abcdefgh"]; } return ["sk_live_ijklmnop"]; }',
    'let s = "";',
    "for (const p of pickArr(flag)) { s += p; }",
    `const key = s + "${PICK_SUFFIX}";`,
  ],
  // (2) Judge repro: JSON.parse with a set argument.
  jsonParseSet: [
    'function pickJson(flag){ if (flag) { return \'{"a":"sk_live_abcdefgh"}\'; } return \'{"a":"sk_live_ijklmnop"}\'; }',
    "const obj = JSON.parse(pickJson(flag));",
    `const key = obj.a + "${PICK_SUFFIX}";`,
  ],
  // JSON.parse set feeding a join.
  jsonParseSetJoin: [
    'function pickJson(flag){ if (flag) { return \'{"a":"sk_live_abcdefgh"}\'; } return \'{"a":"sk_live_ijklmnop"}\'; }',
    `const key = [JSON.parse(pickJson(flag)).a, "${PICK_SUFFIX}"].join("");`,
  ],
  // (3) Judge repro: multi-path replace callback.
  replaceCallbackMultipath: [
    `const key = "Z".replace("Z", () => { if (flag) { return "sk_live_abcdefgh"; } return "sk_live_ijklmnop"; }) + "${PICK_SUFFIX}";`,
  ],
  // Multi-path callback via regex search.
  replaceCallbackRegex: [
    `const key = "Z".replace(/Z/, () => { if (flag) { return "sk_live_abcdefgh"; } return "sk_live_ijklmnop"; }) + "${PICK_SUFFIX}";`,
  ],
  // Callback returning a set value directly.
  replaceCallbackSetReturn: [
    PICK_FN,
    `const key = "Z".replace("Z", () => pick(flag)) + "${PICK_SUFFIX}";`,
  ],
  // (4) Judge repro: Array.reverse on resolved arrays.
  revReverse: [
    'const a = "sk_live_abcd", b = "efghijklmnop1234";',
    'function rev(parts){ return parts.slice().reverse().join(""); }',
    "const key = rev([b, a]);",
  ],
  // Reverse of a set-valued array (array holding a set element).
  revSetArray: [
    PICK_FN,
    `const key = ["${PICK_SUFFIX}", pick(flag)].reverse().join("");`,
  ],
  // Reverse of a set receiver (branchy array).
  revSetReceiver: [
    'function pickArr(flag){ if (flag) { return ["qrstuvwx1234", "sk_live_abcdefgh"]; } return ["qrstuvwx1234", "sk_live_ijklmnop"]; }',
    'const key = pickArr(flag).reverse().join("");',
  ],
  // Reverse feeding concat + join.
  revConcat: [
    'const a = "sk_live_abcd", b = "efghijklmnop1234";',
    'function rev(parts){ return parts.slice().reverse(); }',
    'const key = rev([b, a]).concat([]).join("");',
  ],
  // Reverse feeding index reads.
  revIndex: [
    'const a = "sk_live_abcd", b = "efghijklmnop1234";',
    'function rev(parts){ return parts.slice().reverse(); }',
    "const key = rev([b, a])[0] + rev([b, a])[1];",
  ],
  // Array slice alone on a resolved array (slice was unmodeled too).
  arraySlice: [
    'const arr = ["sk_live_abcdefgh", "x"];',
    `const key = arr.slice(0, 1).join("") + "${PICK_SUFFIX}";`,
  ],
  // Builtins with set arguments.
  bufferFromSet: [
    'function pick(flag){ if (flag) { return "c2tfbGl2ZV9hYmNkZWZnaA=="; } return "c2tfbGl2ZV9pamtsbW5vcA=="; }',
    `const key = Buffer.from(pick(flag), "base64").toString() + "${PICK_SUFFIX}";`,
  ],
  fromCharCodeSet: [
    'function pickCode(flag){ if (flag) { return 97; } return 98; }',
    "const key = String.fromCharCode(115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100, pickCode(flag), 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 49, 50, 51, 52);",
  ],
  uint8FromSet: [
    'function pickBytes(flag){ if (flag) { return [115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100]; } return [115, 107, 95, 108, 105, 118, 101, 95, 101, 102, 103, 104]; }',
    'const key = new TextDecoder().decode(Uint8Array.from(pickBytes(flag))) + "efghijklmnop1234";',
  ],
  arrayFromSet: [
    'function pickArr(flag){ if (flag) { return ["sk_live_abcdefgh"]; } return ["sk_live_ijklmnop"]; }',
    `const key = Array.from(pickArr(flag)).join("") + "${PICK_SUFFIX}";`,
  ],
};

const CLEAN = {
  // Honest for..of accumulation.
  honestForOf: [
    'let s = "";',
    'for (const p of ["hello", " "]) { s += p; }',
    'const key = s + "world";',
  ],
  // Branchy loop with non-secret fragments.
  setLoopNonSecret: [
    'function pick(flag){ if (flag) { return "hello"; } return "world"; }',
    'let s = "";',
    "for (const p of [pick(flag)]) { s += p; }",
    'const key = s + "!";',
  ],
  // Honest JSON.parse use.
  honestJsonParse: [
    'const obj = JSON.parse(\'{"theme":"dark"}\');',
    'const key = obj.theme + "mode";',
  ],
  // Honest single-path replace callback.
  honestCallback: [
    'const key = "hello".replace("l", () => "L");',
  ],
  // Honest reverse (display list).
  honestReverse: [
    'const key = ["c", "b", "a"].reverse().join("");',
  ],
  // Classic for loop bodies still walk token by token (no regression).
  classicForBody: [
    'const a = "hello";',
    'const parts = ["x", "y"];',
    'let s = "";',
    'for (let i = 0; i < parts.length; i++) { s += parts[i]; }',
    'const key = s + a;',
  ],
};

describe("fix round 7: set loops, set builtins, multi-path callbacks, reverse (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-7 shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest loops, parses, callbacks, reverses stay clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 7 (pipeline)", () => {
  for (const [name, src] of Object.entries({
    setLoop: BLOCK.setLoop.join("\n"),
    jsonParseSet: BLOCK.jsonParseSet.join("\n"),
    replaceCallbackMultipath: BLOCK.replaceCallbackMultipath.join("\n"),
    revReverse: BLOCK.revReverse.join("\n"),
    setIterable: BLOCK.setIterable.join("\n"),
    revSetReceiver: BLOCK.revSetReceiver.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr7-${name}`,
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
    honestForOf: CLEAN.honestForOf.join("\n"),
    honestReverse: CLEAN.honestReverse.join("\n"),
    setLoopNonSecret: CLEAN.setLoopNonSecret.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr7-${name}`,
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

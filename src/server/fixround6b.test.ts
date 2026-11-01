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
// the prefix, or 16 chars with no prefix) but DO match when combined
// with the suffix "qrstuvwx1234" (20 chars after the prefix).
const PICK_FN =
  'function pick(flag){ if (flag) { return "sk_live_abcdefgh"; } return "sk_live_ijklmnop"; }';
const PICK_SUFFIX = "qrstuvwx1234";

const BLOCK = {
  // (a) multi-path call result combined at the call site, both orders.
  pickPlus: [
    PICK_FN,
    `const key = pick(flag) + "${PICK_SUFFIX}";`,
  ],
  pickPlusReversed: [
    'function pick(flag){ if (flag) { return "abcdefgh12345678"; } return "ijklmnop12345678"; }',
    'const key = "sk_live_" + pick(flag);',
  ],
  // (d) multi-valued through join (array holds a set element).
  pickJoin: [
    PICK_FN,
    `const key = [pick(flag), "${PICK_SUFFIX}"].join("");`,
  ],
  // Set distribution through methods, members, index, templates.
  pickSlice: [
    PICK_FN,
    'const key = pick(flag).slice(0, 8) + "efghijklmnop1234";',
  ],
  pickSliceChain: [
    PICK_FN,
    'const key = pick(flag).slice(0, 8).toLowerCase() + "efghijklmnop1234";',
  ],
  pickMember: [
    'function pickObj(flag){ if (flag) { return {a: "sk_live_abcdefgh"}; } return {a: "sk_live_ijklmnop"}; }',
    `const key = pickObj(flag).a + "${PICK_SUFFIX}";`,
  ],
  pickIndex: [
    'function pickArr(flag){ if (flag) { return ["sk_live_abcdefgh", "x"]; } return ["sk_live_ijklmnop", "y"]; }',
    `const key = pickArr(flag)[0] + "${PICK_SUFFIX}";`,
  ],
  pickTemplate: [
    PICK_FN,
    "const key = `${pick(flag)}" + PICK_SUFFIX + "`;",
  ],
  pickStringCoerce: [
    PICK_FN,
    `const key = String(pick(flag)) + "${PICK_SUFFIX}";`,
  ],
  pickDecode: [
    'function pick(flag){ if (flag) { return "sk_live_abcd%65fghijklmnop"; } return "hello%20world"; }',
    "const key = decodeURIComponent(pick(flag));",
  ],
  // Set argument into an intractable helper: resolved fallback fans out.
  pickSetArgFallback: [
    "function opaque(x, y){ return JSON.stringify([x, y]); }",
    PICK_FN,
    `const key = opaque(pick(flag), "${PICK_SUFFIX}");`,
  ],
  // (b) variable-fed intractable helpers: resolved-argument fallback.
  classicForVars: [
    'const a = "sk_live_abcd";',
    'const b = "efghijklmnop1234";',
    'function joinClassic(parts){ let s = ""; for (let i = 0; i < parts.length; i++) { s += parts[i]; } return s; }',
    "const key = joinClassic([a, b]);",
  ],
  // (c) variable-fed recursive helper.
  recursiveVars: [
    'const a = "sk_live_abcd";',
    'const b = "efghijklmnop1234";',
    'function rec(parts, i){ if (i >= parts.length) return ""; return parts[i] + rec(parts, i + 1); }',
    "const key = rec([a, b], 0);",
  ],
  whileVars: [
    'const a = "sk_live_abcd";',
    'const b = "efghijklmnop1234";',
    'function joinWhile(parts){ let s = ""; let i = 0; while (i < parts.length) { s += parts[i]; i++; } return s; }',
    "const key = joinWhile([a, b]);",
  ],
  // Variable-fed helper whose body is skipped (switch) — fallback still fires.
  switchVars: [
    'const a = "sk_live_abcd";',
    'const b = "efghijklmnop1234";',
    'function sw(parts){ switch (parts.length) { case 2: return parts.join(""); default: return ""; } }',
    "const key = sw([a, b]);",
  ],
};

const CLEAN = {
  // (e) branchy helper whose combinations do NOT form a secret.
  branchyNonSecret: [
    'function pick(flag){ if (flag) { return "hello"; } return "world"; }',
    'const key = pick(flag) + "!";',
  ],
  // (f) intractable helper with variable-held NON-secret fragments.
  intractableNonSecretVars: [
    'const a = "hello";',
    'const b = "world";',
    'function joinClassic(parts){ let s = ""; for (let i = 0; i < parts.length; i++) { s += parts[i]; } return s; }',
    "const key = joinClassic([a, b]);",
  ],
  // An argument that does not fully resolve skips the resolved
  // fallback (no fabricated partial concatenation).
  unknownArgSkipped: [
    "function opaque(x, y){ return JSON.stringify([x, y]); }",
    'const key = opaque(getPart(), "efghijklmnop1234");',
  ],
  honestUrl: [
    'const base = "https://api.example.com";',
    'const url = base + "/v1" + "/users";',
  ],
  adjacentLiterals: [
    'const a = "sk_live_ab";',
    'const b = "cdefghij";',
  ],
  unknownCallee: [
    'const a = "sk_live_ab";',
    "const b = getPart();",
    "const key = a + b;",
  ],
};

describe("fix round 6b: multi-valued resolution + resolved-arg fallback (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed 6b shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: branchy non-secrets, unknown args, classic controls stay clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 6b: multi-valued + resolved fallback (pipeline)", () => {
  for (const [name, src] of Object.entries({
    pickPlus: BLOCK.pickPlus.join("\n"),
    pickPlusReversed: BLOCK.pickPlusReversed.join("\n"),
    pickJoin: BLOCK.pickJoin.join("\n"),
    classicForVars: BLOCK.classicForVars.join("\n"),
    recursiveVars: BLOCK.recursiveVars.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr6b-${name}`,
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
    branchyNonSecret: CLEAN.branchyNonSecret.join("\n"),
    intractableNonSecretVars: CLEAN.intractableNonSecretVars.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr6b-${name}`,
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

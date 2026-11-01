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

// Judge repro: branchy code list (16 codes after the sk_live_ prefix
// when decoded) vs a short non-secret list.
const PICK_CODES =
  "function pickCodes(flag){ if (flag) { return [115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112]; } return [104, 105]; }";
const PLAIN_CODES =
  "const codes = [115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112];";
// Branch fragments that do NOT match stripe-secret alone (8 chars after
// the prefix) but DO match when combined with the suffix "qrstuvwx1234"
// (20 chars after the prefix).
const PICK_SUFFIX = "qrstuvwx1234";

const BLOCK = {
  // (a) Judge repro: spread of a set-valued array into fromCharCode.
  spreadSetFromCharCode: [
    PICK_CODES,
    "const key = String.fromCharCode(...pickCodes(flag));",
  ],
  // (b) Same gap via fromCodePoint.
  spreadSetFromCodePoint: [
    PICK_CODES,
    "const key = String.fromCodePoint(...pickCodes(flag));",
  ],
  // (c) Regression: DIRECT set arg to fromCharCode still blocks.
  directSetFromCharCode: [
    "function pickCode(flag){ if (flag) { return 97; } return 98; }",
    "const key = String.fromCharCode(115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100, pickCode(flag), 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 49, 50, 51, 52);",
  ],
  // (d) Regression: spread of a PLAIN resolved array still blocks.
  spreadPlainFromCharCode: [
    PLAIN_CODES,
    "const key = String.fromCharCode(...codes);",
  ],
  // (e) Variants in the same position.
  // Spread of a set-valued [data, encoding] pair into Buffer.from.
  spreadSetBufferFrom: [
    'function pickPair(flag){ if (flag) { return ["c2tfbGl2ZV9hYmNkZWZnaGlqa2xtbm9w", "base64"]; } return ["aGVsbG8=", "base64"]; }',
    "const key = Buffer.from(...pickPair(flag)).toString();",
  ],
  // Spread of a set-valued byte array into Uint8Array.of + decode.
  spreadSetUint8Of: [
    PICK_CODES,
    "const key = new TextDecoder().decode(Uint8Array.of(...pickCodes(flag)));",
  ],
  // Spread of a set array through a helper param into fromCharCode.
  spreadSetHelperParam: [
    PICK_CODES,
    "function build(codes){ return String.fromCharCode(...codes); }",
    "const key = build(pickCodes(flag));",
  ],
  // Spread of a set-valued single-string array into JSON.parse.
  spreadSetJsonParse: [
    'function pickJson(flag){ if (flag) { return [\'{"a":"sk_live_abcdefgh"}\']; } return [\'{"a":"sk_live_ijklmnop"}\']; }',
    `const key = JSON.parse(...pickJson(flag)).a + "${PICK_SUFFIX}";`,
  ],
  // Spread of a set-valued range pair into array slice.
  spreadSetSlice: [
    'const arr = ["sk_live_abcdefgh", "x"];',
    "function pickRange(flag){ if (flag) { return [0, 1]; } return [0, 2]; }",
    `const key = arr.slice(...pickRange(flag)).join("") + "${PICK_SUFFIX}";`,
  ],
};

const CLEAN = {
  // Honest spread into fromCharCode with non-secret codes.
  honestSpreadFromCharCode: [
    "const codes = [72, 105];",
    "const key = String.fromCharCode(...codes);",
  ],
  // Honest spread of non-secret branchy codes.
  honestSpreadSetFromCharCode: [
    "function pickCodes(flag){ if (flag) { return [72, 105]; } return [104, 105]; }",
    "const key = String.fromCharCode(...pickCodes(flag));",
  ],
  // Honest spread into an unmodeled call (Math.max): stays unknown.
  honestSpreadMax: [
    "const scores = [3, 1, 2];",
    'const key = "max" + Math.max(...scores);',
  ],
};

describe("fix round 8: spread of set arrays into variadic builtins (unit)", () => {
  test("required shapes: all block", () => {
    for (const [name, lines] of Object.entries(BLOCK)) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed round-8 shape ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest spreads stay clean", () => {
    for (const [name, lines] of Object.entries(CLEAN)) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 8 (pipeline)", () => {
  for (const [name, src] of Object.entries({
    spreadSetFromCharCode: BLOCK.spreadSetFromCharCode.join("\n"),
    spreadSetFromCodePoint: BLOCK.spreadSetFromCodePoint.join("\n"),
    directSetFromCharCode: BLOCK.directSetFromCharCode.join("\n"),
    spreadPlainFromCharCode: BLOCK.spreadPlainFromCharCode.join("\n"),
    spreadSetBufferFrom: BLOCK.spreadSetBufferFrom.join("\n"),
    spreadSetUint8Of: BLOCK.spreadSetUint8Of.join("\n"),
    spreadSetHelperParam: BLOCK.spreadSetHelperParam.join("\n"),
    spreadSetJsonParse: BLOCK.spreadSetJsonParse.join("\n"),
    spreadSetSlice: BLOCK.spreadSetSlice.join("\n"),
  })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr8-${name}`,
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
    honestSpreadFromCharCode: CLEAN.honestSpreadFromCharCode.join("\n"),
    honestSpreadMax: CLEAN.honestSpreadMax.join("\n"),
  })) {
    test(`pipeline: ${name} still ships`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr8-${name}`,
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

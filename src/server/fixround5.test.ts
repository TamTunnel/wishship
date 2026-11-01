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

// Base64 / hex of the pattern-matching secret "sk_live_abcdefghijklmnop"
// (16 chars after the prefix — the stripe-secret pattern needs 16+).
const B64_FULL = "c2tfbGl2ZV9hYmNkZWZnaGlqa2xtbm9w";
const B64_HALF_A = "c2tfbGl2ZV9hYmNk";
const B64_HALF_B = "ZWZnaGlqa2xtbm9w";
const HEX_FULL = "736b5f6c6976655f6162636465666768696a6b6c6d6e6f70";

const JUDGE = {
  member:
    'const o = {};\no.a = "sk_live_abcd";\no.b = "efghijklmnop1234";\nconst key = o.a + o.b;\n',
  slice:
    'const a = "sk_live_abcdPADPAD";\nconst b = "efghijklmnop1234PAD";\nconst key = a.slice(0, 12) + b.slice(0, 16);\n',
  substring:
    'const a = "sk_live_abcdPADPAD";\nconst b = "efghijklmnop1234PAD";\nconst key = a.substring(0, 12) + b.substring(0, 16);\n',
  replace:
    'const a = "sk_live_abcdX";\nconst key = a.replace("X", "") + "efghijklmnop1234";\n',
  fromCodePoint:
    "const key = String.fromCodePoint(115,107,95,108,105,118,101,95,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,49,50,51,52);\n",
  atob: `const key = atob("${B64_FULL}");\n`,
  bufferFrom: `const key = Buffer.from("${B64_FULL}", "base64").toString();\n`,
};

const INVENTED = {
  splitJoin:
    'const s = "sk_live_abcd-efghijklmnop1234";\nconst key = s.split("-").join("");\n',
  sliceThenReplace:
    'const a = "sk_live_abcdXPAD";\nconst key = a.slice(0, 13).replace("X", "") + "efghijklmnop1234";\n',
  replaceThenConcat:
    'const a = "sk_live_abcdX";\nconst key = a.replace("X", "").concat("efghijklmnop1234");\n',
  caseTransform:
    'const a = "SK_LIVE_ABCD";\nconst b = "EFGHIJKLMNOP1234";\nconst key = a.toLowerCase() + b.toLowerCase();\n',
  trimPadded:
    'const a = "  sk_live_abcd  ";\nconst key = a.trim() + "efghijklmnop1234";\n',
  nestedMember:
    'const o = {};\no.inner = {};\no.inner.a = "sk_live_abcd";\no.inner.b = "efghijklmnop1234";\nconst key = o.inner.a + o.inner.b;\n',
  fromCodePointJoin:
    'const c = String.fromCodePoint(115,107,95,108,105,118,101,95,97,98,99,100);\nconst key = [c, "efghijklmnop1234"].join("");\n',
  base64Concat:
    `const a = atob("${B64_HALF_A}");\nconst b = atob("${B64_HALF_B}");\nconst key = a + b;\n`,
  bufferFromDecode:
    `const key = Buffer.from("${B64_FULL}", "base64");\n`,
};

describe("fix round 5: resolver extensions (unit)", () => {
  test("judge shapes: member, slice, substring, replace, fromCodePoint, decodes", () => {
    for (const [name, src] of Object.entries(JUDGE)) {
      const hits = scanAddedLines(src.split("\n"));
      assert.ok(hits.includes("stripe-secret"), `missed judge shape ${name}: ${hits.join(",")}`);
    }
  });

  test("invented probes: transforms, members, decodes, chained methods", () => {
    for (const [name, src] of Object.entries(INVENTED)) {
      const hits = scanAddedLines(src.split("\n"));
      assert.ok(hits.includes("stripe-secret"), `missed invented probe ${name}: ${hits.join(",")}`);
    }
  });

  test("unit extras: hex decode, regex replace, object literal, bracket/computed members, charAt/index chains, substr", () => {
    for (const [name, lines] of Object.entries({
      hexDecode: [`const key = Buffer.from("${HEX_FULL}", "hex").toString();`],
      regexReplace: [
        'const a = "sk_live_abcdX";',
        'const key = a.replace(/X/, "") + "efghijklmnop1234";',
      ],
      regexReplaceAll: [
        'const a = "sk_live_abcdXXefghijklmnop1234";',
        'const key = a.replaceAll(/X/g, "");',
      ],
      objectLiteral: [
        'const o = {a: "sk_live_abcd", b: "efghijklmnop1234"};',
        "const key = o.a + o.b;",
      ],
      bracketMember: [
        "const o = {};",
        'o["a"] = "sk_live_abcd";',
        'const key = o["a"] + "efghijklmnop1234";',
      ],
      computedKeyMember: [
        'const k = "a";',
        "const o = {};",
        'o[k] = "sk_live_abcd";',
        'const key = o[k] + "efghijklmnop1234";',
      ],
      charAtChain: [
        'const s = "sk_live_abcdefghijklmnop";',
        "const key = s.charAt(0) + s.slice(1);",
      ],
      indexChain: [
        'const s = "sk_live_abcdefghijklmnop";',
        "const key = s[0] + s.substring(1);",
      ],
      substr: [
        'const a = "sk_live_abcdPADPAD";',
        'const b = "efghijklmnop1234PAD";',
        "const key = a.substr(0, 12) + b.substr(0, 16);",
      ],
      substringSwap: [
        // substring swaps out-of-order args (JS semantics, not approximation).
        'const a = "PADsk_live_abcd";',
        'const key = a.substring(12, 3) + "efghijklmnop1234";',
      ],
      memberPlusEq: [
        "const o = {};",
        'o.a = "sk_live_abcd";',
        'o.a += "efghijklmnop1234";',
        "const key = o.a;",
      ],
      arrayIndex: [
        'const parts = ["sk_live_abcd", "efghijklmnop1234"];',
        "const key = parts[0] + parts[1];",
      ],
      stringCoercion: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        'const c = "klmnop1234";',
        "const key = String(a + b + c);",
      ],
    })) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed unit extra ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest transforms, unknown callees, non-secret decodes stay clean", () => {
    for (const [name, lines] of Object.entries({
      honestSlice: [
        'const url = "https://api.example.com/v1/users";',
        "const path = url.slice(0, 5);",
      ],
      honestReplace: [
        'const s = "hello world";',
        'const t = s.replace("world", "there");',
      ],
      honestSplitDash: [
        'const parts = ["a", "b"];',
        'const key = parts.join("-");',
      ],
      honestCase: [
        'const s = "hello";',
        "const t = s.toUpperCase();",
      ],
      honestTrim: [
        'const s = "  hello  ";',
        "const t = s.trim();",
      ],
      unknownCallee: [
        'const a = "sk_live_ab";',
        "const b = getPart();",
        "const key = a + b;",
      ],
      missingMember: [
        "const o = {};",
        'const key = o.missing + "x";',
      ],
      nonSecretBase64: [
        'const key = atob("aGVsbG8gd29ybGQ=");',
      ],
      nonSecretBufferHex: [
        'const key = Buffer.from("68656c6c6f", "hex").toString();',
      ],
      memberFragmentOnly: [
        'obj.key = "sk_live_ab";',
        'const b = "cdefghij";',
      ],
      stringIndexSingleChar: [
        'const s = "sk_live_abcd";',
        "const first = s[0];",
      ],
    })) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 5: resolver extensions (pipeline)", () => {
  for (const [name, src] of Object.entries({ ...JUDGE, ...INVENTED })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr5-${name}`,
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

  test("pipeline: honest transform flow still ships", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const backend = nodeStdin(`
      const fs=require('fs');
      fs.writeFileSync('theme.js','const base = "https://api.example.com";\\nconst url = base + "/v1" + "/users";\\nconst slug = url.slice(8, 11);\\nmodule.exports={dark:true,url,slug};\\n');
      fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
    `);
    const t = await buildTestApp(backend);
    const out = await drivePipeline(t, {
      fullName: "acme/fr5-honest",
      fixture,
      backend,
      wishTitle: "Dark mode",
      wishBody: "Add a dark mode toggle.",
    });
    assert.equal(out.run.state, "pr_opened");
    const scan = out.report?.checks.find((c) => c.name === "secret_scan");
    assert.equal(scan?.status, "passed");
    assert.equal(t.github.openedPrs.length, 1);
  });
});

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

// Pattern-matching secret "sk_live_abcdefghijklmnop" (16 chars after the
// prefix — the stripe-secret pattern needs 16+). Halves used below:
// "sk_live_abcd" + "efghijklmnop1234".
const CHARCODE_ARGS = [
  '"a".charCodeAt(0)+18',
  '"a".charCodeAt(0)+10',
  '"a".charCodeAt(0)-2',
  '"a".charCodeAt(0)+11',
  '"a".charCodeAt(0)+8',
  '"a".charCodeAt(0)+21',
  '"a".charCodeAt(0)+4',
  '"a".charCodeAt(0)-2',
  '"a".charCodeAt(0)+0',
  '"a".charCodeAt(0)+1',
  '"a".charCodeAt(0)+2',
  '"a".charCodeAt(0)+3',
  '"a".charCodeAt(0)+4',
  '"a".charCodeAt(0)+5',
  '"a".charCodeAt(0)+6',
  '"a".charCodeAt(0)+7',
  '"a".charCodeAt(0)+8',
  '"a".charCodeAt(0)+9',
  '"a".charCodeAt(0)+10',
  '"a".charCodeAt(0)+11',
  '"a".charCodeAt(0)+12',
  '"a".charCodeAt(0)+13',
  '"a".charCodeAt(0)+14',
  '"a".charCodeAt(0)+15',
].join(", ");

const TEXTDECODER_CODES = [
  115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100,
  101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
].join(",");

const JUDGE = {
  decodeURIComponent:
    'const key = decodeURIComponent("sk_live_abcd%65fghijklmnop");\n',
  unescape:
    'const key = unescape("sk_live_abcd%65fghijklmnop");\n',
  textDecoder:
    `const key = new TextDecoder().decode(Uint8Array.from([${TEXTDECODER_CODES}]));\n`,
  jsonParse:
    "const obj = JSON.parse('{\"a\":\"sk_live_abcd\",\"b\":\"efghijklmnop1234\"}');\nconst key = obj.a + obj.b;\n",
  arrayFrom:
    'const parts = Array.from(["sk_live_abcd", "efghijklmnop1234"]);\nconst key = parts.join("");\n',
  charCodeAtArithmetic:
    `const key = String.fromCharCode(${CHARCODE_ARGS});\n`,
  replaceCallback:
    'const key = "sk_live_abcdX".replace("X", () => "efghijklmnop1234");\n',
  helperCat:
    'function cat(x, y){ return x + y; }\nconst key = cat("sk_live_abcd", "efghijklmnop1234");\n',
  helperLoop:
    'function joinAll(parts){ let s = ""; for (const p of parts) s += p; return s; }\nconst key = joinAll(["sk_live_abcd", "efghijklmnop1234"]);\n',
};

const INVENTED = {
  nestedHelper:
    'function inner(x, y){ return x + y; }\nfunction outer(a, b){ return inner(a, b); }\nconst key = outer("sk_live_abcd", "efghijklmnop1234");\n',
  helperJoin:
    'function j(a, b){ return [a, b].join(""); }\nconst key = j("sk_live_abcd", "efghijklmnop1234");\n',
  helperLoopPush:
    'function acc(parts){ const out = []; for (const p of parts) out.push(p); return out.join(""); }\nconst key = acc(["sk_live_abcd", "efghijklmnop1234"]);\n',
  decodeFeedConcat:
    'const a = decodeURIComponent("sk_live_abcd%65");\nconst key = a + "fghijklmnop1234";\n',
  jsonNested:
    "const obj = JSON.parse('{\"inner\":{\"a\":\"sk_live_abcd\",\"b\":\"efghijklmnop1234\"}}');\nconst key = obj.inner.a + obj.inner.b;\n",
  arrayFromString:
    'const parts = Array.from("sk_live_abcdefghijklmnop");\nconst key = parts.join("");\n',
  charCodeAtVars:
    'const b = "a";\nconst key = String.fromCharCode(b.charCodeAt(0)+18) + "k_live_abcdefghijklmnop";\n',
  replaceCallbackJoin:
    'const key = "sk_live_abcdX".replace("X", () => ["efgh", "ijklmnop1234"].join(""));\n',
  helperReordered:
    'function cat(x, y){ return y + x; }\nconst key = cat("efghijklmnop1234", "sk_live_abcd");\n',
  helperIfElse:
    'function pick(flag){ if (flag) { return "sk_live_abcd" + "efghijklmnop1234"; } return "hello"; }\nconst key = pick(someFlag);\n',
  helperMethodChain:
    'function up(s){ return s.toUpperCase(); }\nconst key = up("sk_live_abcd").toLowerCase() + "efghijklmnop1234";\n',
  fallbackOpaque:
    'function opaque(x, y){ return JSON.stringify([x, y]); }\nconst key = opaque("sk_live_abcd", "efghijklmnop1234");\n',
};

describe("fix round 6: decoders, JSON/Array, numeric domain, function modeling (unit)", () => {
  test("judge shapes: all nine block", () => {
    for (const [name, src] of Object.entries(JUDGE)) {
      const hits = scanAddedLines(src.split("\n"));
      assert.ok(hits.includes("stripe-secret"), `missed judge shape ${name}: ${hits.join(",")}`);
    }
  });

  test("invented probes: helpers, decodes, JSON/Array, callbacks, fallback", () => {
    for (const [name, src] of Object.entries(INVENTED)) {
      const hits = scanAddedLines(src.split("\n"));
      assert.ok(hits.includes("stripe-secret"), `missed invented probe ${name}: ${hits.join(",")}`);
    }
  });

  test("unit extras: arithmetic, encoders, map functions, defaults, rest params", () => {
    for (const [name, lines] of Object.entries({
      arithmeticChain: [
        'const a = "sk_live_abcd";',
        "const n = a.length;",
        "const key = a.slice(0, n - 4) + \"efghijklmnop1234\";",
      ],
      textEncoderRoundTrip: [
        'const bytes = new TextEncoder().encode("sk_live_abcdefghijklmnop");',
        "const key = new TextDecoder().decode(bytes);",
      ],
      uint8ArrayOf: [
        "const bytes = Uint8Array.of(115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112);",
        "const key = new TextDecoder().decode(bytes);",
      ],
      arrayFromMap: [
        'const parts = Array.from(["sk_live_abcd", "efghijklmnop1234"], (s) => s);',
        'const key = parts.join("");',
      ],
      arrowConcise: [
        'const cat = (x, y) => x + y;',
        'const key = cat("sk_live_abcd", "efghijklmnop1234");',
      ],
      arrowBlock: [
        'const cat = (x, y) => { const t = x + y; return t; };',
        'const key = cat("sk_live_abcd", "efghijklmnop1234");',
      ],
      functionExpression: [
        'const cat = function (x, y) { return x + y; };',
        'const key = cat("sk_live_abcd", "efghijklmnop1234");',
      ],
      defaultParam: [
        'function cat(x, y = "efghijklmnop1234"){ return x + y; }',
        'const key = cat("sk_live_abcd");',
      ],
      restParam: [
        'function j(...parts){ return parts.join(""); }',
        'const key = j("sk_live_abcd", "efghijklmnop1234");',
      ],
      objectMethod: [
        'const h = { cat: function (x, y) { return x + y; } };',
        'const key = h.cat("sk_live_abcd", "efghijklmnop1234");',
      ],
      knownCondition: [
        'function pick(flag){ if (flag) { return "sk_live_abcd"; } return "efghijklmnop1234"; }',
        'const key = pick(true) + "efghijklmnop1234";',
      ],
      decodeUri: [
        'const key = decodeURI("sk_live_abcd%65fghijklmnop");',
      ],
      charCodeAtIndex: [
        'const s = "sk_live_abcdefghijklmnop";',
        "const key = s.slice(0, 12) + String.fromCharCode(s.charCodeAt(12), s.charCodeAt(13), s.charCodeAt(14), s.charCodeAt(15), s.charCodeAt(16), s.charCodeAt(17), s.charCodeAt(18), s.charCodeAt(19), s.charCodeAt(20), s.charCodeAt(21), s.charCodeAt(22), s.charCodeAt(23));",
      ],
    })) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed unit extra ${name}: ${hits.join(",")}`);
    }
  });

  test("controls: honest helpers, fallback restraint, classic controls stay clean", () => {
    for (const [name, lines] of Object.entries({
      honestHelperGreet: [
        'function greet(a, b){ return a + " " + b; }',
        'const msg = greet("Hello,", "world");',
      ],
      honestHelperJoin: [
        'function slug(a, b){ return [a, b].join("-"); }',
        'const s = slug("dark", "mode");',
      ],
      honestHelperNumeric: [
        "function add(a, b){ return a + b; }",
        "const n = add(1, 2);",
      ],
      numericDomainNoFlag: [
        "const key = String(1 + 2) + \"x\";",
      ],
      fallbackSingleLiteral: [
        "function f(x){ return x; }",
        'const k = f("sk_live_abcd");',
      ],
      fallbackNonSecret: [
        "function f(x, y){ return x + y; }",
        'const k = f("hello", "world");',
      ],
      adjacentLiterals: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
      ],
      honestUrl: [
        'const base = "https://api.example.com";',
        'const url = base + "/v1" + "/users";',
      ],
      unknownCallee: [
        'const a = "sk_live_ab";',
        "const b = getPart();",
        "const key = a + b;",
      ],
      nonSecretDecode: [
        'const key = decodeURIComponent("hello%20world");',
      ],
      missingMember: [
        "const o = {};",
        'const key = o.missing + "x";',
      ],
    })) {
      const hits = scanAddedLines(lines);
      assert.deepEqual(hits, [], `false positive on control ${name}: ${hits.join(",")}`);
    }
  });
});

describe("fix round 6: decoders, helpers, fallback (pipeline)", () => {
  for (const [name, src] of Object.entries({ ...JUDGE, ...INVENTED })) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr6-${name}`,
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

  test("pipeline: honest helper flow still ships", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const backend = nodeStdin(`
      const fs=require('fs');
      fs.writeFileSync('theme.js','function greet(a, b){ return a + " " + b; }\\nconst msg = greet("Hello,", "world");\\nmodule.exports={dark:true,msg};\\n');
      fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
    `);
    const t = await buildTestApp(backend);
    const out = await drivePipeline(t, {
      fullName: "acme/fr6-honest-helper",
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

  test("pipeline: honest slug + numeric helpers still ship", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const backend = nodeStdin(`
      const fs=require('fs');
      fs.writeFileSync('theme.js','function slug(a, b){ return [a, b].join("-"); }\\nfunction double(n){ return n * 2; }\\nmodule.exports={dark:true,slug:slug("dark","mode"),n:double(21)};\\n');
      fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark||t.slug!=="dark-mode"||t.n!==42)process.exit(1);\\n');
    `);
    const t = await buildTestApp(backend);
    const out = await drivePipeline(t, {
      fullName: "acme/fr6-honest-helper-2",
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

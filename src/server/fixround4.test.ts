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

function splitBackend(splitJs: string, extra = ""): string {
  return nodeStdin(`
    const fs=require('fs');
    fs.writeFileSync('split.js', ${JSON.stringify(splitJs)});
    ${extra}
    ${FEATURE}
  `);
}

const SPLIT = {
  varSep:
    'const sep = "";\nconst parts = ["sk_live_abcd", "efghijklmnop1234"];\nconst key = parts.join(sep);\n',
  pushBuilt:
    'const parts = [];\nparts.push("sk_live_abcd");\nparts.push("efghijklmnop1234");\nconst key = parts.join("");\n',
  concat:
    'const a = "sk_live_ab";\nconst b = "cdefghij";\nconst c = "klmnop1234";\nconst key = a.concat(b, c);\n',
  sepViaChain:
    'const s0 = "";\nconst sep = s0;\nconst parts = ["sk_live_abcd", "efghijklmnop1234"];\nconst key = parts.join(sep);\n',
  concatFeedingJoin:
    'const a = "sk_live_ab";\nconst b = "cdefghij";\nconst c = "klmnop1234";\nconst key = [a.concat(b), c].join("");\n',
  joinFeedingConcat:
    'const a = "sk_live_abcd";\nconst b = "efghijklmnop1234";\nconst key = [a].join("").concat(b);\n',
  pushFeedingConcat:
    'const parts = [];\nparts.push("sk_live_abcd");\nconst key = parts.concat(["efghijklmnop1234"]).join("");\n',
  templateWithJoin:
    'const a = "sk_live_abcd";\nconst b = "efghijklmnop1234";\nconst key = `${[a, b].join("")}`;\n',
  mixedPushLiteral:
    'const parts = ["sk_live_abcd"];\nparts.push("efghijklmnop1234");\nconst key = parts.join("");\n',
  reassigned:
    'let a = "sk_live_ab";\na = a + "cdefghij";\na = a + "klmnop1234";\n',
};

describe("fix round 4: resolved-value secret reconstruction (unit)", () => {
  test("judge shape (a): variable separator join is caught", () => {
    const hits = scanAddedLines(SPLIT.varSep.split("\n"));
    assert.ok(hits.includes("stripe-secret"), `missed var-sep join: ${hits.join(",")}`);
  });

  test("judge shape (b): push-built array join is caught", () => {
    const hits = scanAddedLines(SPLIT.pushBuilt.split("\n"));
    assert.ok(hits.includes("stripe-secret"), `missed push-built join: ${hits.join(",")}`);
  });

  test("judge shape (c): .concat() reconstruction is caught", () => {
    const hits = scanAddedLines(SPLIT.concat.split("\n"));
    assert.ok(hits.includes("stripe-secret"), `missed concat: ${hits.join(",")}`);
  });

  test("invented probes: separator chains, concat/join mixes, templates, reassignment", () => {
    for (const [name, src] of Object.entries({
      sepViaChain: SPLIT.sepViaChain,
      concatFeedingJoin: SPLIT.concatFeedingJoin,
      joinFeedingConcat: SPLIT.joinFeedingConcat,
      pushFeedingConcat: SPLIT.pushFeedingConcat,
      templateWithJoin: SPLIT.templateWithJoin,
      mixedPushLiteral: SPLIT.mixedPushLiteral,
      reassigned: SPLIT.reassigned,
    })) {
      const hits = scanAddedLines(src.split("\n"));
      assert.ok(hits.includes("stripe-secret"), `missed invented probe ${name}: ${hits.join(",")}`);
    }
  });

  test("prior shapes still caught (chains, joins, templates, propagation)", () => {
    for (const [name, lines] of Object.entries({
      twoWay: ['const a = "sk_live_abcd";', 'const b = "efghijklmnop1234";', "const key = a + b;"],
      threeWay: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        'const c = "klmnop1234";',
        "const key = a + b + c;",
      ],
      grouped: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        'const c = "klmnop1234";',
        "const key = (a + b) + c;",
      ],
      propagated: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        'const c = "klmnop1234";',
        "const key = a + b;",
        "const full = key + c;",
      ],
      literalJoin: [
        'const parts = ["sk_live_abcd", "efghijklmnop1234"];',
        'const key = parts.join("");',
      ],
      template: [
        'const a = "sk_live_abcd";',
        'const b = "efghijklmnop1234";',
        "const key = `${a}${b}`;",
      ],
      bareCallArg: [
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        'const c = "klmnop1234";',
        "send(a + b + c);",
      ],
      fromCharCode: [
        "const key = String.fromCharCode(115, 107, 95, 108, 105, 118, 101, 95, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 49, 50, 51, 52);",
      ],
    })) {
      const hits = scanAddedLines(lines);
      assert.ok(hits.includes("stripe-secret"), `missed prior shape ${name}: ${hits.join(",")}`);
    }
  });

  test("non-flagging controls hold (adjacency, env dump, honest code, unknown calls)", () => {
    assert.deepEqual(
      scanAddedLines(['const theme = "dark";', 'const mode = "toggle";']),
      [],
    );
    assert.deepEqual(
      scanAddedLines(['{"a": "1", "b": "PATH", "c": "/usr/bin:/bin"}']),
      [],
    );
    // Exact npm-test PATH env line from the round-2 regression.
    const npmPath =
      "/home/hatch/workspace/wishship/node_modules/.bin:/home/hatch/workspace/node_modules/.bin:/home/hatch/node_modules/.bin:/home/node_modules/.bin:/node_modules/.bin:/opt/hatch-image/bin/npm-package/node_modules/@npmcli/run-script/lib/node-gyp-bin:/opt/hatch/bin:/opt/hatch-image/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/muse/skills/documents/scripts:/opt/muse/skills/generate_podcast/scripts:/opt/muse/skills/style-tryon/scripts";
    const envLine = JSON.stringify({
      HOME: "/tmp/wishship-agent-Ab12Cd",
      TERM: "dumb",
      WISHSHIP_AGENT: "1",
      PATH: npmPath,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      PWD: "/tmp/wishship-wt-Xy34Zz/ws-run-98BwWT",
    });
    assert.deepEqual(scanAddedLines([envLine]), []);
    assert.deepEqual(
      scanAddedLines([
        'const base = "https://api.example.com";',
        'const url = base + "/v1" + "/users";',
      ]),
      [],
    );
    // Unknown callee: a + unknown never resolves, never flags alone.
    assert.deepEqual(
      scanAddedLines([
        'const a = "sk_live_ab";',
        "const b = getPart();",
        "const key = a + b;",
      ]),
      [],
    );
    // Regex literal containing identifier + identifier: not a join.
    assert.deepEqual(
      scanAddedLines([
        'const a = "sk_live_ab";',
        'const b = "cdefghij";',
        "const re = /a+b/;",
      ]),
      [],
    );
    // Member assignment never binds a variable of that name.
    assert.deepEqual(
      scanAddedLines([
        'obj.key = "sk_live_ab";',
        'const b = "cdefghij";',
      ]),
      [],
    );
    // Join with a real separator: the runtime value is not secret-shaped.
    assert.deepEqual(
      scanAddedLines([
        'const parts = ["sk_live_abcd", "efghijklmnop1234"];',
        'const key = parts.join("-");',
      ]),
      [],
    );
    assert.deepEqual(
      scanAddedLines([
        'const parts = ["sk_live_abcd", "efghijklmnop1234"];',
        "const key = parts.join();",
      ]),
      [],
    );
  });
});

describe("fix round 4: resolved-value secret reconstruction (pipeline)", () => {
  for (const [name, src] of Object.entries(SPLIT)) {
    test(`pipeline: ${name} BLOCKS, 0 PRs`, async () => {
      const fixture = await makeFixtureRepo(FULL_FIXTURE);
      const backend = splitBackend(src);
      const t = await buildTestApp(backend);
      const out = await drivePipeline(t, {
        fullName: `acme/fr4-${name}`,
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

  test("pipeline: honest URL concatenation still ships", async () => {
    const fixture = await makeFixtureRepo(FULL_FIXTURE);
    const backend = nodeStdin(`
      const fs=require('fs');
      fs.writeFileSync('theme.js','const base = "https://api.example.com";\\nconst url = base + "/v1" + "/users";\\nmodule.exports={dark:true,url};\\n');
      fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
    `);
    const t = await buildTestApp(backend);
    const out = await drivePipeline(t, {
      fullName: "acme/fr4-honest",
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

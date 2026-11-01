# WishShip

**The vote-to-ship loop for app builders.** Users submit feature requests and vote on them.
Each cycle, the top-voted wish goes to the maintainer for approval. An approved winner is
implemented by a coding agent, verified by deterministic checks, and opened as a **draft PR**
carrying the full verification report. The maintainer reviews and merges. The agent never merges.

## The problem, in plain language

Open-source maintainers drown in feature requests. Issues pile up, voters have no say in what
gets built next, and when someone does build a requested feature, nobody can tell at a glance
whether it was checked. WishShip turns "most-wanted feature" into a visible, auditable loop:
vote → approve → build → verify → review → ship.

## How it works

1. **Board.** A maintainer installs the WishShip GitHub App on a repo. Users sign in with
   GitHub, submit wishes, and upvote them. Votes are public: who voted for what is visible.
2. **Cycle.** Weekly (configurable), the cycle closes and the top-voted wish above the
   threshold is proposed. No winner below threshold: nothing is proposed.
3. **Approval (human gate 1).** The maintainer approves or rejects the winner. No approval,
   no agent run, no money spent. A rejected winner returns to `open`; it never auto-advances
   to the runner-up.
4. **Agent run.** A coding-agent CLI runs in a fresh temp worktree with a scrubbed environment
   (no GitHub token, no npm auth, no service credentials). The agent never pushes: the PR
   branch is service-created.
5. **Verification (the moat).** Deterministic checks run on a clean checkout with the diff
   applied: the repo's own tests, lint, typecheck, secret scan, diff-size limit, churn check,
   dependency rules, new-network-call flagging, and an advisory second-model review.
   **Ordering matters:** dependency/manifest violations are computed FIRST, and when they
   fail, no check command executes at all. The old order ran the tests first — and a pinned
   command string like `make test` still dispatches to the PATCHED Makefile, so an agent
   rewriting the test recipe got its recipe executed during verification. Fail-fast closes
   that hole; it also keeps check output (which lands in run records served by
   unauthenticated `GET /api/runs/:id`) free of anything a hostile recipe could print.
   Two maintainer escapes exist for honest blocks, both audited: **retry-with-deps**
   (dependency changes permitted for that run) and **churn override** (see below).
6. **Draft PR (human gate 2).** Only `VERIFIED` or `PARTIAL` reports open a PR, and it opens
   as a **draft** carrying the full report. The maintainer reviews, merges, or closes it.

### Verification details worth knowing

- **Script additions are not violations.** If the agent adds a `package.json` script key
  that did not exist at base, that addition is exempted per-key: it can never run under
  verification, because check commands are pinned to the base discovery. The addition is
  diff content the maintainer reviews in the draft PR. Changing or removing a script key
  that exists at base still blocks, as do dependency adds and lockfile changes.
- **Split tokens are caught.** The secret scan covers the whole added-lines text joined
  together plus actual join operations in the diff (`a + b` with both sides resolved
  through same-diff assignments, and template literals). A token split across lines or
  rebuilt from quoted fragments fails the scan. Mere adjacency without a join operator
  is NOT flagged: concatenating neighboring literals fabricated tokens that do not exist
  in the source (it once blocked a JSON env dump, where `"1"` + `"PATH"` + the PATH
  value formed a 40-character slash run tripping the AWS-secret shape).
- **Churn override (maintainer-only, audited).** When a run blocks ONLY on the churn-size
  heuristic — e.g. a legitimate 30-line helper with no relation to the wish — the
  maintainer can attest the unrelated files are legitimate, either up front
  (`allowChurn` on approve) or after the block
  (`POST /api/runs/:id/retry-with-churn-override`). The override is recorded on the run
  record (`allow_churn`), audited (`run_retried_with_churn_override`), and noted in the
  PR body. It downgrades ONLY the size heuristic to flagged: an unrelated file with a
  new outbound call (the backdoor shape) still blocks, and non-maintainers are refused
  (403). The automatic retry runs first, so the override applies once that retry has
  also blocked and the wish is back in `open`.

## Honest limits — read these before you trust a WishShip PR

1. **Voting integrity stops at a determined Sybil attacker with aged accounts.** The MVP
   defends with one-GitHub-account-one-vote, a 30-day account-age floor (maintainer-
   configurable, displayed on the board), eligibility modes, rate limits, a public ledger,
   derived counts, anomaly flags, and the maintainer approval gate. A patient attacker farming
   aged accounts can still vote. The maintainer gate is the backstop, not a cure.
2. **The MVP sandbox is worktree-level isolation plus env hygiene, not a security boundary.**
   The agent can reach the network (it needs its model API). The PR review step is the
   security boundary for what actually ships. Read this plainly: in the compose deployment
   agents run as subprocesses **inside the app container** — compose does **not** run them
   in a separate container. A same-UID agent can read service environment (including
   `SESSION_SECRET`, `ENCRYPTION_KEY`, and `DATABASE_URL`) via `/proc/<pid>/environ`, and
   can read the service's source clone only after the installation token is stripped from
   it (the clone's remote is removed and `FETCH_HEAD` deleted immediately after cloning).
   Use branch protection on target repos so a compromised run cannot push outside the PR
   flow, and treat per-run containers with a different UID plus egress allowlisting as the
   v1.1 fix — they are not v1. Mandatory per-run containers and egress allowlisting remain
   the real sandbox fix; the worktree-level sandbox does not confine network access.
3. **"Verified" means the checks ran with the reported results.** It does not mean the code
   is correct, secure, or free of subtle backdoors. A second-model review is advisory only,
   and no deterministic check catches every malicious pattern. A repo with no test suite gets
   a `PARTIAL` PR labeled `no-test-suite` — not blocked, and not lied about.
4. **Agent PR quality is the product's core risk.** If maintainers routinely reject the PRs,
   the loop is not worth running. Draft PRs, small diffs, verification reports, and rejection
   reasons fed back to voters exist to keep the accept rate high.
5. **Cost per shipped feature is real and visible** in the PR body and the run record.
   Small repos with few voters may find the cost exceeds the value — the maintainer-pick
   bypass exists for exactly that case.
6. **Self-host-first, not SaaS.** v1 has no billing and no multi-tenant hardening. You run
   it, you bring your own agent credentials. Upvotes only, no downvotes. Draft PRs by default
   (per-repo override to open ready). Second-model review is advisory only. The audit log is
   a plain append-only table, not a hash chain — the threat model here is community
   transparency, not tamper-evidence against a store-writing attacker.

## Quick start

### Docker Compose (recommended)

```sh
SESSION_SECRET="$(openssl rand -hex 32)" \
ENCRYPTION_KEY="$(openssl rand -hex 32)" \
GITHUB_OAUTH_CLIENT_ID="..." GITHUB_OAUTH_CLIENT_SECRET="..." \
GITHUB_APP_ID="..." GITHUB_APP_PRIVATE_KEY="$(cat app-private-key.pem)" \
BASE_URL="https://wishship.example.com" \
docker compose up --build
```

Then open `http://localhost:3000`, sign in with GitHub, and link a repo (install the GitHub
App on the repo first, then link it with the installation id).

### Bare metal

Requirements: Node 22+ LTS, Postgres 16+, git.

```sh
npm install
npm run build
DATABASE_URL="postgres://wishship:secret@localhost:5432/wishship" \
SESSION_SECRET="..." ENCRYPTION_KEY="<32 bytes hex>" \
npm start
```

### Agent backends

Two CLI adapters ship in v1, plus a script escape hatch:

- `claude` — Claude Code CLI (`CLAUDE_COMMAND` overrides the default invocation).
- `codex` — Codex CLI (`CODEX_COMMAND` overrides).
- `script` — an operator-provided shell command (`SCRIPT_BACKEND_COMMAND`) that receives the
  task spec JSON on stdin and runs in the worktree. It may print `WISHSHIP_COST: <usd>` for
  cost reporting. An optional `SCRIPT_REVIEW_COMMAND` receives `{spec, diff}` JSON on stdin
  and prints one review concern per line (advisory).

The task spec is a structured JSON document: the wish body sits in a data field, never
concatenated into instructions, and the system prompt states the instruction hierarchy
(system > developer constraints > wish data). Verification commands come from repo config
only — a wish claiming a malicious test command has zero effect on what actually runs.
Verification commands are discovered from the **base commit before the agent runs** and
passed into verification; they are never re-discovered from the patched tree, so an agent
that rewrites the test script to a no-op cannot grade its own homework. Second-model
review reuses the run argv with the review prompt written to a file passed as `{spec}` —
the wish title never appears in argv, and the review runs in a fresh scratch HOME, never
the operator's real HOME.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://wishship:wishship-dev@127.0.0.1:5432/wishship` | Postgres connection |
| `SESSION_SECRET` | — (fail-closed, see below) | HMAC key for session cookies |
| `ENCRYPTION_KEY` | — (fail-closed, see below) | 32 bytes hex, AES-256-GCM key for stored secrets |
| `BASE_URL` | `http://localhost:3000` | Public URL (OAuth redirect) |
| `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_OAUTH_CLIENT_SECRET` | — | GitHub OAuth app |
| `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_APP_SLUG` | — | GitHub App (installation tokens, PRs) |
| `GITHUB_CLIENT=fake` | — | Dev-only in-memory GitHub client; never in production |
| `RUN_TIMEOUT_MINUTES` | `30` | Wall-clock timeout per run (process group killed) |
| `MAX_CONCURRENT_RUNS` | `2` | Cross-repo concurrency (one active run per repo always) |
| `RUN_COST_CAP_USD` | — | Per-run cost cap, post-hoc and only for cost-reporting backends (script backend via `WISHSHIP_COST`; CLI backends report no cost, so the cap never applies to them — they are time-bounded only). An overrun blocks the PR, it does not stop spend already incurred. |
| `REPO_MONTHLY_BUDGET_USD` | — | Monthly budget per repo: a **pre-run gate, not a hard cap**. A run that starts under budget can push spend over it; costs are recorded on failed runs too, so the gate sees real totals. |
| `OPERATOR_LOGINS` | — | Comma-separated logins allowed on operator controls |
| `AGENT_HOME` | temp dir | HOME fallback for agent processes; every run overrides it with a fresh per-run temp dir, deleted when the run finishes |
| `AGENT_ENV_PASSTHROUGH` | — | Extra env vars passed to agents (denylist always wins; any `*TOKEN*` / `*SECRET*` / `*PASSWORD*` / `*CREDENTIAL*` name or `*_KEY` suffix is blocked by pattern) |

**Fail-closed secrets:** dev fallbacks for `SESSION_SECRET` / `ENCRYPTION_KEY` apply only
when `NODE_ENV` is explicitly `development`. With `NODE_ENV=production` and no secret, the
service refuses to boot; with `NODE_ENV` unset and no secret, it also refuses to boot —
a bare-metal deploy can never silently run on a publicly known dev secret. The compose
file already requires both variables, and the Dockerfile sets `NODE_ENV=production`.

Per-repo settings (cycle length — cycles are closed manually in v1, there is no automatic
timer; vote threshold, age floor 0–365 days, eligibility mode
`any` / `stargazers` / `contributors` / `allowlist`, diff limits, draft-vs-ready, extra task
constraints) are edited by maintainers via `PUT /api/repos/:id/config` and the board UI.

## Architecture

```
React SPA (Vite) ──► Fastify API ──► Postgres
                        │  ├─ repos / wishes / votes (ledger, counts derived)
                        │  ├─ cycles / winners (approval gate)
                        │  ├─ runs / verification_reports / prs
                        │  ├─ jobs (DB-backed queue, SKIP LOCKED claims)
                        │  └─ audit_events (append-only)
                        │
                        ├─ Worker: claim job → temp worktree → agent CLI
                        │   (scrubbed env, process-group kill, file-redirected
                        │    output) → clean-checkout verification → draft PR
                        │
                        └─ GitHub App: installation tokens per operation,
                           never stored; PR branch service-created, never
                           agent-pushed; agent worktree has no remote.
```

**Verification tiers:** `VERIFIED` (every applicable check passed), `PARTIAL` (nothing failed,
something couldn't run — e.g. no test suite), `BLOCKED` (any check failed or hard rule
tripped — no PR, exactly one retry with verifier feedback, then dead).

**Checks:** tests / lint / typecheck from repo config only, discovered at the base commit
before the agent runs and never re-discovered from the patched tree; secret scan on added
lines (shape-based: it catches known token shapes, not split tokens or shapeless
high-entropy blobs); diff-size limit (default 500 lines / 20 files, BLOCKED not trimmed);
unrelated-churn check — a file counts as related on path-token overlap or on a token from
its non-comment added lines, so a keyword comment alone no longer counts; an unrelated
file with a new outbound call BLOCKS, and a single unrelated file with 20+ added lines
BLOCKS; dependency, script, and lockfile changes BLOCKED by default (version changes and
nested manifests included; maintainer may allow a retry with dependencies permitted); new
outbound hosts flagged, not blocked, where the baseline counts hosts only at actual
network-call sites in the base tree (a host merely mentioned in a comment does not count);
dynamically constructed URLs are flagged as `dynamic-url`; second-model review advisory
only; outside-worktree writes flagged (weak check, honestly labeled).

**Queue:** one worker process, `SKIP LOCKED` claims, one active run per repo, bounded
cross-repo concurrency. Crash recovery re-queues jobs whose run is still `queued`,
fails stale `running`/`verifying` runs, and carries attempt counts across the recovery
chain so the attempts guard bounds the whole chain; the stale threshold is
`max(30min, runTimeout + 10min)` so a long legitimate run is never "recovered"
mid-flight. The worker re-validates run state immediately before opening a PR, so a
recovered-while-in-flight run cannot open a second PR. Redis/BullMQ is the documented
first scaling step, not a v1 dependency.

**Approval surface:** the pending-approval response carries the cycle's anomaly data
(window votes, total votes, share, account span, window start) and the board UI renders it
prominently — an anomaly is a warning, not a block. A wish whose body contains
secret-shaped material is flagged at submission and the body is withheld from the PR body
entirely; otherwise the wish body is blockquoted so it cannot spoof the verification
section. Every PR body lists its changed files.

**Reads are public by design:** the board, run records, audit view, and export are
unauthenticated — transparency is the premise. Run records include capped (500-char)
failure-log excerpts of agent output; do not paste secrets into wishes or agent prompts.

**PR decisions are maintainer-attested bookkeeping:** the service does not query GitHub
for merge state — the maintainer's click is the record, which keeps the endpoint
offline-testable and avoids a new API surface. Merged/shipped states are terminal and
reject further transitions, and a linked-issue comment is posted only when the issue's
repo matches the board's repo.

**Injection flagging is English-first:** it covers common instruction-override phrasings
("ignore all previous instructions", "forget everything above", "pretend/roleplay",
"developer mode", base64-encoded instructions, "do not follow", "include the API key") plus
a small set of Spanish/French/German/Portuguese variants — not a multilingual guarantee.
A flagged wish still runs, with the flag carried on the agent spec.

**States worth knowing:** a wish whose first verification BLOCKS stays `implementing`
while its one retry is queued — there is no separate `retrying` state in v1; the run
record and audit show the retry chain. Global pause gates new claims **and** PR opening,
so an in-flight run cannot open a PR after the operator pauses.

## Deployment notes

- **Agents run inside the app container (compose).** The compose deployment does **not**
  run agent backends in a separate container: they are subprocesses of the service, under
  the same UID. That means a malicious agent can read service environment via
  `/proc/<pid>/environ` (see Honest limits §2). If you need stronger isolation before
  v1.1, run the service itself in a throwaway environment with no other credentials on
  the host, and keep branch protection on every target repo. Per-run containers with a
  different UID plus egress allowlisting are the v1.1 fix.
- **GitHub App permissions (minimal):** contents write + pull requests only. No admin, no
  secrets access. Use branch protection on target repos.
- **Kill switches (all one-click, all audited):** pause a repo's cycles, disconnect a repo
  (revokes the installation), global pause on agent runs (operator page). Re-linking a
  disconnected repo does **not** re-enable it — only an explicit maintainer reconnect
  does, and linking a repo requires the caller to be a maintainer of that repo.
- **Verification gaps (stated, not hidden):** `docker compose up` was never
  boot-verified in the development environment used for this build (no Docker
  there), and the real GitHub App push path has only ever run against the
  in-memory FakeGitHub client, never against a real repo. Verify both on a
  machine with Docker and a real GitHub App installation before trusting a
  production deployment.
- **Secrets:** installation tokens are short-lived and never stored. The service clone's
  token-bearing remote is stripped immediately after cloning, and token URLs are scrubbed
  from git error output. Stored operator secrets are encrypted at rest (AES-256-GCM, key
  from environment). KMS integration is out of v1 — the operator key is the documented
  trust point.

## Development

```sh
npm install
npm run build        # server (dist/) + client (client/dist/)
npm test             # needs Postgres; per-process test DBs (see below)
npm run typecheck
npm run lint         # eslint + stale-artifact check (no .js/.d.ts next to .ts)
```

Tests use a real Postgres database: each test process gets its own database
(`wishship_test_<pid>`, user `wishship`, created on demand from `TEST_DATABASE_URL` or
the default `wishship_test` base URL) so test files cannot wipe each other's in-flight
data. Start Postgres 16 locally and create the user, or point `TEST_DATABASE_URL` at
your own instance (see `src/server/testutil.ts`).

```sh
# Ubuntu example
sudo apt-get install -y postgresql
sudo pg_ctlcluster 16 main start
sudo -u postgres psql -c "CREATE USER wishship PASSWORD 'wishship-dev';"
sudo -u postgres psql -c "CREATE DATABASE wishship_test OWNER wishship;"
```

## FAQ

**Why two human gates?** Because a fully automatic loop is a brigading machine that burns
model money on junk and opens PRs nobody asked for in good faith. The maintainer approves
the winner before any agent runs, and reviews the PR before anything merges. An opt-in
auto-run mode for explicitly trusted repos is a possible v1.1 variant, default off.

**Why upvotes only?** Downvotes would let brigades bury legitimate wishes and would double
the gaming surface — downvote brigades are cheaper than upvote brigades. The maintainer's
rejection reason is the substitute for "please don't build this".

**Why does a repo with no tests still get a PR?** Blocking it would make WishShip useless
on exactly the small repos that are its target market. The PR opens as `PARTIAL`, labeled
`no-test-suite`, with the gap named in the body — the maintainer sees it, not buried in a log.

**Can the agent merge?** No. Auto-merge is out of v1 entirely. The agent holds no GitHub
token and its worktree has no remote; only the service opens (draft) PRs.

**What happens when a PR is rejected?** The wish returns to `open` (or `rejected` if the
maintainer says so) with the reason recorded and visible to voters. Nothing auto-reruns.
Rejection reasons are the feedback loop that keeps the product honest.

**What about monorepos?** Works if the repo exposes one test command; otherwise `PARTIAL`.
Monorepo special-casing is out of v1.

## Roadmap (v1.1 candidates, not promises)

- Opt-in auto-run mode for explicitly trusted repos (default off).
- Per-run containers as mandatory; egress allowlisting (model API + registry only).
  Until then, two residuals stand: a same-UID agent can read service env via
  `/proc/<pid>/environ`, and `setsid` descendants of an agent process survive the
  timeout's process-group kill (normal children are killed).
- AgentCred attestation: "this PR was produced by agent X under spec version Y", verifiable.
- Hash-chained audit log, if a customer asks for tamper-evidence.
- Webhooks for live updates (v1 polls; webhooks add a signature-verification surface).
- Email/Slack notifications; agent change-request iteration on PRs.
- Embedded direct-model API backends (CLI adapters first by design).

## License

Apache 2.0. See [LICENSE](LICENSE).

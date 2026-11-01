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
6. **Draft PR (human gate 2).** Only `VERIFIED` or `PARTIAL` reports open a PR, and it opens
   as a **draft** carrying the full report. The maintainer reviews, merges, or closes it.

## Honest limits — read these before you trust a WishShip PR

1. **Voting integrity stops at a determined Sybil attacker with aged accounts.** The MVP
   defends with one-GitHub-account-one-vote, a 30-day account-age floor (maintainer-
   configurable, displayed on the board), eligibility modes, rate limits, a public ledger,
   derived counts, anomaly flags, and the maintainer approval gate. A patient attacker farming
   aged accounts can still vote. The maintainer gate is the backstop, not a cure.
2. **The MVP sandbox is worktree-level isolation plus env hygiene, not a security boundary.**
   The agent can reach the network (it needs its model API). The PR review step is the
   security boundary for what actually ships. Run agent backends containerized (see
   Deployment) — per-run containers as mandatory and egress allowlisting are v1.1.
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

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `postgres://wishship:wishship-dev@127.0.0.1:5432/wishship` | Postgres connection |
| `SESSION_SECRET` | (dev fallback; required in prod) | HMAC key for session cookies |
| `ENCRYPTION_KEY` | (dev fallback; required in prod) | 32 bytes hex, AES-256-GCM key for stored secrets |
| `BASE_URL` | `http://localhost:3000` | Public URL (OAuth redirect) |
| `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_OAUTH_CLIENT_SECRET` | — | GitHub OAuth app |
| `GITHUB_APP_ID` / `GITHUB_APP_PRIVATE_KEY` / `GITHUB_APP_SLUG` | — | GitHub App (installation tokens, PRs) |
| `GITHUB_CLIENT=fake` | — | Dev-only in-memory GitHub client; never in production |
| `RUN_TIMEOUT_MINUTES` | `30` | Wall-clock timeout per run (process group killed) |
| `MAX_CONCURRENT_RUNS` | `2` | Cross-repo concurrency (one active run per repo always) |
| `RUN_COST_CAP_USD` | — | Per-run cost cap where the backend reports usage |
| `REPO_MONTHLY_BUDGET_USD` | — | Monthly budget per repo; exhausted cycles queue but do not run |
| `OPERATOR_LOGINS` | — | Comma-separated logins allowed on operator controls |
| `AGENT_HOME` | temp dir | HOME dir for agent processes (backend CLI config lives here) |
| `AGENT_ENV_PASSTHROUGH` | — | Extra env vars passed to agents (denylist always wins) |

Per-repo settings (cycle length, vote threshold, age floor 0–365 days, eligibility mode
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

**Checks:** tests / lint / typecheck from repo config only; secret scan on added lines;
diff-size limit (default 500 lines / 20 files, BLOCKED not trimmed); unrelated-churn check
(flagged, BLOCKED only when unrelated lines are the majority across 2+ files); dependency and
lockfile changes BLOCKED by default (maintainer may allow a retry with dependencies
permitted); new outbound hosts flagged, not blocked; second-model review advisory only;
outside-worktree writes flagged (weak check, honestly labeled).

**Queue:** one worker process, `SKIP LOCKED` claims, one active run per repo, bounded
cross-repo concurrency. Redis/BullMQ is the documented first scaling step, not a v1
dependency.

## Deployment notes

- **Containerized runs (recommended).** The compose deployment runs the service in a
  container; run agent backends inside a container with no volume mounts beyond the worktree
  and no access to the host's credentials. The worktree-level sandbox does not confine
  network access — treat PR review as the security boundary.
- **GitHub App permissions (minimal):** contents write + pull requests only. No admin, no
  secrets access. Use branch protection on target repos.
- **Kill switches (all one-click, all audited):** pause a repo's cycles, disconnect a repo
  (revokes the installation), global pause on agent runs (operator page).
- **Secrets:** installation tokens are short-lived and never stored. Stored operator secrets
  are encrypted at rest (AES-256-GCM, key from environment). KMS integration is out of v1 —
  the operator key is the documented trust point.

## Development

```sh
npm install
npm run build        # server (dist/) + client (client/dist/)
npm test             # needs Postgres; uses wishship_test (see below)
npm run typecheck
npm run lint         # eslint + stale-artifact check (no .js/.d.ts next to .ts)
```

Tests use a real Postgres database (`wishship_test`, user `wishship`). Start Postgres 16
locally and create it, or point `TEST_DATABASE_URL` at your own instance (the test helper
reads the fixed `wishship_test` URL — see `src/server/testutil.ts`).

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
- AgentCred attestation: "this PR was produced by agent X under spec version Y", verifiable.
- Hash-chained audit log, if a customer asks for tamper-evidence.
- Webhooks for live updates (v1 polls; webhooks add a signature-verification surface).
- Email/Slack notifications; agent change-request iteration on PRs.
- Embedded direct-model API backends (CLI adapters first by design).

## License

Apache 2.0. See [LICENSE](LICENSE).

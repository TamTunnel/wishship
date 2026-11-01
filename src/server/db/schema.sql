-- WishShip schema (Postgres 16+). Applied idempotently on boot.
-- The vote ledger is the truth: counts are always COUNT(*) over votes,
-- never a mutable counter. There is deliberately no count-editing endpoint.

CREATE TABLE IF NOT EXISTS users (
  id BIGINT PRIMARY KEY,
  login TEXT NOT NULL,
  avatar_url TEXT NOT NULL DEFAULT '',
  account_created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS repos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT NOT NULL,
  full_name TEXT NOT NULL UNIQUE,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  paused BOOLEAN NOT NULL DEFAULT false,
  disconnected BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wishes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id UUID NOT NULL REFERENCES repos(id),
  author_id BIGINT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  linked_issue_url TEXT,
  state TEXT NOT NULL DEFAULT 'open'
    CHECK (state IN ('open','proposed','approved','implementing','pr_open','shipped','rejected','hidden','needs_input')),
  injection_flag BOOLEAN NOT NULL DEFAULT false,
  injection_patterns TEXT[] NOT NULL DEFAULT '{}',
  -- Secret-shaped material in the wish body, flagged at submission (not
  -- blocking: flagging, not censorship). The PR body withholds flagged
  -- bodies instead of quoting them verbatim.
  secret_flag BOOLEAN NOT NULL DEFAULT false,
  secret_patterns TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS wishes_repo_state_idx ON wishes (repo_id, state);
-- Added after v1: backfill for databases created before these columns.
ALTER TABLE wishes ADD COLUMN IF NOT EXISTS secret_flag BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE wishes ADD COLUMN IF NOT EXISTS secret_patterns TEXT[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS wishes_title_body_idx ON wishes USING gin (to_tsvector('english', title || ' ' || body));

CREATE TABLE IF NOT EXISTS votes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  wish_id UUID NOT NULL REFERENCES wishes(id),
  voter_id BIGINT NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  withdrawn_at TIMESTAMPTZ
);
-- One live vote per (wish, voter). Re-vote after withdrawal creates a new
-- row so history is preserved; the partial unique index enforces it.
CREATE UNIQUE INDEX IF NOT EXISTS votes_live_unique_idx
  ON votes (wish_id, voter_id) WHERE withdrawn_at IS NULL;
CREATE INDEX IF NOT EXISTS votes_wish_idx ON votes (wish_id);

CREATE TABLE IF NOT EXISTS cycles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  repo_id UUID NOT NULL REFERENCES repos(id),
  opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at TIMESTAMPTZ,
  anomaly_suspected BOOLEAN NOT NULL DEFAULT false,
  anomaly_details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cycle_winners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cycle_id UUID NOT NULL REFERENCES cycles(id),
  wish_id UUID NOT NULL REFERENCES wishes(id),
  state TEXT NOT NULL DEFAULT 'pending_approval'
    CHECK (state IN ('pending_approval','approved','rejected')),
  approver_id BIGINT REFERENCES users(id),
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  winner_id UUID NOT NULL REFERENCES cycle_winners(id),
  backend TEXT NOT NULL,
  spec_version INT NOT NULL DEFAULT 1,
  state TEXT NOT NULL DEFAULT 'queued'
    CHECK (state IN ('queued','running','verifying','pr_opened','failed','blocked')),
  worktree_commit TEXT,
  duration_ms INT,
  cost_usd NUMERIC(12,4),
  allow_dependencies BOOLEAN NOT NULL DEFAULT false,
  allow_churn BOOLEAN NOT NULL DEFAULT false,
  failure_reason TEXT,
  retry_of UUID REFERENCES runs(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);

-- Churn override, added after the runs table shipped: IF NOT EXISTS
-- keeps this a no-op on fresh databases (which get the column inline
-- above) and backfills databases created before the column existed.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS allow_churn BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS verification_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL UNIQUE REFERENCES runs(id),
  tier TEXT NOT NULL CHECK (tier IN ('VERIFIED','PARTIAL','BLOCKED')),
  checks JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One winner per (cycle, wish): close-and-propose and maintainer-pick
-- race safely against this instead of relying on a state pre-check.
-- (Placed after the tables: a fresh-DB migrate aborts if an index
-- references a table defined later in this file.)
CREATE UNIQUE INDEX IF NOT EXISTS cycle_winners_cycle_wish_idx
  ON cycle_winners (cycle_id, wish_id);
-- One active run per winner: the backstop behind createRunForWinner's
-- FOR UPDATE serialization. Terminal states (pr_opened/failed/blocked)
-- do not count, so retries and recovery runs are still possible.
CREATE UNIQUE INDEX IF NOT EXISTS runs_active_winner_idx
  ON runs (winner_id) WHERE state IN ('queued','running','verifying');

CREATE TABLE IF NOT EXISTS prs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id UUID NOT NULL REFERENCES runs(id),
  repo_id UUID NOT NULL REFERENCES repos(id),
  number INT NOT NULL,
  url TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'draft'
    CHECK (state IN ('draft','open','merged','closed')),
  branch TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only by convention: no code path updates or deletes rows here.
CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  before_state JSONB,
  after_state JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_entity_idx ON audit_events (entity_type, entity_id);

-- DB-backed job queue. No Redis in v1 (documented scaling limit).
CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind TEXT NOT NULL DEFAULT 'run',
  run_id UUID NOT NULL REFERENCES runs(id),
  repo_id UUID NOT NULL REFERENCES repos(id),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','claimed','done','failed')),
  attempts INT NOT NULL DEFAULT 0,
  claimed_at TIMESTAMPTZ,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs (status, created_at);

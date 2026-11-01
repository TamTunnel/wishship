import { useCallback, useEffect, useState } from "react";

interface User {
  id: number;
  login: string;
}

interface Repo {
  id: string;
  full_name: string;
  config: Record<string, unknown>;
  paused: boolean;
  disconnected: boolean;
}

interface BoardWish {
  id: string;
  title: string;
  body: string;
  state: string;
  author_id: number;
  injection_flag: boolean;
  injection_patterns: string[];
  created_at: string;
  vote_count: number;
  voters: { id: number; login: string }[];
}

interface BoardData {
  repo: Repo;
  board: BoardWish[];
  cycle: { id: string; opened_at: string } | null;
  pending: {
    id: string;
    wish_id: string;
    wish: BoardWish;
    state: string;
  } | null;
}

interface RunRow {
  id: string;
  state: string;
  backend: string;
  wish_title: string;
  report: { tier: string; checks: { name: string; status: string; detail: string }[] } | null;
  pr: { number: number; url: string; state: string } | null;
}

async function api(path: string, init?: RequestInit): Promise<{ status: number; body: any }> {
  const res = await fetch(path, { credentials: "include", ...init });
  let body: any = {};
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  return { status: res.status, body };
}

function useHashRoute(): string {
  const [hash, setHash] = useState(window.location.hash.slice(1) || "/");
  useEffect(() => {
    const onChange = () => setHash(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash;
}

export default function App() {
  const route = useHashRoute();
  const [me, setMe] = useState<User | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/auth/me").then(({ status, body }) => {
      if (status === 200) setMe(body.user);
    });
  }, []);

  const logout = useCallback(async () => {
    await api("/api/auth/logout", { method: "POST" });
    setMe(null);
  }, []);

  const parts = route.split("/").filter(Boolean);
  let view: React.ReactNode = <ReposView me={me} setError={setError} />;
  if (parts[0] === "repo" && parts[1]) {
    view = <BoardView repoId={parts[1]} me={me} setError={setError} />;
  } else if (parts[0] === "operator") {
    view = <OperatorView me={me} setError={setError} />;
  }

  return (
    <div>
      <header>
        <strong>
          <a href="#/">WishShip</a>
        </strong>
        <a href="#/">Boards</a>
        <a href="#/operator">Operator</a>
        <span style={{ flex: 1 }} />
        {me ? (
          <span>
            {me.login} <button onClick={logout}>Log out</button>
          </span>
        ) : (
          <a href="/api/auth/login">
            <button>Sign in with GitHub</button>
          </a>
        )}
      </header>
      <main>
        {error && <div className="error">{error}</div>}
        {view}
      </main>
    </div>
  );
}

function ReposView({ me, setError }: { me: User | null; setError: (s: string) => void }) {
  const [repos, setRepos] = useState<Repo[]>([]);
  const [installationId, setInstallationId] = useState("");
  const [fullName, setFullName] = useState("");

  const load = useCallback(() => {
    api("/api/repos").then(({ body }) => setRepos(body.repos ?? []));
  }, []);
  useEffect(load, [load]);

  const link = async () => {
    setError("");
    const { status, body } = await api("/api/repos/link", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ installationId: Number(installationId), fullName }),
    });
    if (status !== 200) setError(body.error ?? "link failed");
    else load();
  };

  return (
    <div>
      <h1>Wish boards</h1>
      <p className="muted">
        Users submit wishes, vote on them, and each cycle the top-voted wish is proposed to the
        maintainer. Approved winners are implemented by a coding agent and opened as verified draft
        PRs — the maintainer reviews and merges. The agent never merges.
      </p>
      {repos.map((r) => (
        <div className="card" key={r.id}>
          <a href={`#/repo/${r.id}`}>
            <strong>{r.full_name}</strong>
          </a>
          <span className="muted">
            {" "}
            · {r.paused ? "paused" : "active"}
            {r.disconnected ? " · disconnected" : ""}
          </span>
        </div>
      ))}
      {me && (
        <div className="card">
          <h3>Link a repo</h3>
          <p className="muted">
            Install the WishShip GitHub App on the repo first, then link it here with the
            installation id.
          </p>
          <input
            placeholder="Installation id"
            value={installationId}
            onChange={(e) => setInstallationId(e.target.value)}
          />
          <input
            placeholder="owner/repo"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
          />
          <button className="primary" onClick={link}>
            Link repo
          </button>
        </div>
      )}
    </div>
  );
}

function BoardView({
  repoId,
  me,
  setError,
}: {
  repoId: string;
  me: User | null;
  setError: (s: string) => void;
}) {
  const [data, setData] = useState<BoardData | null>(null);
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [audit, setAudit] = useState<any[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [tab, setTab] = useState<"board" | "runs" | "audit" | "config">("board");

  const load = useCallback(() => {
    api(`/api/repos/${repoId}/board`).then(({ body }) => setData(body));
    api(`/api/repos/${repoId}/runs`).then(({ body }) => setRuns(body.runs ?? []));
    api(`/api/repos/${repoId}/audit`).then(({ body }) => setAudit(body.events ?? []));
  }, [repoId]);
  useEffect(load, [load]);

  const act = async (path: string, payload?: unknown) => {
    setError("");
    const { status, body } = await api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    if (status >= 400) setError(body.error ?? `request failed (${status})`);
    load();
  };

  if (!data) return <p>Loading…</p>;
  const { repo, board, pending, anomaly } = data;

  return (
    <div>
      <h1>{repo.full_name}</h1>
      <p className="muted">
        Votes are public. Eligibility: {String(repo.config.eligibilityMode)} · age floor{" "}
        {String(repo.config.ageFloorDays)} days · threshold {String(repo.config.minVotes)} votes
        {repo.paused ? " · PAUSED" : ""}
      </p>
      <div className="row" style={{ marginBottom: 12 }}>
        <button onClick={() => setTab("board")}>Board</button>
        <button onClick={() => setTab("runs")}>Runs</button>
        <button onClick={() => setTab("audit")}>Audit</button>
        <button onClick={() => setTab("config")}>Maintainer</button>
      </div>

      {pending && (
        <div className="card">
          <h3>Pending approval</h3>
          <p>
            <strong>{pending.wish.title}</strong> — awaiting maintainer approval before any agent
            runs.
          </p>
          {anomaly?.suspected && (
            <p>
              <span className="flag">
                ⚠ Anomaly suspected in this cycle&apos;s votes:{" "}
                {String(anomaly.details?.windowVotes ?? "?")} of{" "}
                {String(anomaly.details?.totalVotes ?? "?")} votes (
                {String(
                  Math.round(((anomaly.details?.share as number | undefined) ?? 0) * 100),
                )}
                %) arrived within one hour from accounts created within{" "}
                {String(anomaly.details?.accountSpanDays ?? "?")} days of each other
                (window start {String(anomaly.details?.windowStart ?? "?")}). This is a
                warning, not a block — approve only if the votes look genuine.
              </span>
            </p>
          )}
          <div className="row">
            <button
              className="primary"
              onClick={() => act(`/api/winners/${pending.id}/approve`, { backend: "script" })}
            >
              Approve &amp; run agent
            </button>
            <button onClick={() => act(`/api/winners/${pending.id}/reject`, { reason: "" })}>
              Reject
            </button>
          </div>
        </div>
      )}

      {tab === "board" && (
        <div>
          <div className="row" style={{ marginBottom: 12 }}>
            <button onClick={() => act(`/api/repos/${repoId}/cycles/close`)}>
              Close cycle &amp; propose winner
            </button>
          </div>
          {board.map((w) => (
            <div className="card" key={w.id}>
              <div className="row">
                <strong>{w.title}</strong>
                <span className={`state ${w.state}`}>{w.state}</span>
                <span className="muted">
                  {w.vote_count} vote{w.vote_count === 1 ? "" : "s"}
                </span>
              </div>
              <p>{w.body}</p>
              {w.injection_flag && (
                <p>
                  <span className="flag">
                    Flagged: {w.injection_patterns.join(", ")} — wish text is data, not instructions.
                  </span>
                </p>
              )}
              {w.secret_flag && (
                <p>
                  <span className="flag">
                    Flagged: possible secret-shaped material ({w.secret_patterns.join(", ")}) —
                    withheld from PR bodies; scrub before approving.
                  </span>
                </p>
              )}
              <p className="muted">Voters: {w.voters.map((v) => v.login).join(", ") || "none"}</p>
              {me && (
                <div className="row">
                  <button onClick={() => act(`/api/wishes/${w.id}/vote`)}>Upvote</button>
                  <button onClick={() => act(`/api/wishes/${w.id}/unvote`)}>Withdraw vote</button>
                  <button onClick={() => act(`/api/wishes/${w.id}/hide`)}>Hide (maintainer)</button>
                  <button onClick={() => act(`/api/repos/${repoId}/pick`, { wishId: w.id })}>
                    Pick (maintainer)
                  </button>
                </div>
              )}
            </div>
          ))}
          {me && (
            <div className="card">
              <h3>Submit a wish</h3>
              <input placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
              <textarea
                placeholder="Describe the feature…"
                rows={4}
                value={body}
                onChange={(e) => setBody(e.target.value)}
              />
              <button
                className="primary"
                onClick={() => {
                  act(`/api/repos/${repoId}/wishes`, { title, body }).then(() => {
                    setTitle("");
                    setBody("");
                  });
                }}
              >
                Submit
              </button>
            </div>
          )}
        </div>
      )}

      {tab === "runs" && (
        <div>
          {runs.map((r) => (
            <div className="card" key={r.id}>
              <div className="row">
                <strong>{r.wish_title}</strong>
                <span className="state">{r.state}</span>
                <span className="muted">{r.backend}</span>
                {r.pr && (
                  <a href={r.pr.url} target="_blank" rel="noreferrer">
                    PR #{r.pr.number} ({r.pr.state})
                  </a>
                )}
              </div>
              {r.report && (
                <table>
                  <thead>
                    <tr>
                      <th>Check</th>
                      <th>Result</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.report.checks.map((c) => (
                      <tr key={c.name}>
                        <td>{c.name}</td>
                        <td>{c.status}</td>
                        <td>{c.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {r.state === "pr_opened" && r.pr && (
                <div className="row" style={{ marginTop: 8 }}>
                  <button onClick={() => act(`/api/runs/${r.id}/pr-decision`, { outcome: "merged" })}>
                    Mark merged
                  </button>
                  <button
                    onClick={() =>
                      act(`/api/runs/${r.id}/pr-decision`, { outcome: "rejected", reason: "" })
                    }
                  >
                    Mark rejected
                  </button>
                  <button
                    onClick={() =>
                      act(`/api/runs/${r.id}/pr-decision`, { outcome: "rework", reason: "" })
                    }
                  >
                    Send back (rework)
                  </button>
                </div>
              )}
              {r.state === "blocked" && (
                <button
                  onClick={() => act(`/api/runs/${r.id}/retry-with-deps`)}
                >
                  Retry with dependencies permitted
                </button>
              )}
            </div>
          ))}
          {runs.length === 0 && <p className="muted">No runs yet.</p>}
        </div>
      )}

      {tab === "audit" && (
        <div>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Entity</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((e: any) => (
                <tr key={e.id}>
                  <td>{new Date(e.created_at).toLocaleString()}</td>
                  <td>{e.actor_id}</td>
                  <td>{e.action}</td>
                  <td>
                    {e.entity_type}:{String(e.entity_id).slice(0, 8)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === "config" && (
        <div className="card">
          <h3>Maintainer controls</h3>
          <div className="row">
            <button onClick={() => act(`/api/repos/${repoId}/pause`, { paused: !repo.paused })}>
              {repo.paused ? "Resume cycles" : "Pause cycles"}
            </button>
            <button onClick={() => act(`/api/repos/${repoId}/disconnect`)}>
              Disconnect repo
            </button>
            <a href={`/api/repos/${repoId}/export`} target="_blank" rel="noreferrer">
              <button>Export JSON</button>
            </a>
          </div>
          <p className="muted">
            Thresholds, eligibility mode, and diff limits are configurable via the API
            (PUT /api/repos/{repo.id}/config). Kill switches: pause cycles, disconnect the repo,
            or use the operator global pause.
          </p>
        </div>
      )}
    </div>
  );
}

function OperatorView({ me, setError }: { me: User | null; setError: (s: string) => void }) {
  const [data, setData] = useState<any>(null);
  const load = useCallback(() => {
    api("/api/operator").then(({ status, body }) => {
      if (status === 200) setData(body);
      else setError(body.error ?? "operator page unavailable");
    });
  }, [setError]);
  useEffect(load, [load]);
  if (!data) return <p>Loading…</p>;
  return (
    <div>
      <h1>Operator</h1>
      <p className="muted">
        Health, queue, and monthly spend. Global pause stops all agent runs immediately.
      </p>
      <div className="card">
        <p>
          Global pause: <strong>{data.globalPaused ? "ON" : "off"}</strong>
        </p>
        <button
          onClick={() =>
            api("/api/operator/global-pause", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ paused: !data.globalPaused }),
            }).then(load)
          }
        >
          {data.globalPaused ? "Resume all runs" : "Pause all runs"}
        </button>
      </div>
      <div className="card">
        <h3>Queue ({data.queue.length})</h3>
        {data.queue.map((j: any) => (
          <p key={j.id} className="muted">
            {j.run_id.slice(0, 8)} · {j.status} · attempts {j.attempts}
          </p>
        ))}
        {data.queue.length === 0 && <p className="muted">Queue empty.</p>}
      </div>
      <div className="card">
        <h3>Monthly spend</h3>
        {data.monthlySpend.map((s: any) => (
          <p key={s.repo_id} className="muted">
            {s.repo_id.slice(0, 8)} · ${s.spend} · {s.runs} runs
          </p>
        ))}
      </div>
      {!me && <p className="muted">Sign in to use operator controls.</p>}
    </div>
  );
}

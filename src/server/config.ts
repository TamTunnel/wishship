import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

export interface WishShipConfig {
  port: number;
  host: string;
  databaseUrl: string;
  sessionSecret: string;
  baseUrl: string;
  githubOAuthClientId: string;
  githubOAuthClientSecret: string;
  githubAppId: string;
  githubAppPrivateKey: string;
  githubAppSlug: string;
  encryptionKey: Buffer;
  worktreeRoot: string;
  agentHome: string;
  agentEnvPassthrough: string[];
  runTimeoutMs: number;
  maxConcurrentRuns: number;
  runCostCapUsd: number | null;
  repoMonthlyBudgetUsd: number | null;
  isProduction: boolean;
}

function env(name: string, fallback = ""): string {
  return process.env[name] ?? fallback;
}

function devSecret(kind: string): string {
  if (process.env.NODE_ENV === "production") {
    throw new Error(`${kind} is required in production`);
  }
  // Dev-only fallback. Never used when NODE_ENV=production.
  return `wishship-dev-${kind}`;
}

export function loadConfig(): WishShipConfig {
  const encryptionHex = env("ENCRYPTION_KEY", "");
  let encryptionKey: Buffer;
  if (encryptionHex) {
    encryptionKey = Buffer.from(encryptionHex, "hex");
    if (encryptionKey.length !== 32) {
      throw new Error("ENCRYPTION_KEY must be 32 bytes, hex-encoded");
    }
  } else if (process.env.NODE_ENV === "production") {
    throw new Error("ENCRYPTION_KEY is required in production");
  } else {
    // Dev-only deterministic key; operator key is the documented trust point.
    encryptionKey = Buffer.alloc(32, 7);
  }
  return {
    port: Number(env("PORT", "3000")),
    host: env("HOST", "0.0.0.0"),
    databaseUrl: env(
      "DATABASE_URL",
      "postgres://wishship:wishship-dev@127.0.0.1:5432/wishship",
    ),
    sessionSecret: env("SESSION_SECRET", devSecret("session")),
    baseUrl: env("BASE_URL", "http://localhost:3000"),
    githubOAuthClientId: env("GITHUB_OAUTH_CLIENT_ID", ""),
    githubOAuthClientSecret: env("GITHUB_OAUTH_CLIENT_SECRET", ""),
    githubAppId: env("GITHUB_APP_ID", ""),
    githubAppPrivateKey: env("GITHUB_APP_PRIVATE_KEY", ""),
    githubAppSlug: env("GITHUB_APP_SLUG", "wishship"),
    encryptionKey,
    worktreeRoot: env("WORKTREE_ROOT", join(tmpdir(), "wishship-worktrees")),
    agentHome: env("AGENT_HOME", join(tmpdir(), "wishship-agent-home")),
    agentEnvPassthrough: env("AGENT_ENV_PASSTHROUGH", "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    runTimeoutMs: Number(env("RUN_TIMEOUT_MINUTES", "30")) * 60 * 1000,
    maxConcurrentRuns: Number(env("MAX_CONCURRENT_RUNS", "2")),
    runCostCapUsd: env("RUN_COST_CAP_USD", "")
      ? Number(env("RUN_COST_CAP_USD"))
      : null,
    repoMonthlyBudgetUsd: env("REPO_MONTHLY_BUDGET_USD", "")
      ? Number(env("REPO_MONTHLY_BUDGET_USD"))
      : null,
    isProduction: process.env.NODE_ENV === "production",
  };
}

/** Random id for temp dirs / branch suffixes. Not a secret. */
export function randomId(bytes = 8): string {
  return randomBytes(bytes).toString("hex");
}

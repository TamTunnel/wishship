import { loadConfig } from "./config";
import { createPool, migrate } from "./db";
import {
  FakeGitHubClient,
  OctokitGitHubClient,
  UnconfiguredGitHubClient,
  type GitHubClient,
} from "./github";
import { buildApp, productionResolveRepo } from "./server";
import { Worker } from "./runner";

async function main(): Promise<void> {
  const config = loadConfig();
  const pool = createPool(config.databaseUrl);
  await migrate(pool);

  let github: GitHubClient;
  if (process.env.GITHUB_CLIENT === "fake") {
    console.warn("GITHUB_CLIENT=fake: using the in-memory GitHub client (dev only)");
    github = new FakeGitHubClient();
  } else if (config.githubAppId && config.githubAppPrivateKey) {
    github = new OctokitGitHubClient(config.githubAppId, config.githubAppPrivateKey);
  } else {
    console.warn("No GitHub App credentials configured: GitHub operations will fail until configured");
    github = new UnconfiguredGitHubClient();
  }

  const operator = {
    globalPaused: false,
    operatorLogins: (process.env.OPERATOR_LOGINS ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  };

  const backends = {
    scriptCommand: process.env.SCRIPT_BACKEND_COMMAND,
    scriptReviewCommand: process.env.SCRIPT_REVIEW_COMMAND ?? null,
  };

  const worker = new Worker({
    pool,
    config,
    github,
    backends: {
      claudeCommand: process.env.CLAUDE_COMMAND,
      codexCommand: process.env.CODEX_COMMAND,
      scriptCommand: backends.scriptCommand,
      scriptReviewCommand: backends.scriptReviewCommand,
    },
    resolveRepo: productionResolveRepo(github),
    isGloballyPaused: () => operator.globalPaused,
  });

  const app = buildApp({ pool, config, github, worker, operator, backends });
  worker.start();
  await app.listen({ port: config.port, host: config.host });
  console.log(`WishShip listening on http://${config.host}:${config.port}`);

  const shutdown = async (): Promise<void> => {
    worker.stop();
    await app.close();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

// Only boot the server when this file is the entry point. Importing it
// (e.g. from tests) must never start listening: node --test on a directory
// executes the directory's index.js as a test file, and an unguarded boot
// would hang the runner on a never-exiting server.
if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

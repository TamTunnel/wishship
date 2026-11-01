import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import Fastify, { type FastifyInstance } from "fastify";
import type { Pool } from "pg";
import type { WishShipConfig } from "./config";
import type { GitHubClient } from "./github";
import { registerRoutes, type OperatorState, type RouteDeps } from "./routes";
import { Worker, type ResolveRepoSource } from "./runner";
import type { Repo } from "./store";

const execFileAsync = promisify(execFile);

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".mp4": "video/mp4",
};

/**
 * Strip credential-bearing state from a service-side clone, immediately
 * after cloning and before any agent worktree is derived from it. The
 * installation token arrives in the clone URL, so without this the URL
 * persists in `.git/config` (and `.git/FETCH_HEAD`) for the whole run,
 * readable by the same-UID agent process. After stripping, the clone
 * has no remote at all; agent worktrees clone from this local path and
 * strip their own remote too.
 *
 * Residual, stated plainly (not hidden): a same-UID agent can still
 * read the service process's environment via /proc/<pid>/environ. True
 * separation needs a different UID or container per run (v1.1).
 */
export async function stripCloneCredentials(dir: string): Promise<void> {
  try {
    await execFileAsync("git", ["remote", "remove", "origin"], {
      cwd: dir,
      env: { PATH: process.env.PATH ?? "" },
    });
  } catch {
    // No remote to remove; nothing to strip.
  }
  await rm(join(dir, ".git", "FETCH_HEAD"), { force: true });
}

/**
 * Production repo resolution: the SERVICE clones with a short-lived
 * installation token into a temp dir, and agent worktrees clone from
 * that local path. The token never appears in an agent worktree, in
 * agent env, or in logs (error messages are scrubbed).
 */
export function productionResolveRepo(github: GitHubClient): ResolveRepoSource {
  return async (repo: Repo) => {
    const url = await github.serviceCloneUrl(repo.installation_id, repo.full_name);
    const dir = await mkdtemp(join(tmpdir(), "wishship-src-"));
    try {
      await execFileAsync("git", ["clone", "--quiet", url, "."], {
        cwd: dir,
        env: { PATH: process.env.PATH ?? "" },
        maxBuffer: 10 * 1024 * 1024,
      });
      // Strip BEFORE returning: the source clone lives for the whole
      // run, and the agent process shares the service's UID.
      await stripCloneCredentials(dir);
    } catch (err) {
      await rm(dir, { recursive: true, force: true });
      const message = (err as Error).message.replace(
        /x-access-token:[^@]+@/,
        "x-access-token:[redacted]@",
      );
      throw new Error(`service clone failed: ${message.slice(0, 300)}`);
    }
    return {
      dir,
      cleanup: () => rm(dir, { recursive: true, force: true }),
    };
  };
}

export interface AppDeps {
  pool: Pool;
  config: WishShipConfig;
  github: GitHubClient;
  worker: Worker;
  operator: OperatorState;
  backends: RouteDeps["backends"];
}

export function buildApp(deps: AppDeps): FastifyInstance {
  const app = Fastify({ logger: false });
  registerRoutes(app, {
    pool: deps.pool,
    config: deps.config,
    github: deps.github,
    worker: deps.worker,
    operator: deps.operator,
    backends: deps.backends,
  });

  // Static frontend (Vite build output). API routes take precedence.
  // Unknown /api/* paths are 404, not the SPA shell: returning
  // index.html with 200 for an API typo hides client bugs.
  app.get("/*", async (req, reply) => {
    const urlPath = (req.url.split("?")[0] ?? "/").replace(/^\/+/, "");
    if (urlPath.startsWith("api/")) {
      return reply.code(404).send({ error: "not found" });
    }
    const clientDist = resolve(process.cwd(), "client", "dist");
    const tryFile = async (name: string): Promise<Buffer | null> => {
      const path = resolve(clientDist, name);
      if (!path.startsWith(clientDist)) return null;
      try {
        const s = await stat(path);
        if (!s.isFile()) return null;
        return readFile(path);
      } catch {
        return null;
      }
    };
    let body: Buffer | null = null;
    let type = "text/html";
    if (urlPath === "" || urlPath === "/") {
      body = await tryFile("index.html");
    } else {
      body = await tryFile(urlPath);
      if (body) {
        const ext = urlPath.slice(urlPath.lastIndexOf("."));
        type = CONTENT_TYPES[ext] ?? "application/octet-stream";
      } else {
        body = await tryFile("index.html");
      }
    }
    if (!body) {
      return reply
        .code(200)
        .header("Content-Type", "text/html")
        .send(
          `<html><body><h1>WishShip</h1><p>Frontend not built yet. Run <code>npm run build:client</code>.</p><p>API: <a href="/api/health">/api/health</a></p></body></html>`,
        );
    }
    return reply.header("Content-Type", type).send(body);
  });

  return app;
}

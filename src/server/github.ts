/**
 * GitHub integration behind an interface. The real implementation uses
 * Octokit (App auth for installation tokens, OAuth tokens for user reads).
 * Tests and offline development use FakeGitHub, which records every call
 * so the gates can assert on exactly what the service attempted.
 *
 * Security invariants enforced HERE, not in callers:
 * - The agent never receives a token: pushBranch/openPr run in the service
 *   process only, and tokens are never written to logs, run records, or
 *   PR bodies (callers must not pass tokens into those channels either).
 * - Installation tokens are requested per operation and never stored.
 */
export interface RepoInfo {
  fullName: string;
  defaultBranch: string;
  private: boolean;
}

export interface CreatedPr {
  number: number;
  url: string;
}

export interface GitHubClient {
  /** Repos visible to an installation. */
  listInstallationRepos(installationId: number): Promise<RepoInfo[]>;
  /** Whether a user starred the repo. */
  hasStarred(installationId: number, fullName: string, login: string): Promise<boolean>;
  /** Whether a user has any commit/PR in the repo (best-effort). */
  hasContributed(installationId: number, fullName: string, login: string): Promise<boolean>;
  /** Whether a user is a maintainer (admin/maintain permission). */
  isMaintainer(installationId: number, fullName: string, login: string): Promise<boolean>;
  /** Clone URL the service may use with an installation token. */
  serviceCloneUrl(installationId: number, fullName: string): Promise<string>;
  /**
   * Push a patch to a new branch, service-side only. The agent worktree
   * has no remote and can never do this itself.
   */
  pushBranch(
    installationId: number,
    fullName: string,
    branch: string,
    baseCommit: string,
    patch: string,
  ): Promise<void>;
  /** Open a PR (draft or ready) from an existing branch. */
  openPr(
    installationId: number,
    fullName: string,
    branch: string,
    base: string,
    title: string,
    body: string,
    draft: boolean,
  ): Promise<CreatedPr>;
  /** Add labels to a PR (e.g. no-test-suite on PARTIAL reports). */
  addLabels(
    installationId: number,
    fullName: string,
    prNumber: number,
    labels: string[],
  ): Promise<void>;
  /** Delete a branch created by the service. */
  deleteBranch(installationId: number, fullName: string, branch: string): Promise<void>;
  /** Comment once on a linked issue (optional, one comment, no chatter). */
  commentOnIssue(
    installationId: number,
    fullName: string,
    issueNumber: number,
    body: string,
  ): Promise<void>;
}

/** Redact an installation-token URL from any text (git stderr, error
 * messages, run records). The clone path already scrubbed; pushBranch
 * did not — its raw git stderr could carry the token URL into a run's
 * failure_reason. */
export function scrubTokenUrl(text: string): string {
  return text.replace(/x-access-token:[^@\s]+@/g, "x-access-token:[redacted]@");
}

export class OctokitGitHubClient implements GitHubClient {
  private appId: string;
  private privateKey: string;

  constructor(appId: string, privateKey: string) {
    this.appId = appId;
    this.privateKey = privateKey;
    if (!appId || !privateKey) {
      throw new Error("GitHub App credentials are required for the real client");
    }
  }

  private async installationOctokit(installationId: number): Promise<import("octokit").Octokit> {
    const { Octokit } = await import("octokit");
    const { createAppAuth } = await import("@octokit/auth-app");
    return new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: this.appId,
        privateKey: this.privateKey,
        installationId,
      },
    });
  }

  async listInstallationRepos(installationId: number): Promise<RepoInfo[]> {
    const octokit = await this.installationOctokit(installationId);
    const repos = await octokit.paginate(
      octokit.rest.apps.listReposAccessibleToInstallation,
    );
    return repos.map((r: { full_name: string; default_branch: string; private: boolean }) => ({
      fullName: r.full_name,
      defaultBranch: r.default_branch,
      private: r.private,
    }));
  }

  async hasStarred(
    installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    try {
      await octokit.rest.activity.checkRepoIsStarredByAuthenticatedUser({ owner, repo });
      return true;
    } catch {
      // Star checks via the installation token reflect the installation,
      // not the user; fall back to the public stargazer list, paged
      // manually and CAPPED (10 pages x 100) instead of paginating the
      // entire list for a mega-repo.
      try {
        for (let page = 1; page <= 10; page++) {
          const res = await octokit.rest.activity.listStargazersForRepo({
            owner,
            repo,
            per_page: 100,
            page,
          });
          if (res.data.some((s: { login: string }) => s.login === login)) return true;
          if (res.data.length < 100) return false;
        }
        return false;
      } catch {
        return false;
      }
    }
  }

  async hasContributed(
    installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    try {
      const commits = await octokit.rest.repos.listCommits({
        owner,
        repo,
        author: login,
        per_page: 1,
      });
      if (commits.data.length > 0) return true;
      const prs = await octokit.rest.search.issuesAndPullRequests({
        q: `repo:${fullName} type:pr author:${login}`,
        per_page: 1,
      });
      return prs.data.total_count > 0;
    } catch {
      return false;
    }
  }

  async isMaintainer(
    installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    try {
      const res = await octokit.rest.repos.getCollaboratorPermissionLevel({
        owner,
        repo,
        username: login,
      });
      return res.data.permission === "admin" || res.data.permission === "maintain";
    } catch {
      return false;
    }
  }

  async serviceCloneUrl(installationId: number, fullName: string): Promise<string> {
    // A short-lived installation token embedded in the clone URL. It is
    // used only by the service-side git process, never logged, never
    // handed to the agent, and never persisted.
    const { Octokit } = await import("octokit");
    const { createAppAuth } = await import("@octokit/auth-app");
    const auth = createAppAuth({
      appId: this.appId,
      privateKey: this.privateKey,
      installationId,
    });
    const { token } = (await auth({ type: "installation" })) as { token: string };
    void Octokit;
    return `https://x-access-token:${token}@github.com/${fullName}.git`;
  }

  async pushBranch(
    installationId: number,
    fullName: string,
    branch: string,
    baseCommit: string,
    patch: string,
  ): Promise<void> {
    // Service-side only: clone, apply the verified patch, push the branch.
    // The token lives in the clone URL of this process only.
    const { spawn } = await import("node:child_process");
    const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const url = await this.serviceCloneUrl(installationId, fullName);
    const dir = await mkdtemp(join(tmpdir(), "wishship-push-"));
    // The patch file lives OUTSIDE the clone: the old code wrote
    // .wishship.patch inside it and then `git add -A` staged it, so
    // every PR branch shipped a stray file.
    const patchFile = join(
      await mkdtemp(join(tmpdir(), "wishship-patch-")),
      "patch.diff",
    );
    try {
      const run = (args: string[], input?: string): Promise<void> =>
        new Promise((resolve, reject) => {
          const child = spawn("git", args, {
            cwd: dir,
            stdio: ["pipe", "ignore", "pipe"],
            env: { PATH: process.env.PATH ?? "", HOME: dir },
          });
          let stderr = "";
          child.stderr.on("data", (d: Buffer) => {
            stderr += d.toString();
          });
          child.on("error", reject);
          child.on("close", (code) => {
            if (code === 0) resolve();
            else
              reject(
                new Error(
                  `git ${args[0]} failed: ${scrubTokenUrl(stderr).slice(0, 500)}`,
                ),
              );
          });
          if (input !== undefined) {
            child.stdin.write(input);
            child.stdin.end();
          } else {
            child.stdin.end();
          }
        });
      await run(["clone", "--quiet", url, "."]);
      await run(["checkout", "--quiet", baseCommit]);
      await run(["checkout", "-b", branch]);
      await writeFile(patchFile, patch);
      await run(["apply", "--whitespace=nowarn", patchFile]);
      await run(["add", "-A"]);
      await run([
        "-c",
        "user.name=wishship",
        "-c",
        "user.email=wishship@local",
        "commit",
        "--quiet",
        "-m",
        "WishShip: agent implementation (verified draft)",
      ]);
      await run(["push", "--quiet", "origin", branch]);
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(join(patchFile, ".."), { recursive: true, force: true });
    }
  }

  async openPr(
    installationId: number,
    fullName: string,
    branch: string,
    base: string,
    title: string,
    body: string,
    draft: boolean,
  ): Promise<CreatedPr> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    const pr = await octokit.rest.pulls.create({
      owner,
      repo,
      title,
      head: branch,
      base,
      body,
      draft,
    });
    return { number: pr.data.number, url: pr.data.html_url };
  }

  async addLabels(
    installationId: number,
    fullName: string,
    prNumber: number,
    labels: string[],
  ): Promise<void> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    await octokit.rest.issues.addLabels({
      owner,
      repo,
      issue_number: prNumber,
      labels,
    });
  }

  async deleteBranch(
    installationId: number,
    fullName: string,
    branch: string,
  ): Promise<void> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    await octokit.rest.git.deleteRef({ owner, repo, ref: `heads/${branch}` });
  }

  async commentOnIssue(
    installationId: number,
    fullName: string,
    issueNumber: number,
    body: string,
  ): Promise<void> {
    const octokit = await this.installationOctokit(installationId);
    const [owner, repo] = fullName.split("/");
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body,
    });
  }
}

/** Throws on every call: used when no GitHub App credentials are configured. */
export class UnconfiguredGitHubClient implements GitHubClient {
  private err(): Error {
    return new Error("GitHub App is not configured on this WishShip instance");
  }
  async listInstallationRepos(): Promise<RepoInfo[]> {
    throw this.err();
  }
  async hasStarred(): Promise<boolean> {
    throw this.err();
  }
  async hasContributed(): Promise<boolean> {
    throw this.err();
  }
  async isMaintainer(): Promise<boolean> {
    throw this.err();
  }
  async serviceCloneUrl(): Promise<string> {
    throw this.err();
  }
  async pushBranch(): Promise<void> {
    throw this.err();
  }
  async openPr(): Promise<CreatedPr> {
    throw this.err();
  }
  async addLabels(): Promise<void> {
    throw this.err();
  }
  async deleteBranch(): Promise<void> {
    throw this.err();
  }
  async commentOnIssue(): Promise<void> {
    throw this.err();
  }
}
export class FakeGitHubClient implements GitHubClient {
  stargazers = new Map<string, Set<string>>();
  contributors = new Map<string, Set<string>>();
  maintainers = new Map<string, Set<string>>();
  pushedBranches: { fullName: string; branch: string; patch: string }[] = [];
  openedPrs: {
    fullName: string;
    branch: string;
    title: string;
    body: string;
    draft: boolean;
  }[] = [];
  prLabels: { fullName: string; prNumber: number; labels: string[] }[] = [];
  deletedBranches: string[] = [];
  comments: { fullName: string; issueNumber: number; body: string }[] = [];
  private prCounter = 41;

  seedRepo(fullName: string): void {
    if (!this.stargazers.has(fullName)) this.stargazers.set(fullName, new Set());
    if (!this.contributors.has(fullName)) this.contributors.set(fullName, new Set());
    if (!this.maintainers.has(fullName)) this.maintainers.set(fullName, new Set());
  }

  async listInstallationRepos(_installationId: number): Promise<RepoInfo[]> {
    return [...this.stargazers.keys()].map((fullName) => ({
      fullName,
      defaultBranch: "main",
      private: false,
    }));
  }

  async hasStarred(
    _installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    return this.stargazers.get(fullName)?.has(login) ?? false;
  }

  async hasContributed(
    _installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    return this.contributors.get(fullName)?.has(login) ?? false;
  }

  async isMaintainer(
    _installationId: number,
    fullName: string,
    login: string,
  ): Promise<boolean> {
    return this.maintainers.get(fullName)?.has(login) ?? false;
  }

  async serviceCloneUrl(_installationId: number, fullName: string): Promise<string> {
    return `https://fake.invalid/${fullName}.git`;
  }

  async pushBranch(
    _installationId: number,
    fullName: string,
    branch: string,
    _baseCommit: string,
    patch: string,
  ): Promise<void> {
    this.pushedBranches.push({ fullName, branch, patch });
  }

  async openPr(
    _installationId: number,
    fullName: string,
    branch: string,
    _base: string,
    title: string,
    body: string,
    draft: boolean,
  ): Promise<CreatedPr> {
    this.openedPrs.push({ fullName, branch, title, body, draft });
    this.prCounter += 1;
    return {
      number: this.prCounter,
      url: `https://github.com/${fullName}/pull/${this.prCounter}`,
    };
  }

  async addLabels(
    _installationId: number,
    fullName: string,
    prNumber: number,
    labels: string[],
  ): Promise<void> {
    this.prLabels.push({ fullName, prNumber, labels });
  }

  async deleteBranch(
    _installationId: number,
    fullName: string,
    branch: string,
  ): Promise<void> {
    this.deletedBranches.push(`${fullName}:${branch}`);
  }

  async commentOnIssue(
    _installationId: number,
    fullName: string,
    issueNumber: number,
    body: string,
  ): Promise<void> {
    this.comments.push({ fullName, issueNumber, body });
  }
}

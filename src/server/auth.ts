import { createHmac, timingSafeEqual } from "node:crypto";

export interface SessionUser {
  id: number;
  login: string;
}

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function unb64url(input: string): Buffer {
  return Buffer.from(input, "base64url");
}

/**
 * Signed session cookie: payload.sig where sig = HMAC-SHA256(secret,
 * payload). No server-side session store; the cookie carries only the
 * GitHub id + login, never a token. Tokens are never stored in cookies.
 */
export function signSession(secret: string, user: SessionUser): string {
  const payload = b64url(
    JSON.stringify({ id: user.id, login: user.login, exp: Date.now() + SESSION_TTL_MS }),
  );
  const sig = b64url(createHmac("sha256", secret).update(payload).digest());
  return `${payload}.${sig}`;
}

export function verifySession(secret: string, cookie: string): SessionUser | null {
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0) return null;
  const payload = cookie.slice(0, dot);
  const sig = cookie.slice(dot + 1);
  const expected = b64url(createHmac("sha256", secret).update(payload).digest());
  try {
    if (
      sig.length !== expected.length ||
      !timingSafeEqual(Buffer.from(sig), Buffer.from(expected))
    ) {
      return null;
    }
  } catch {
    return null;
  }
  let parsed: { id: number; login: string; exp: number };
  try {
    parsed = JSON.parse(unb64url(payload).toString("utf8")) as typeof parsed;
  } catch {
    return null;
  }
  if (typeof parsed.id !== "number" || typeof parsed.login !== "string") return null;
  if (parsed.exp < Date.now()) return null;
  return { id: parsed.id, login: parsed.login };
}

export function githubAuthorizeUrl(
  clientId: string,
  baseUrl: string,
  state: string,
): string {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: `${baseUrl}/api/auth/callback`,
    scope: "read:user",
    state,
  });
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

export interface GitHubOAuthUser {
  id: number;
  login: string;
  avatar_url: string;
  created_at: string;
}

export async function exchangeCode(
  clientId: string,
  clientSecret: string,
  code: string,
  baseUrl: string,
): Promise<string> {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: `${baseUrl}/api/auth/callback`,
    }),
  });
  if (!res.ok) throw new Error(`OAuth exchange failed: ${res.status}`);
  const body = (await res.json()) as { access_token?: string; error?: string };
  if (!body.access_token) throw new Error(`OAuth exchange failed: ${body.error ?? "no token"}`);
  return body.access_token;
}

export async function fetchOAuthUser(token: string): Promise<GitHubOAuthUser> {
  const res = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "wishship",
    },
  });
  if (!res.ok) throw new Error(`GitHub user fetch failed: ${res.status}`);
  return (await res.json()) as GitHubOAuthUser;
}

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Pool, type PoolClient } from "pg";

export type Db = Pool | PoolClient;

export function createPool(databaseUrl: string): Pool {
  return new Pool({ connectionString: databaseUrl, max: 10 });
}

/** Apply the schema idempotently. Safe to run on every boot. */
export async function migrate(pool: Pool): Promise<void> {
  // Compiled layout mirrors src/: schema.sql lives in db/ next to db.js.
  const sql = readFileSync(join(__dirname, "db", "schema.sql"), "utf8");
  await pool.query(sql);
}

/** Test helper: wipe all data but keep the schema. */
export async function truncateAll(pool: Pool): Promise<void> {
  await pool.query(
    `TRUNCATE jobs, prs, verification_reports, runs, cycle_winners, cycles,
     votes, wishes, repos, users, audit_events RESTART IDENTITY CASCADE`,
  );
}

export async function queryOne<T>(
  db: Db,
  text: string,
  params: unknown[] = [],
): Promise<T | null> {
  const res = await db.query(text, params as never[]);
  return (res.rows[0] as T | undefined) ?? null;
}

export async function queryAll<T>(
  db: Db,
  text: string,
  params: unknown[] = [],
): Promise<T[]> {
  const res = await db.query(text, params as never[]);
  return res.rows as T[];
}

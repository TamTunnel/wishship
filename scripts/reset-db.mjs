// Dev helper: drop and recreate the wishship database schema.
import { Client } from "pg";

const url =
  process.env.DATABASE_URL ??
  "postgres://wishship:wishship-dev@127.0.0.1:5432/wishship";
const client = new Client({ connectionString: url });
await client.connect();
await client.query(`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`);
await client.end();
console.log("Schema dropped. Run the server (or migrate) to recreate it.");

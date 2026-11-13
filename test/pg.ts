// A fresh, empty Postgres schema per test file on TEST_DATABASE_URL, dropped after. Tests that need it are skipped without it.
import { randomBytes } from "node:crypto";
import postgres from "postgres";
import { wireSchemaSql } from "../src/postgres.js";

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "";
export const hasTestDb = Boolean(TEST_DATABASE_URL);

export interface TestSchema {
  sql: postgres.Sql;
  /** Another pool on the same schema: a second instance of the site. */
  other: postgres.Sql;
  drop: () => Promise<void>;
}

export async function freshSchema(): Promise<TestSchema> {
  const schema = `t_${randomBytes(6).toString("hex")}`;
  const admin = postgres(TEST_DATABASE_URL, { max: 1, onnotice: () => {} });
  await admin.unsafe(`CREATE SCHEMA ${schema}`);
  const pool = () => postgres(TEST_DATABASE_URL, { max: 3, onnotice: () => {}, connection: { search_path: schema } });
  const sql = pool();
  const other = pool();
  await sql.begin((tx) => tx.unsafe(wireSchemaSql()));
  return {
    sql,
    other,
    drop: async () => {
      await sql.end({ timeout: 5 });
      await other.end({ timeout: 5 });
      await admin.unsafe(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end({ timeout: 5 });
    },
  };
}

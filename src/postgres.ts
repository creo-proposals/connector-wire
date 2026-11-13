/**
 * The stores on Postgres (the `/postgres` entry). Uses the `postgres` client, a peer dependency: only this file imports it, and only
 * its types. The site passes its own pool; the tables are `WIRE_SCHEMA_SQL` (also in `sql/0001_wire.sql`), applied with the site's
 * own migrations.
 */
import type postgres from "postgres";
import { WIRE_SCHEMA_SQL } from "./schema.js";
import { conflictAnswer, isRetryLater } from "./stores.js";
import type { AnswerStore, LogStore, LoggedEntry, NonceStore, OutboxEntry, OutboxStore, WireAnswer } from "./stores.js";
import { RETRY_KEEP_HOURS } from "./wire.js";

export type Sql = postgres.Sql;
/** A transaction, or the pool itself when there is none. */
export type Tx = postgres.TransactionSql | postgres.Sql;

/** The schema the stores need, as SQL (also exported as WIRE_SCHEMA_SQL). */
export function wireSchemaSql(): string {
  return WIRE_SCHEMA_SQL;
}

export { WIRE_SCHEMA_SQL };

const json = (sql: Tx, v: unknown) => sql.json(v as postgres.JSONValue);

export function postgresNonces(sql: Sql): NonceStore {
  return {
    async claim(scope, nonce) {
      const rows = await sql`
        INSERT INTO wire_nonces (pairing, key_id, nonce) VALUES (${scope.pairing}, ${scope.keyId}, ${nonce})
        ON CONFLICT DO NOTHING RETURNING nonce`;
      return rows.length === 1;
    },
    async forgetBefore(cutoff) {
      return (await sql`DELETE FROM wire_nonces WHERE seen_at < ${cutoff}`).count;
    },
  };
}

class RetryLater extends Error {
  constructor(readonly answer: WireAnswer) {
    super("retry later");
  }
}

/**
 * The write and its answer share one transaction. The claim is a row insert: a second call with the same key waits on the first's
 * uncommitted row, then reads its answer (or, if the first rolled back, claims the key itself).
 */
export function postgresAnswers(sql: Sql): AnswerStore<postgres.TransactionSql> {
  return {
    async once(claim, act) {
      try {
        return await sql.begin(async (tx) => {
          await tx`
            DELETE FROM wire_answers
            WHERE pairing = ${claim.pairing} AND retry_key = ${claim.retryKey}
              AND at < now() - make_interval(hours => ${RETRY_KEEP_HOURS})`;
          const claimed = await tx`
            INSERT INTO wire_answers (pairing, retry_key, body_hash, op)
            VALUES (${claim.pairing}, ${claim.retryKey}, ${claim.bodyHash}, ${claim.op})
            ON CONFLICT (pairing, retry_key) DO NOTHING RETURNING retry_key`;
          if (claimed.length === 0) {
            const [kept] = await tx<{ body_hash: string; answer: WireAnswer }[]>`
              SELECT body_hash, answer FROM wire_answers WHERE pairing = ${claim.pairing} AND retry_key = ${claim.retryKey}`;
            if (!kept || kept.body_hash !== claim.bodyHash) return conflictAnswer();
            return kept.answer;
          }
          const answer = await act(tx);
          if (isRetryLater(answer)) throw new RetryLater(answer);
          await tx`UPDATE wire_answers SET answer = ${json(tx, answer)} WHERE pairing = ${claim.pairing} AND retry_key = ${claim.retryKey}`;
          return answer;
        });
      } catch (err) {
        if (err instanceof RetryLater) return err.answer;
        throw err;
      }
    },
    savepoint<T>(tx: postgres.TransactionSql, fn: (tx: postgres.TransactionSql) => Promise<T>): Promise<T> {
      return tx.savepoint((sp) => fn(sp)) as Promise<T>;
    },
    async forgetBefore(cutoff) {
      return (await sql`DELETE FROM wire_answers WHERE at < ${cutoff}`).count;
    },
  };
}

interface OutboxRow {
  id: string; pairing: string; kind: string; at: Date; fields: Record<string, unknown>; tries: number; next_at: Date; sent_at: Date | null; dead: boolean;
}
const toEntry = (r: OutboxRow): OutboxEntry => ({
  id: r.id, pairing: r.pairing, kind: r.kind, at: r.at.toISOString(), fields: r.fields, tries: r.tries, nextAt: r.next_at, sentAt: r.sent_at, dead: r.dead,
});

export function postgresOutbox(sql: Sql): OutboxStore<Tx> {
  return {
    async add(event, tx = sql) {
      await tx`
        INSERT INTO wire_outbox (id, pairing, kind, at, fields, next_at)
        VALUES (${event.id}, ${event.pairing}, ${event.kind}, ${event.at}, ${json(tx, event.fields)}, 'epoch')`;
    },
    async due(pairing, now, limit) {
      const rows = await sql<OutboxRow[]>`
        SELECT id, pairing, kind, at, fields, tries, next_at, sent_at, dead FROM wire_outbox
        WHERE pairing = ${pairing} AND sent_at IS NULL AND NOT dead AND next_at <= ${now}
        ORDER BY at, id LIMIT ${limit}`;
      return rows.map(toEntry);
    },
    async markSent(id, at) {
      await sql`UPDATE wire_outbox SET sent_at = ${at} WHERE id = ${id}`;
    },
    async markRetry(id, nextAt) {
      await sql`UPDATE wire_outbox SET tries = tries + 1, next_at = ${nextAt} WHERE id = ${id}`;
    },
    async markDead(id) {
      await sql`UPDATE wire_outbox SET tries = tries + 1, dead = true WHERE id = ${id}`;
    },
    async removeSentBefore(cutoff) {
      return (await sql`DELETE FROM wire_outbox WHERE sent_at IS NOT NULL AND sent_at < ${cutoff}`).count;
    },
    async get(id) {
      const [r] = await sql<OutboxRow[]>`SELECT id, pairing, kind, at, fields, tries, next_at, sent_at, dead FROM wire_outbox WHERE id = ${id}`;
      return r ? toEntry(r) : null;
    },
  };
}

export function postgresLog(sql: Sql): LogStore<Tx> {
  return {
    async append(e, tx = sql) {
      await tx`
        INSERT INTO wire_log (pairing, key_id, retry_key, op, changed, before, after)
        VALUES (${e.pairing}, ${e.keyId}, ${e.retryKey}, ${e.op}, ${e.changed}, ${json(tx, e.before ?? null)}, ${json(tx, e.after ?? null)})`;
    },
    async byRetryKey(pairing, retryKey) {
      const rows = await sql<{ id: string; at: Date; pairing: string; key_id: string; retry_key: string; op: string; changed: boolean; before: unknown; after: unknown }[]>`
        SELECT id, at, pairing, key_id, retry_key, op, changed, before, after FROM wire_log
        WHERE pairing = ${pairing} AND retry_key = ${retryKey} ORDER BY id`;
      return rows.map((r): LoggedEntry => ({
        id: Number(r.id), at: r.at, pairing: r.pairing, keyId: r.key_id, retryKey: r.retry_key, op: r.op, changed: r.changed, before: r.before, after: r.after,
      }));
    },
  };
}

/** All four stores on one pool. */
export function postgresStores(sql: Sql) {
  return { nonces: postgresNonces(sql), answers: postgresAnswers(sql), outbox: postgresOutbox(sql), log: postgresLog(sql) };
}

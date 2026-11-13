/**
 * What a site keeps for its side of a connection, as interfaces. `postgres.ts` (the `/postgres` entry) implements them on Postgres;
 * the `test…` functions here are in-memory versions **for tests only** (one process, no durability, no real savepoint).
 *
 * `Tx` is the store's transaction: a write runs inside it, with its stored answer, its log entries and any outbox events, so they
 * commit together or not at all.
 */
import { NONCE_KEEP_SECONDS, RETRY_KEEP_HOURS, WIRE_PAIRING_ID, WIRE_RETRY_LATER, type ClaimNonce } from "./wire.js";

/** An answer as a site sends it: an HTTP status and a JSON body. */
export interface WireAnswer {
  readonly status: number;
  readonly body: { readonly data: unknown } | { readonly error: { readonly code: string } };
}

/** One-use numbers: `claim` records one for a pairing and key, false if it was already used. */
export interface NonceStore {
  claim: ClaimNonce;
  /** Forgets numbers used before `cutoff`. Answers how many. Use `forgetExpired`, which keeps the margin. */
  forgetBefore(cutoff: Date): Promise<number>;
}

export interface RetryClaim {
  /** Retry keys are per pairing: the same key at two pairings is two keys. */
  readonly pairing: string;
  readonly retryKey: string;
  readonly bodyHash: string;
  readonly op: string;
}

/**
 * Answers by retry key, kept RETRY_KEEP_HOURS. `once` runs a write at most once per pairing and key: a new key runs `act` and keeps its
 * answer; the same key and body returns the kept answer and runs nothing; the same key with another body is `conflict` and runs nothing.
 * Two calls with one key at once: one runs, the other gets its answer. A retry-later answer (or a throw) keeps nothing and rolls the
 * whole transaction back, so a retry runs again.
 */
export interface AnswerStore<Tx> {
  once(claim: RetryClaim, act: (tx: Tx) => Promise<WireAnswer>): Promise<WireAnswer>;
  /**
   * Runs `fn` in a savepoint of `tx`: if it throws, everything it did is undone and the throw passes on, while the transaction itself
   * (and the answer it will keep) carries on.
   */
  savepoint<T>(tx: Tx, fn: (tx: Tx) => Promise<T>): Promise<T>;
  /** Forgets answers kept before `cutoff`. Answers how many. Use `forgetExpired`, which keeps the margin. */
  forgetBefore(cutoff: Date): Promise<number>;
}

/** An event waiting to go to the board. `fields` were checked against the site's declaration before it was added. */
export interface OutboxEvent {
  readonly id: string;
  /**
   * The pairing the event is queued for: the site's pairing when the thing it reports happened (in a write, `ctx.pairing`). An event
   * is sent only while that is still the site's pairing. After the site is paired again, an earlier pairing's events stay unsent:
   * they are never signed for the new pairing.
   */
  readonly pairing: string;
  readonly kind: string;
  /** The event's moment: `YYYY-MM-DDTHH:MM:SS[.mmm]Z` (read back from a store with milliseconds). */
  readonly at: string;
  readonly fields: Readonly<Record<string, unknown>>;
}
export interface OutboxEntry extends OutboxEvent {
  readonly tries: number;
  readonly nextAt: Date;
  readonly sentAt: Date | null;
  readonly dead: boolean;
}

/**
 * The outbox. `add` with a transaction writes the event in the same transaction as the thing it reports. An id is added once, and
 * only with a pairing id as its `pairing`.
 */
export interface OutboxStore<Tx> {
  add(event: OutboxEvent, tx?: Tx): Promise<void>;
  /** Unsent, live events queued for `pairing` whose next try is due, oldest first. Never another pairing's. */
  due(pairing: string, now: Date, limit: number): Promise<OutboxEntry[]>;
  markSent(id: string, at: Date): Promise<void>;
  /** One more try counted, the next not before `nextAt`. */
  markRetry(id: string, nextAt: Date): Promise<void>;
  /** Never sent again. */
  markDead(id: string): Promise<void>;
  get(id: string): Promise<OutboxEntry | null>;
  /** Removes events sent before `cutoff`. Unsent and dead events stay. Answers how many. */
  removeSentBefore(cutoff: Date): Promise<number>;
}

/** One change the board made through a write. */
export interface LogEntry {
  readonly pairing: string;
  readonly keyId: string;
  readonly retryKey: string;
  readonly op: string;
  readonly changed: boolean;
  readonly before: unknown;
  readonly after: unknown;
}
export interface LoggedEntry extends LogEntry {
  readonly id: number;
  readonly at: Date;
}

/**
 * The log of changes: append-only. Written in the write's transaction. Reads are not logged. Nothing here ever removes a row, and the
 * Postgres table refuses UPDATE, DELETE and TRUNCATE: keeping it, or ending that by a deliberate migration of the site's own, is the
 * site owner's decision.
 */
export interface LogStore<Tx> {
  append(entry: LogEntry, tx?: Tx): Promise<void>;
  /**
   * The entries of one write, oldest first: by its pairing **and** its retry key, as the write itself was claimed. Retry keys are per
   * pairing, so the same key at another pairing is another write, and is never given back here.
   */
  byRetryKey(pairing: string, retryKey: string): Promise<LoggedEntry[]>;
}

/** What an outbox sender does after one try: `null` is no answer at all (a timeout or a dropped connection). */
export function afterSend(code: string | null): "sent" | "retry" | "dead" {
  if (code === "recorded") return "sent";
  if (code === null || (WIRE_RETRY_LATER as readonly string[]).includes(code)) return "retry";
  return "dead";
}

/** When to try an event again after `tries` failed tries: 1, 2, 4 ... minutes, at most a day. */
export function nextTry(tries: number, now: Date): Date {
  const minutes = Math.min(2 ** Math.max(0, tries - 1), 24 * 60);
  return new Date(now.getTime() + minutes * 60_000);
}

/**
 * One-use numbers are kept this long: the contract's 601 seconds (twice the window and a second, the least it allows) plus a minute for
 * clocks that differ and slow requests.
 */
export const NONCE_KEEP_WITH_MARGIN_SECONDS = NONCE_KEEP_SECONDS + 60;
/**
 * The clean-up keeps a stored answer this long: the contract's 24 hours plus an hour. The clean-up's cut-off comes from the app's
 * clock and a kept answer's time from the store's (a database stamps the row), and the two differ: with no margin, a clean-up on a
 * fast clock would forget an answer the contract still wants kept, and a repeat of its write would act a second time.
 */
export const ANSWER_KEEP_WITH_MARGIN_SECONDS = RETRY_KEEP_HOURS * 3600 + 3600;
/** Sent events are kept this long by default, for looking back; unsent and dead ones are never removed. */
export const SENT_KEEP_DAYS = 7;

/**
 * The daily clean-up, with the margins built in: one-use numbers older than NONCE_KEEP_WITH_MARGIN_SECONDS, answers older than
 * ANSWER_KEEP_WITH_MARGIN_SECONDS and sent events older than `sentKeepDays` (default SENT_KEEP_DAYS). The log is never touched. Run it on a schedule.
 */
export async function forgetExpired<Tx>(
  stores: { nonces: NonceStore; answers: AnswerStore<Tx>; outbox?: OutboxStore<Tx> },
  now: Date,
  options: { sentKeepDays?: number } = {},
): Promise<{ nonces: number; answers: number; sent: number }> {
  const ago = (ms: number) => new Date(now.getTime() - ms);
  const sentKeepDays = options.sentKeepDays ?? SENT_KEEP_DAYS;
  if (!(sentKeepDays >= 0)) throw new TypeError("forgetExpired: sentKeepDays is 0 or more");
  return {
    nonces: await stores.nonces.forgetBefore(ago(NONCE_KEEP_WITH_MARGIN_SECONDS * 1000)),
    answers: await stores.answers.forgetBefore(ago(ANSWER_KEEP_WITH_MARGIN_SECONDS * 1000)),
    sent: stores.outbox ? await stores.outbox.removeSentBefore(ago(sentKeepDays * 86_400_000)) : 0,
  };
}

export const conflictAnswer = (): WireAnswer => ({ status: 409, body: { error: { code: "conflict" } } });

export const isRetryLater = (a: WireAnswer): boolean =>
  "error" in a.body && (WIRE_RETRY_LATER as readonly string[]).includes(a.body.error.code);

// ── In memory, for tests only ─────────────────────────────────────────────────────────────────────────────────

/** One-use numbers in memory. For tests only. */
export function testNonces(clock: () => Date = () => new Date()): NonceStore {
  const used = new Map<string, number>();
  return {
    claim: (scope, nonce) => {
      const k = `${scope.pairing}\n${scope.keyId}\n${nonce}`;
      if (used.has(k)) return false;
      used.set(k, clock().getTime());
      return true;
    },
    async forgetBefore(cutoff) {
      let n = 0;
      for (const [k, at] of used) if (at < cutoff.getTime()) { used.delete(k); n++; }
      return n;
    },
  };
}

/** Answers in memory. For tests only: `savepoint` cannot undo anything here, so a refusal's partial work is not rolled back. */
export function testAnswers(clock: () => Date = () => new Date()): AnswerStore<undefined> {
  const kept = new Map<string, { bodyHash: string; op: string; answer: WireAnswer; at: number }>();
  const running = new Map<string, Promise<unknown>>();
  const fresh = (k: { at: number }) => k.at >= clock().getTime() - RETRY_KEEP_HOURS * 3600_000;
  return {
    async once(claim, act) {
      const key = `${claim.pairing}\n${claim.retryKey}`;
      for (;;) {
        const k = kept.get(key);
        if (k && fresh(k)) return k.bodyHash === claim.bodyHash ? k.answer : conflictAnswer();
        const r = running.get(key);
        if (!r) break;
        // Another call with this key is running: wait for it, then look again (it kept an answer, or nothing).
        await r.catch(() => null);
      }
      const work = act(undefined);
      running.set(key, work);
      try {
        const answer = await work;
        if (!isRetryLater(answer)) kept.set(key, { bodyHash: claim.bodyHash, op: claim.op, answer, at: clock().getTime() });
        return answer;
      } finally {
        running.delete(key);
      }
    },
    savepoint: (tx, fn) => fn(tx),
    async forgetBefore(cutoff) {
      let n = 0;
      for (const [key, k] of kept) if (k.at < cutoff.getTime()) { kept.delete(key); n++; }
      return n;
    },
  };
}

/** The outbox in memory. For tests only. */
export function testOutbox(): OutboxStore<undefined> {
  const rows = new Map<string, OutboxEntry>();
  const need = (id: string) => {
    const r = rows.get(id);
    if (!r) throw new Error("no such outbox event");
    return r;
  };
  return {
    async add(event) {
      if (typeof event.pairing !== "string" || !WIRE_PAIRING_ID.test(event.pairing)) throw new Error("an outbox event is queued for a pairing");
      if (rows.has(event.id)) throw new Error("an outbox event id is added once");
      rows.set(event.id, { ...event, at: new Date(event.at).toISOString(), fields: structuredClone(event.fields), tries: 0, nextAt: new Date(0), sentAt: null, dead: false });
    },
    async due(pairing, now, limit) {
      return [...rows.values()]
        .filter((r) => r.pairing === pairing && r.sentAt === null && !r.dead && r.nextAt.getTime() <= now.getTime())
        .sort((a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id))
        .slice(0, limit);
    },
    async markSent(id, at) { rows.set(id, { ...need(id), sentAt: at }); },
    async markRetry(id, nextAt) { const r = need(id); rows.set(id, { ...r, tries: r.tries + 1, nextAt }); },
    async markDead(id) { const r = need(id); rows.set(id, { ...r, tries: r.tries + 1, dead: true }); },
    async get(id) { return rows.get(id) ?? null; },
    async removeSentBefore(cutoff) {
      let n = 0;
      for (const [id, r] of rows) if (r.sentAt && r.sentAt.getTime() < cutoff.getTime()) { rows.delete(id); n++; }
      return n;
    },
  };
}

/** The log in memory. For tests only. */
export function testLog(clock: () => Date = () => new Date()): LogStore<undefined> {
  const rows: LoggedEntry[] = [];
  return {
    async append(entry) { rows.push(Object.freeze({ ...entry, id: rows.length + 1, at: clock() })); },
    async byRetryKey(pairing, retryKey) { return rows.filter((r) => r.pairing === pairing && r.retryKey === retryKey); },
  };
}

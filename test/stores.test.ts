import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  afterSend, ANSWER_KEEP_WITH_MARGIN_SECONDS, forgetExpired, NONCE_KEEP_SECONDS, NONCE_KEEP_WITH_MARGIN_SECONDS, nonceMemory, RETRY_KEEP_HOURS,
  testAnswers, testLog, testNonces, testOutbox, nextTry,
  type AnswerStore, type LogStore, type NonceStore, type OutboxStore, type WireAnswer,
} from "../src/index.js";
import { postgresStores } from "../src/postgres.js";
import { freshSchema, hasTestDb, type TestSchema } from "./pg.js";

interface Instance {
  nonces: NonceStore;
  answers: AnswerStore<unknown>;
  outbox: OutboxStore<unknown>;
  log: LogStore<unknown>;
}
interface Setup {
  /** Two instances of a site sharing one store. */
  one: Instance;
  two: Instance;
  /** Ages a kept answer, as if it were kept `hours` ago. */
  age: (retryKey: string, hours: number) => Promise<void>;
  /** The clock the answers store stamps a kept answer with (the database's, or the in-memory store's own). */
  now: () => Date;
}

const done = (n: number): WireAnswer => ({ status: 200, body: { data: { n } } });

/** The same behaviour from every implementation of the stores. */
function conformance(name: string, setup: () => Promise<Setup>, skip = false) {
  describe.skipIf(skip)(`${name} stores`, () => {
    let s: Setup;
    beforeAll(async () => { s = await setup(); });

    describe("one-use numbers", () => {
      it("refuse a second use, from either instance", async () => {
        expect(await s.one.nonces.claim({ pairing: "p1", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
        expect(await s.two.nonces.claim({ pairing: "p1", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
        expect(await s.one.nonces.claim({ pairing: "p1", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
      });
      it("accept exactly one of two claims made at once", async () => {
        const r = await Promise.all([
          s.one.nonces.claim({ pairing: "p1", keyId: "k1" }, "BBBBBBBBBBBBBBBBBBBBBB"),
          s.two.nonces.claim({ pairing: "p1", keyId: "k1" }, "BBBBBBBBBBBBBBBBBBBBBB"),
        ]);
        expect(r.filter(Boolean)).toHaveLength(1);
      });
      it("are per pairing and key", async () => {
        expect(await s.one.nonces.claim({ pairing: "p2", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
        expect(await s.one.nonces.claim({ pairing: "p1", keyId: "k2" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
      });
      it("are forgotten only before the cutoff", async () => {
        expect(await s.one.nonces.forgetBefore(new Date(Date.now() - 3600_000))).toBe(0);
        expect(await s.one.nonces.claim({ pairing: "p1", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
        expect(await s.one.nonces.forgetBefore(new Date(Date.now() + 1000))).toBeGreaterThan(0);
        expect(await s.one.nonces.claim({ pairing: "p1", keyId: "k1" }, "AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
      });
    });

    describe("answers by retry key", () => {
      it("run a new key once and keep its answer", async () => {
        let runs = 0;
        const claim = { pairing: "p1", retryKey: "retry-new-0000000001", bodyHash: "hash-a", op: "x.hide" };
        expect(await s.one.answers.once(claim, async () => done(++runs))).toEqual(done(1));
        expect(await s.two.answers.once(claim, async () => done(++runs))).toEqual(done(1));
        expect(runs).toBe(1);
      });
      it("answer the same key with another body as conflict and act nothing", async () => {
        let runs = 0;
        const claim = { pairing: "p1", retryKey: "retry-diff-000000001", bodyHash: "hash-a", op: "x.hide" };
        await s.one.answers.once(claim, async () => done(++runs));
        expect(await s.one.answers.once({ ...claim, bodyHash: "hash-b" }, async () => done(++runs))).toEqual({
          status: 409, body: { error: { code: "conflict" } },
        });
        expect(runs).toBe(1);
      });
      it("act once when the same key arrives twice at once", async () => {
        let runs = 0;
        const act = async () => { runs++; await new Promise((r) => setTimeout(r, 50)); return done(runs); };
        const claim = { pairing: "p1", retryKey: "retry-race-000000001", bodyHash: "hash-a", op: "x.hide" };
        const [a, b] = await Promise.all([s.one.answers.once(claim, act), s.two.answers.once(claim, act)]);
        expect(runs).toBe(1);
        expect(a).toEqual(b);
      });
      it("keep nothing for a retry-later answer or a throw, so the retry runs", async () => {
        const claim = { pairing: "p1", retryKey: "retry-later-00000001", bodyHash: "hash-a", op: "x.hide" };
        const busy: WireAnswer = { status: 503, body: { error: { code: "unavailable" } } };
        expect(await s.one.answers.once(claim, async () => busy)).toEqual(busy);
        await expect(s.one.answers.once(claim, async () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
        expect(await s.one.answers.once(claim, async () => done(7))).toEqual(done(7));
      });
      it("keep a refusal that is not retry-later", async () => {
        const claim = { pairing: "p1", retryKey: "retry-refused-000001", bodyHash: "hash-a", op: "x.hide" };
        const nf: WireAnswer = { status: 404, body: { error: { code: "not_found" } } };
        expect(await s.one.answers.once(claim, async () => nf)).toEqual(nf);
        expect(await s.one.answers.once(claim, async () => done(1))).toEqual(nf);
      });
      it("are per pairing: one retry key at two pairings is two keys", async () => {
        let runs = 0;
        const claim = { pairing: "p1", retryKey: "retry-pairs-00000001", bodyHash: "hash-a", op: "x.hide" };
        expect(await s.one.answers.once(claim, async () => done(++runs))).toEqual(done(1));
        expect(await s.one.answers.once({ ...claim, pairing: "p2", bodyHash: "hash-b" }, async () => done(++runs))).toEqual(done(2));
        expect(await s.two.answers.once(claim, async () => done(++runs))).toEqual(done(1));
        expect(runs).toBe(2);
      });
      it("forget an answer after 24 hours", async () => {
        const claim = { pairing: "p1", retryKey: "retry-old-0000000001", bodyHash: "hash-a", op: "x.hide" };
        await s.one.answers.once(claim, async () => done(1));
        await s.age(claim.retryKey, 25);
        expect(await s.one.answers.once({ ...claim, bodyHash: "hash-b" }, async () => done(2))).toEqual(done(2));
      });
    });

    describe("the outbox", () => {
      it("adds an event once and gives back what was added", async () => {
        await s.one.outbox.add({ id: "ev-1", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: { added: 3 } });
        await expect(s.two.outbox.add({ id: "ev-1", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: {} })).rejects.toThrow();
        const e = await s.two.outbox.get("ev-1");
        expect(e).toMatchObject({ id: "ev-1", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30.000Z", fields: { added: 3 }, tries: 0, sentAt: null, dead: false });
        expect(await s.one.outbox.get("ev-none")).toBeNull();
      });
      it("hands out due events oldest first, and never a sent, dead or not-yet-due one", async () => {
        await s.one.outbox.add({ id: "ev-2", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:00Z", fields: {} });
        await s.one.outbox.add({ id: "ev-3", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:45Z", fields: {} });
        await s.one.outbox.add({ id: "ev-4", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:50Z", fields: {} });
        const now = new Date("2099-01-01T00:00:00Z");
        expect((await s.one.outbox.due("p1", now, 10)).map((e) => e.id)).toEqual(["ev-2", "ev-1", "ev-3", "ev-4"]);
        expect((await s.one.outbox.due("p1", now, 2)).map((e) => e.id)).toEqual(["ev-2", "ev-1"]);
        await s.one.outbox.markSent("ev-2", now);
        await s.one.outbox.markDead("ev-3");
        await s.one.outbox.markRetry("ev-4", new Date("2099-01-01T00:01:00Z"));
        expect((await s.two.outbox.due("p1", now, 10)).map((e) => e.id)).toEqual(["ev-1"]);
        expect((await s.two.outbox.due("p1", new Date("2099-01-01T00:01:00Z"), 10)).map((e) => e.id)).toEqual(["ev-1", "ev-4"]);
        expect(await s.two.outbox.get("ev-4")).toMatchObject({ tries: 1, dead: false });
        expect(await s.two.outbox.get("ev-3")).toMatchObject({ dead: true });
        expect((await s.two.outbox.get("ev-2"))?.sentAt?.toISOString()).toBe("2099-01-01T00:00:00.000Z");
      });
      it("hands out only the events queued for the pairing asked about, each with its pairing", async () => {
        // Queued while the site was paired another way: older than every event above, and never handed out for `p1`.
        await s.one.outbox.add({ id: "ev-5", pairing: "p2", kind: "shop.feed.loaded", at: "2098-12-31T23:58:00Z", fields: {} });
        const later = new Date("2099-01-01T00:01:00Z");
        expect((await s.two.outbox.due("p1", later, 10)).map((e) => [e.id, e.pairing])).toEqual([["ev-1", "p1"], ["ev-4", "p1"]]);
        expect((await s.two.outbox.due("p2", later, 10)).map((e) => [e.id, e.pairing])).toEqual([["ev-5", "p2"]]);
        expect(await s.two.outbox.due("p3", later, 10)).toEqual([]);
        expect(await s.two.outbox.get("ev-5")).toMatchObject({ id: "ev-5", pairing: "p2", tries: 0, sentAt: null, dead: false });
      });
      it("takes an event only with the pairing it is queued for", async () => {
        for (const pairing of ["", "not a pairing id", undefined as unknown as string]) {
          await expect(s.one.outbox.add({ id: "ev-6", pairing, kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: {} })).rejects.toThrow();
        }
        expect(await s.two.outbox.get("ev-6")).toBeNull();
      });
    });

    describe("clean-up", () => {
      it("removes only events sent before the cutoff", async () => {
        await s.one.outbox.add({ id: "ev-clean-1", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: {} });
        await s.one.outbox.add({ id: "ev-clean-2", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: {} });
        await s.one.outbox.markSent("ev-clean-1", new Date("2099-01-01T00:00:00Z"));
        await s.one.outbox.markSent("ev-clean-2", new Date("2099-01-09T00:00:00Z"));
        expect(await s.one.outbox.removeSentBefore(new Date("2099-01-05T00:00:00Z"))).toBeGreaterThanOrEqual(1);
        expect(await s.two.outbox.get("ev-clean-1")).toBeNull();
        expect(await s.two.outbox.get("ev-clean-2")).not.toBeNull();
        // Unsent and dead events are never removed.
        expect(await s.two.outbox.get("ev-1")).not.toBeNull();
        expect(await s.two.outbox.get("ev-3")).not.toBeNull();
      });
      it("forgetExpired keeps numbers 661 seconds (the contract's 601 and a margin)", async () => {
        expect([NONCE_KEEP_SECONDS, NONCE_KEEP_WITH_MARGIN_SECONDS]).toEqual([601, 661]);
        const now = new Date(Date.now() + 600_000);
        const before = await s.one.nonces.claim({ pairing: "p9", keyId: "k9" }, "CCCCCCCCCCCCCCCCCCCCCC");
        expect(before).toBe(true);
        // Ten minutes on, the number is still kept ...
        await forgetExpired({ nonces: s.one.nonces, answers: s.one.answers, outbox: s.one.outbox }, now);
        expect(await s.two.nonces.claim({ pairing: "p9", keyId: "k9" }, "CCCCCCCCCCCCCCCCCCCCCC")).toBe(false);
        // ... and gone after more than 661 seconds.
        const r = await forgetExpired({ nonces: s.one.nonces, answers: s.one.answers }, new Date(Date.now() + 662_000));
        expect(r.nonces).toBeGreaterThan(0);
        expect(r.sent).toBe(0);
        expect(await s.two.nonces.claim({ pairing: "p9", keyId: "k9" }, "CCCCCCCCCCCCCCCCCCCCCC")).toBe(true);
      });
      it("forgetExpired keeps answers 25 hours (the contract's 24 and a margin): its clock is the app's, a kept answer's the store's", async () => {
        expect([RETRY_KEEP_HOURS, ANSWER_KEEP_WITH_MARGIN_SECONDS]).toEqual([24, 25 * 3600]);
        const stores = { nonces: s.one.nonces, answers: s.one.answers };
        const conflict = { status: 409, body: { error: { code: "conflict" } } };
        const claim = { pairing: "p9", retryKey: "retry-margin-0000001", bodyHash: "hash-a", op: "x.hide" };
        // Kept a moment ago by the store's clock.
        expect(await s.one.answers.once(claim, async () => done(1))).toEqual(done(1));
        const kept = s.now().getTime();
        // A clean-up whose own clock runs half an hour fast believes 24 hours have passed. The answer is not yet a day old: it stays,
        // and the key still answers for its write.
        await forgetExpired(stores, new Date(kept + 24 * 3600_000 + 30 * 60_000));
        expect(await s.two.answers.once({ ...claim, bodyHash: "hash-b" }, async () => done(2))).toEqual(conflict);
        expect(await s.two.answers.once(claim, async () => done(3))).toEqual(done(1));
        // Past 25 hours it is forgotten, and the key may be used again.
        const r = await forgetExpired(stores, new Date(kept + 25 * 3600_000 + 60_000));
        expect(r.answers).toBeGreaterThan(0);
        expect(await s.two.answers.once({ ...claim, bodyHash: "hash-b" }, async () => done(2))).toEqual(done(2));
      });
    });

    describe("the log", () => {
      it("appends and reads back by pairing and retry key", async () => {
        const entry = { pairing: "p1", keyId: "k1", retryKey: "retry-log-0000000001", op: "x.hide", changed: true, before: { hidden: false }, after: { hidden: true } };
        await s.one.log.append(entry);
        await s.two.log.append({ ...entry, changed: false, before: null, after: null });
        const rows = await s.one.log.byRetryKey("p1", "retry-log-0000000001");
        expect(rows.map(({ id: _id, at: _at, ...r }) => r)).toEqual([entry, { ...entry, changed: false, before: null, after: null }]);
        expect(rows[0]!.id).toBeLessThan(rows[1]!.id);
      });
      it("looks a retry key up at its own pairing only: the same key at another pairing is another write", async () => {
        const mine = { pairing: "p1", keyId: "k1", retryKey: "retry-log-0000000002", op: "x.hide", changed: true, before: { n: 1 }, after: { n: 2 } };
        const theirs = { ...mine, pairing: "p2", before: { n: 7 }, after: { n: 8 } };
        await s.one.log.append(mine);
        await s.one.log.append(theirs);
        expect((await s.two.log.byRetryKey("p1", "retry-log-0000000002")).map(({ id: _id, at: _at, ...r }) => r)).toEqual([mine]);
        expect((await s.two.log.byRetryKey("p2", "retry-log-0000000002")).map(({ id: _id, at: _at, ...r }) => r)).toEqual([theirs]);
        expect(await s.two.log.byRetryKey("p3", "retry-log-0000000002")).toEqual([]);
      });
    });
  });
}

conformance("memory", async () => {
  const one = { nonces: testNonces(), answers: testAnswers(), outbox: testOutbox(), log: testLog() };
  let shift = 0;
  const clocked = { ...one, answers: testAnswers(() => new Date(Date.now() + shift)) };
  return {
    one: clocked,
    two: clocked,
    age: async (_key, hours) => { shift += hours * 3600_000; },
    now: () => new Date(Date.now() + shift),
  };
});

describe.skipIf(!hasTestDb)("postgres (needs TEST_DATABASE_URL)", () => {
  let t: TestSchema;
  afterAll(async () => { await t?.drop(); });
  conformance("postgres", async () => {
    t = await freshSchema();
    return {
      one: postgresStores(t.sql),
      two: postgresStores(t.other),
      age: async (key, hours) => { await t.sql`UPDATE wire_answers SET at = now() - make_interval(hours => ${hours}) WHERE retry_key = ${key}`; },
      // The test database runs beside the tests: its clock is this one, to well within the half hour the test allows.
      now: () => new Date(),
    };
  });

  it("the log refuses UPDATE, DELETE and TRUNCATE", async () => {
    await expect(t.sql`UPDATE wire_log SET changed = false`).rejects.toThrow(/append-only/);
    await expect(t.sql`DELETE FROM wire_log`).rejects.toThrow(/append-only/);
    await expect(t.sql`TRUNCATE wire_log`).rejects.toThrow(/append-only/);
  });

  it("an outbox event and a log entry commit with their transaction, or not at all", async () => {
    const { outbox, log } = postgresStores(t.sql);
    await expect(t.sql.begin(async (tx) => {
      await outbox.add({ id: "ev-tx-1", pairing: "p1", kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: {} }, tx);
      await log.append({ pairing: "p1", keyId: "k1", retryKey: "retry-tx-00000000001", op: "x.hide", changed: true, before: null, after: null }, tx);
      throw new Error("roll back");
    })).rejects.toThrow("roll back");
    expect(await outbox.get("ev-tx-1")).toBeNull();
    expect(await log.byRetryKey("p1", "retry-tx-00000000001")).toEqual([]);
  });
});

describe("one-use numbers, by a clock the test controls (contract section 3, step 7)", () => {
  const T0 = Date.parse("2099-01-01T00:00:00Z");
  const scope = { pairing: "p1", keyId: "k1" };
  const N = "DDDDDDDDDDDDDDDDDDDDDD";

  it("the in-process store keeps a number 601 seconds, per pairing and key: refused at 600, accepted again at 601", async () => {
    let now = T0;
    const claim = nonceMemory(() => new Date(now));
    expect(await claim(scope, N)).toBe(true);
    now = T0 + 600_000;
    expect(await claim(scope, N)).toBe(false);
    // The same number under another key, or at another pairing, is a different number.
    expect(await claim({ pairing: "p1", keyId: "k2" }, N)).toBe(true);
    expect(await claim({ pairing: "p2", keyId: "k1" }, N)).toBe(true);
    now = T0 + 600_999;
    expect(await claim(scope, N)).toBe(false);
    now = T0 + 601_000;
    expect(await claim(scope, N)).toBe(true);
    expect(await claim(scope, N)).toBe(false);
  });

  it("a store cleaned by forgetExpired keeps a number through 601 seconds and its margin, per pairing and key", async () => {
    let now = T0;
    const nonces = testNonces(() => new Date(now));
    const stores = { nonces, answers: testAnswers(() => new Date(now)) };
    expect(await nonces.claim(scope, N)).toBe(true);
    // Cleaned at 600 seconds, at 601 and at the margin's end, it is still a used number.
    for (const seconds of [600, 601, NONCE_KEEP_WITH_MARGIN_SECONDS]) {
      now = T0 + seconds * 1000;
      expect((await forgetExpired(stores, new Date(now))).nonces, String(seconds)).toBe(0);
      expect(await nonces.claim(scope, N), String(seconds)).toBe(false);
    }
    // The same number under another key, or at another pairing, is a different number.
    expect(await nonces.claim({ pairing: "p1", keyId: "k2" }, N)).toBe(true);
    expect(await nonces.claim({ pairing: "p2", keyId: "k1" }, N)).toBe(true);
    // A second past the margin it is forgotten, alone: the two used a second ago stay.
    now = T0 + (NONCE_KEEP_WITH_MARGIN_SECONDS + 1) * 1000;
    expect((await forgetExpired(stores, new Date(now))).nonces).toBe(1);
    expect(await nonces.claim(scope, N)).toBe(true);
    expect(await nonces.claim({ pairing: "p1", keyId: "k2" }, N)).toBe(false);
  });
});

describe("sending events", () => {
  it("retries later on the retry-later codes and no answer, never again on any other", () => {
    expect(afterSend("recorded")).toBe("sent");
    for (const c of ["rate_limited", "unavailable", "internal", null]) expect(afterSend(c)).toBe("retry");
    for (const c of ["bad_event", "unknown_event", "bad_signature", "replayed"]) expect(afterSend(c)).toBe("dead");
  });
  it("backs off 1, 2, 4 ... minutes, at most a day", () => {
    const now = new Date("2099-01-01T00:00:00Z");
    expect(nextTry(1, now).toISOString()).toBe("2099-01-01T00:01:00.000Z");
    expect(nextTry(3, now).toISOString()).toBe("2099-01-01T00:04:00.000Z");
    expect(nextTry(40, now).toISOString()).toBe("2099-01-02T00:00:00.000Z");
  });
});

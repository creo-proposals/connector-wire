import { Readable } from "node:stream";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  BodyReadTimeout, createRegistry, handleOperation, loadWireKeys, newKeyPair, newNonce, readCapped, signWire, testAnswers, testNonces, WireRefusal,
  type HandlerDeps, type NonceStore, type SitePairing, type WireHttpRequest, type WireOperation,
} from "../src/index.js";
import { postgresStores, type Tx } from "../src/postgres.js";
import { freshSchema, hasTestDb, type TestSchema } from "./pg.js";

const board = newKeyPair();
const NOW = new Date("2099-01-01T00:00:00Z");
const SITE: SitePairing = {
  pairing: "site-test",
  keys: loadWireKeys([{ id: "op-t1", pairing: "site-test", direction: "operation", publicKey: board.publicKey, from: "2098-12-01T00:00:00Z" }]),
};

function request(op: string, body: string | Uint8Array, o: { retry?: string; path?: string } = {}): WireHttpRequest {
  const path = o.path ?? `/wire/v0/ops/${op}`;
  const headers = signWire({
    direction: "operation", method: "POST", path, body, keyId: "op-t1", pairing: "site-test", privateKey: board.privateKey,
    time: Math.floor(NOW.getTime() / 1000), nonce: newNonce(), retry: o.retry,
  });
  return { method: "POST", path, headers, body: typeof body === "string" ? Buffer.from(body) : body };
}
const code = (r: { body: string | null }) => (JSON.parse(r.body ?? "null") as { error?: { code: string } })?.error?.code;
/** An operation's body: exactly `op`, `input` and `marked`. */
const body = (op: string, input: unknown = {}): string => JSON.stringify({ op, input, marked: false });

let seenSignal: AbortSignal | undefined;
const reads: WireOperation[] = [
  {
    name: "things.get", write: false,
    input: [{ name: "mode", type: "choice", of: ["refuseOddly", "refuseMadeUp", "slow"], optional: true }, { name: "note", type: "text", maxLength: 20, optional: true }],
    answer: [{ name: "note", type: "text", maxLength: 200, provenance: "outside" }],
    async run(input, ctx) {
      seenSignal = ctx.signal;
      if (input.mode === "refuseOddly") throw new WireRefusal("rate_limited" as never);
      if (input.mode === "refuseMadeUp") throw new WireRefusal("a sentence, not a code" as never);
      if (input.mode === "slow") await new Promise((r) => setTimeout(r, 100));
      return { note: "ok" };
    },
  },
  {
    name: "things.atOnce", write: false,
    input: [{ name: "mode", type: "choice", of: ["refuse", "fail"] }],
    answer: [{ name: "note", type: "text", maxLength: 200, provenance: "outside" }],
    // Not an async function: it throws before it has returned any promise.
    run(input) {
      if (input.mode === "refuse") throw new WireRefusal("not_found");
      throw new Error("boom");
    },
  },
  {
    name: "things.big", write: false, input: [],
    // A hundred notes of 20,000 characters fit the declaration and are well over 1 MiB together.
    answer: [{ name: "notes", type: "list", of: [{ name: "note", type: "text", maxLength: 20_000, provenance: "outside" }] }],
    async run() { return { notes: Array.from({ length: 100 }, () => ({ note: "x".repeat(20_000) })) }; },
  },
];
const registry = createRegistry(reads, []);
const deps = (over: Partial<HandlerDeps<unknown>> = {}): HandlerDeps<unknown> =>
  ({ pairing: () => SITE, registry, nonces: testNonces(), answers: testAnswers(), now: () => NOW, deadlineMs: 30, ...over }) as HandlerDeps<unknown>;

describe("the handler", () => {
  it("answers a refusal with a code it may not use as internal, never a sentence", async () => {
    for (const mode of ["refuseOddly", "refuseMadeUp"]) {
      const r = await handleOperation(request("things.get", body("things.get", { mode })), "things.get", deps());
      expect([r.status, r.body]).toEqual([500, '{"error":{"code":"internal"}}']);
    }
  });

  it("awaits an async limiter", async () => {
    const no = await handleOperation(request("things.get", body("things.get")), "things.get", deps({ allow: async () => false }));
    expect(code(no)).toBe("rate_limited");
    const yes = await handleOperation(request("things.get", body("things.get")), "things.get", deps({ allow: async () => true }));
    expect(yes.status).toBe(200);
  });

  it("refuses a request whose path does not end in /ops/<the operation>", async () => {
    const r = await handleOperation(request("things.get", body("things.get"), { path: "/wire/v0/ops/other" }), "things.get", deps());
    expect(code(r)).toBe("bad_input");
    const d = await handleOperation(request("describe", body("describe"), { path: "/wire/v0/ops/things.get" }), "describe", deps());
    expect(code(d)).toBe("bad_input");
  });

  it("refuses a body that is not UTF-8", async () => {
    const bytes = Buffer.concat([Buffer.from('{"op":"things.get","input":{"note":"'), Buffer.from([0xff]), Buffer.from('"},"marked":false}')]);
    expect(code(await handleOperation(request("things.get", bytes), "things.get", deps()))).toBe("bad_input");
    // The same body with a real character in that place is taken, so it was the bytes that were refused.
    const fine = Buffer.concat([Buffer.from('{"op":"things.get","input":{"note":"'), Buffer.from("\u00e9", "utf8"), Buffer.from('"},"marked":false}')]);
    expect((await handleOperation(request("things.get", fine), "things.get", deps())).status).toBe(200);
    // A byte-order mark at the start refuses the body whole.
    const withMark = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(body("things.get"))]);
    expect(code(await handleOperation(request("things.get", withMark), "things.get", deps()))).toBe("bad_input");
  });

  it("aborts a read's signal at the deadline", async () => {
    const r = await handleOperation(request("things.get", body("things.get", { mode: "slow" })), "things.get", deps());
    expect(code(r)).toBe("unavailable");
    expect(seenSignal?.aborted).toBe(true);
    await handleOperation(request("things.get", body("things.get")), "things.get", deps({ deadlineMs: 1000 }));
    expect(seenSignal?.aborted).toBe(false);
  });

  it("answers a read that refuses before it returns a promise with its refusal, and leaves no deadline timer running", async () => {
    // With timers this test controls, a deadline timer that was set and never cleared is still counted when the answer is back.
    vi.useFakeTimers();
    try {
      const lines: string[] = [];
      const d = deps({ deadlineMs: 60_000, log: (l) => { lines.push(l); } });
      const refused = await handleOperation(request("things.atOnce", body("things.atOnce", { mode: "refuse" })), "things.atOnce", d);
      expect([refused.status, refused.body]).toEqual([404, '{"error":{"code":"not_found"}}']);
      expect(vi.getTimerCount()).toBe(0);
      expect(lines).toEqual([]);
      // Any other throw is still `internal`, and its timer is cleared as well.
      const failed = await handleOperation(request("things.atOnce", body("things.atOnce", { mode: "fail" })), "things.atOnce", d);
      expect([failed.status, failed.body]).toEqual([500, '{"error":{"code":"internal"}}']);
      expect(vi.getTimerCount()).toBe(0);
      expect(lines).toEqual(["[wire] a request failed: Error"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("answers internal when its own answer fits its declaration and is over 1 MiB, and tells the log", async () => {
    const lines: string[] = [];
    const r = await handleOperation(request("things.big", body("things.big")), "things.big", deps({ deadlineMs: 5000, log: (l) => { lines.push(l); } }));
    expect([r.status, r.body]).toEqual([500, '{"error":{"code":"internal"}}']);
    expect(lines).toEqual(["[wire] things.big answered more than 1 MiB"]);
  });

  it("refuses a body of 100,000 opening brackets, and is still standing (contract section 6: nesting, without recursion)", async () => {
    const deep = [
      "[".repeat(100_000),
      "[".repeat(50_000) + "]".repeat(50_000),
      // Well formed in every other way, with an input 40 objects deep.
      `{"op":"things.get","input":${'{"a":'.repeat(40)}1${"}".repeat(40)},"marked":false}`,
    ];
    for (const text of deep) {
      const r = await handleOperation(request("things.get", text), "things.get", deps());
      expect([r.status, r.body], text.slice(0, 40)).toEqual([400, '{"error":{"code":"bad_input"}}']);
    }
    expect((await handleOperation(request("things.get", body("things.get")), "things.get", deps())).status).toBe(200);
  });

  it("calls store methods as methods, so a store written as a class works", async () => {
    class ClassNonces implements NonceStore {
      private used = new Set<string>();
      async claim(scope: { pairing: string; keyId: string }, nonce: string) {
        const k = `${scope.pairing}/${scope.keyId}/${nonce}`;
        if (this.used.has(k)) return false;
        this.used.add(k);
        return true;
      }
      async forgetBefore() { return 0; }
    }
    const req = request("things.get", body("things.get"));
    const d = deps({ nonces: new ClassNonces() });
    expect((await handleOperation(req, "things.get", d)).status).toBe(200);
    expect(code(await handleOperation(req, "things.get", d))).toBe("replayed");
  });
});

describe("reading a body", () => {
  it("reads a Node stream, and stops one byte past the cap", async () => {
    expect(Buffer.from(await readCapped(Readable.from([Buffer.from("ab"), "c"]))).toString()).toBe("abc");
    const big = Readable.from((function* () { for (let i = 0; i < 100; i++) yield Buffer.alloc(10_000, 0x20); })());
    expect((await readCapped(big, { limit: 50_000 })).length).toBe(50_001);
  });
  it("times out a body that does not arrive, for both kinds of stream", async () => {
    const stalledNode = new Readable({ read() {} });
    await expect(readCapped(stalledNode, { timeoutMs: 20 })).rejects.toBeInstanceOf(BodyReadTimeout);
    expect(stalledNode.destroyed).toBe(true);
    const stalledWeb = new ReadableStream<Uint8Array>({ pull() { return new Promise(() => {}); } });
    await expect(readCapped(stalledWeb, { timeoutMs: 20 })).rejects.toBeInstanceOf(BodyReadTimeout);
  });
});

describe.skipIf(!hasTestDb)("writes on Postgres (needs TEST_DATABASE_URL)", () => {
  let t: TestSchema;
  beforeAll(async () => { t = await freshSchema(); await t.sql`CREATE TABLE things (id text PRIMARY KEY, hidden boolean NOT NULL)`; });
  afterAll(async () => { await t?.drop(); });

  const ops = (big: () => boolean): WireOperation<Tx>[] => [{
    name: "things.hide", write: true,
    input: [{ name: "id", type: "id" }, { name: "refuse", type: "choice", of: ["conflict", "not_found", "bad_input"], optional: true }],
    // A hundred notes of 20,000 characters fit the declaration and are well over 1 MiB together.
    answer: [{ name: "notes", type: "list", of: [{ name: "note", type: "text", maxLength: 20_000, provenance: "outside" }] }],
    async run(input, ctx) {
      const tx = ctx.tx!;
      await tx`INSERT INTO things (id, hidden) VALUES (${input.id as string}, true)`;
      if (input.refuse) throw new WireRefusal(input.refuse as "conflict");
      return { notes: big() ? Array.from({ length: 100 }, () => ({ note: "x".repeat(20_000) })) : [{ note: "done" }] };
    },
  }];
  const pgDeps = (big: () => boolean): HandlerDeps<Tx> => {
    const st = postgresStores(t.sql);
    return { pairing: () => SITE, registry: createRegistry(ops(big), []), nonces: st.nonces, answers: st.answers, now: () => NOW };
  };
  const exists = async (id: string) => (await t.sql`SELECT 1 FROM things WHERE id = ${id}`).length === 1;

  it("rolls a write back when its answer is over 1 MiB, keeps nothing, and lets the retry run again", async () => {
    let big = true;
    const d = pgDeps(() => big);
    const hide = body("things.hide", { id: "t-big" });
    const first = await handleOperation(request("things.hide", hide, { retry: "retry-big-0000000001" }), "things.hide", d);
    expect([first.status, code(first)]).toEqual([500, "internal"]);
    expect(await exists("t-big")).toBe(false);
    expect((await t.sql`SELECT 1 FROM wire_answers WHERE retry_key = 'retry-big-0000000001'`).length).toBe(0);
    big = false;
    const retry = await handleOperation(request("things.hide", hide, { retry: "retry-big-0000000001" }), "things.hide", d);
    expect([retry.status, retry.body]).toEqual([200, '{"data":{"notes":[{"note":"done"}]}}']);
    expect(await exists("t-big")).toBe(true);
  });

  it("undoes what a write did before refusing, and keeps the refusal as its answer", async () => {
    const d = pgDeps(() => false);
    for (const refuse of ["conflict", "not_found", "bad_input"]) {
      const id = `t-${refuse}`;
      const hide = body("things.hide", { id, refuse });
      const key = `retry-${refuse}-0000000`.replace(/_/g, "-").slice(0, 20).padEnd(16, "0");
      const r = await handleOperation(request("things.hide", hide, { retry: key }), "things.hide", d);
      expect(code(r), refuse).toBe(refuse);
      expect(await exists(id), refuse).toBe(false);
      const again = await handleOperation(request("things.hide", hide, { retry: key }), "things.hide", d);
      expect(again.body).toBe(r.body);
      expect(await exists(id)).toBe(false);
      expect((await t.sql`SELECT answer FROM wire_answers WHERE retry_key = ${key}`)[0]?.answer).toEqual({ status: r.status, body: { error: { code: refuse } } });
    }
  });
});

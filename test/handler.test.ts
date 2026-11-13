import type { KeyObject } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createRegistry, describeProblems, handleOperation, headersOf, loadWireKeys, newKeyPair, newNonce, privateKeyFromSeed, publicKeyToWire,
  readCapped, signWire, testAnswers, testNonces, WIRE_BODY_MAX_BYTES, WireRefusal,
  type HandlerDeps, type SitePairing, type WireHttpRequest, type WireOperation,
} from "../src/index.js";
import { postgresStores } from "../src/postgres.js";
import { freshSchema, hasTestDb, type TestSchema } from "./pg.js";

// A key made inside the test. Never a real key.
const board = newKeyPair();
const NOW = new Date("2099-01-01T00:00:00Z");
const SECONDS = Math.floor(NOW.getTime() / 1000);
// The site's keys, loaded once, ahead of every request: one live key and one already retired.
const KEYS = loadWireKeys([
  { id: "op-t1", pairing: "site-test", direction: "operation", publicKey: board.publicKey, from: "2098-12-01T00:00:00Z" },
  { id: "op-old", pairing: "site-test", direction: "operation", publicKey: board.publicKey, from: "2098-11-01T00:00:00Z", until: "2098-12-31T00:00:00Z" },
]);
const SITE: SitePairing = { pairing: "site-test", keys: KEYS };
const otherBoard = privateKeyFromSeed(Buffer.alloc(32, 9));

let hides = 0;
const marks: boolean[] = [];
const OPS: WireOperation<unknown>[] = [
  {
    name: "things.get", write: false,
    input: [{ name: "id", type: "id" }, { name: "mode", type: "choice", of: ["extra", "slow", "throw"], optional: true }],
    answer: [{ name: "id", type: "id", prefix: "T-", provenance: "code" }, { name: "title", type: "text", maxLength: 200, provenance: "outside" }],
    async run(input, ctx) {
      marks.push(ctx.marked);
      if (input.id === "T-none") throw new WireRefusal("not_found");
      if (input.mode === "extra") return { id: input.id, title: "x", secret: "never" };
      if (input.mode === "slow") return new Promise((r) => setTimeout(() => r({ id: input.id, title: "late" }), 200));
      if (input.mode === "throw") throw new Error("boom");
      return { id: input.id, title: "A title" };
    },
  },
  {
    name: "things.hide", write: true,
    input: [{ name: "id", type: "id" }, { name: "note", type: "text", maxLength: 10, optional: true }],
    answer: [{ name: "changed", type: "yesNo", provenance: "code" }],
    async run(_input, ctx) {
      // A site may refuse a marked request for an operation, in its own code.
      if (ctx.marked) throw new WireRefusal("bad_input");
      hides++;
      return { changed: true };
    },
  },
];
const EVENTS = [{ kind: "site.things.hidden", sender: "system" as const, fields: [{ name: "count", type: "number" as const, min: 0 }] }];
const registry = createRegistry(OPS, EVENTS);

function deps(over: Partial<HandlerDeps<unknown>> = {}): HandlerDeps<unknown> {
  return {
    pairing: () => SITE, registry, nonces: testNonces(), answers: testAnswers(), now: () => NOW, deadlineMs: 50, ...over,
  } as HandlerDeps<unknown>;
}

function request(op: string, body: string, o: { retry?: string; pairing?: string; key?: KeyObject; keyId?: string; method?: string } = {}): WireHttpRequest {
  const path = `/wire/v0/ops/${op}`;
  const headers = signWire({
    direction: "operation", method: "POST", path, body, keyId: o.keyId ?? "op-t1", pairing: o.pairing ?? "site-test", privateKey: o.key ?? board.privateKey,
    time: SECONDS, nonce: newNonce(), retry: o.retry,
  });
  return { method: o.method ?? "POST", path, headers, body: Buffer.from(body) };
}
/** An operation's body: exactly `op`, `input` and `marked`. */
const body = (op: string, input: unknown = {}, marked = false): string => JSON.stringify({ op, input, marked });
const DESCRIBE = body("describe");

const code = (r: { body: string | null }) => (JSON.parse(r.body ?? "null") as { error?: { code: string } })?.error?.code;
const NOT_VERIFIED = [401, '{"error":{"code":"bad_signature"}}'];

describe("the keys", () => {
  it("loaded with no problem", () => {
    expect([KEYS.size, KEYS.problems]).toEqual([2, []]);
  });
});

describe("not paired", () => {
  const ERROR_HEADERS = { "cache-control": "no-store", "x-robots-tag": "noindex", "content-type": "application/json" };
  const PATH = "/wire/v0/ops/describe";
  // Two paired sites that do not hold the key the requests below are signed with: one holds another key under the id they name, the
  // other holds a key under another id only.
  const heldUnder = (id: string): SitePairing => ({
    pairing: "site-test",
    keys: loadWireKeys([{ id, pairing: "site-test", direction: "operation", publicKey: publicKeyToWire(otherBoard), from: "2098-12-01T00:00:00Z" }]),
  });
  const sameId = heldUnder("op-t1"), otherId = heldUnder("op-else");
  const SITES: readonly (readonly [what: string, pairing: () => SitePairing | null])[] = [
    ["paired, holding another key under that id", () => sameId],
    ["paired, holding a key under another id", () => otherId],
    ["not paired", () => null],
    ["a pairing that cannot be read", () => { throw new Error("bad config"); }],
  ];
  const REQUESTS: readonly (readonly [what: string, make: () => WireHttpRequest, status: number, body: string])[] = [
    ["a bare GET", () => ({ method: "GET", path: PATH, headers: {}, body: new Uint8Array() }), 400, '{"error":{"code":"bad_version"}}'],
    ["the wrong version", () => { const r = request("describe", DESCRIBE); return { ...r, headers: { ...r.headers, "wire-version": "v1" } }; },
      400, '{"error":{"code":"bad_version"}}'],
    ["an unsigned POST", () => ({ method: "POST", path: PATH, headers: { "wire-version": "v0" }, body: Buffer.from(DESCRIBE) }),
      400, '{"error":{"code":"bad_request"}}'],
    ["a correctly signed POST", () => request("describe", DESCRIBE), 401, '{"error":{"code":"bad_signature"}}'],
  ];

  it("answers every request exactly as a paired site that does not hold its key does: the same status, body and headers", async () => {
    expect([sameId.keys.problems, otherId.keys.problems]).toEqual([[], []]);
    for (const [what, make, status, text] of REQUESTS) {
      const req = make();
      for (const [site, pairing] of SITES) {
        const r = await handleOperation(req, "describe", deps({ pairing }));
        // The contract's own answer (sections 3 and 4), byte for byte, whoever is asked: an unpaired site holds no key, and a key
        // that is not held is `bad_signature` with status 401, after every earlier check.
        expect(r, `${what}, ${site}`).toEqual({ status, headers: ERROR_HEADERS, body: text });
      }
    }
  });

  it("asks the limit first and then runs the same checks, the one verification among them; nothing is claimed", async () => {
    const asked: [string, string | undefined][] = [];
    const lines: string[] = [];
    let claims = 0, reads = 0;
    const d = deps({
      pairing: () => null,
      allow: (pairing, source) => { asked.push([pairing, source]); return asked.length <= 1; },
      nonces: { claim: () => { claims++; return true; }, forgetBefore: async () => 0 },
      log: (l) => { lines.push(l); },
    });
    // Within the limit: the request goes through the checks to the key, which is not held. Only the log is told so.
    const signed = await handleOperation({ ...request("describe", DESCRIBE), source: "203.0.113.7" }, "describe", d);
    expect([signed.status, signed.body]).toEqual(NOT_VERIFIED);
    // Past the limit: `rate_limited`, and the request's headers and body are never read, so nothing is hashed or verified.
    const req = request("describe", DESCRIBE);
    const watched: WireHttpRequest = {
      method: req.method, path: req.path,
      get headers() { reads++; return req.headers; },
      get body() { reads++; return req.body; },
    };
    const limited = await handleOperation(watched, "describe", d);
    expect([limited.status, limited.body, limited.headers]).toEqual([429, '{"error":{"code":"rate_limited"}}', ERROR_HEADERS]);
    expect(reads).toBe(0);
    // A site that is not paired has no pairing id: the limit is asked with the empty string, which is no pairing's id.
    expect(asked).toEqual([["", "203.0.113.7"], ["", undefined]]);
    expect(lines).toEqual(["[wire] not verified: no_key (key op-t1)"]);
    expect(claims).toBe(0);
  });

  it("tells why a pairing could not be read to the log only", async () => {
    const lines: string[] = [];
    const d = deps({ pairing: () => { throw new RangeError("the reason, in the site's own words"); }, log: (l) => { lines.push(l); } });
    const r = await handleOperation(request("describe", DESCRIBE), "describe", d);
    expect(r).toEqual({ status: 401, headers: ERROR_HEADERS, body: '{"error":{"code":"bad_signature"}}' });
    expect(lines).toEqual(["[wire] the pairing could not be read (RangeError); answering as a site that is not paired", "[wire] not verified: no_key (key op-t1)"]);
    // A log that fails changes nothing about the answer.
    const quiet = await handleOperation(request("describe", DESCRIBE), "describe", deps({ pairing: () => { throw new Error("x"); }, log: () => { throw new Error("log down"); } }));
    expect(quiet).toEqual(r);
  });
});

describe("a request that is not a POST, at a paired site", () => {
  const ERROR_HEADERS = { "cache-control": "no-store", "x-robots-tag": "noindex", "content-type": "application/json" };

  it("is answered as the contract's checks answer it: bad_request, in the body every refusal has (sections 3 and 4)", async () => {
    let claims = 0;
    const inner = testNonces();
    const d = deps({ nonces: { claim: (scope, nonce) => { claims++; return inner.claim(scope, nonce); }, forgetBefore: (cutoff) => inner.forgetBefore(cutoff) } });
    // Signed in every other way, so the method is the one thing wrong.
    for (const method of ["GET", "get", "PUT", "DELETE", "HEAD", "OPTIONS"]) {
      const r = await handleOperation(request("describe", DESCRIBE, { method }), "describe", d);
      expect([r.status, r.body, r.headers], method).toEqual([400, '{"error":{"code":"bad_request"}}', ERROR_HEADERS]);
    }
    // A request refused at the method never uses a one-use number up.
    expect(claims).toBe(0);
    // `post` is POST (section 2): the method is compared without regard to the case of A to Z.
    expect((await handleOperation(request("describe", DESCRIBE, { method: "post" }), "describe", d)).status).toBe(200);
    expect(claims).toBe(1);
  });

  it("keeps the order of the checks: the limit first, then the version, then the method", async () => {
    const bare: WireHttpRequest = { method: "GET", path: "/wire/v0/ops/describe", headers: {}, body: new Uint8Array() };
    const unversioned = await handleOperation(bare, "describe", deps());
    expect([unversioned.status, unversioned.body, unversioned.headers]).toEqual([400, '{"error":{"code":"bad_version"}}', ERROR_HEADERS]);
    const limited = await handleOperation(request("describe", DESCRIBE, { method: "GET" }), "describe", deps({ allow: () => false }));
    expect([limited.status, limited.body]).toEqual([429, '{"error":{"code":"rate_limited"}}']);
  });
});

describe("paired", () => {
  it("answers describe from the registry, and it is a well-formed describe", async () => {
    const r = await handleOperation(request("describe", DESCRIBE), "describe", deps());
    expect(r.status).toBe(200);
    expect(r.headers).toEqual({ "cache-control": "no-store", "x-robots-tag": "noindex", "content-type": "application/json" });
    const data = (JSON.parse(r.body!) as { data: unknown }).data;
    expect(data).toEqual(registry.describe);
    expect(describeProblems(data)).toEqual([]);
    expect((data as { operations: { freeText: boolean }[] }).operations.map((o) => o.freeText)).toEqual([true, false]);
  });

  it("refuses a request check with exactly its code", async () => {
    const elsewhere = await handleOperation(request("describe", DESCRIBE, { pairing: "site-prod" }), "describe", deps());
    expect([elsewhere.status, elsewhere.body]).toEqual(NOT_VERIFIED);
    const stranger = await handleOperation(request("describe", DESCRIBE, { key: otherBoard }), "describe", deps());
    expect([stranger.status, stranger.body]).toEqual(NOT_VERIFIED);
    const req = request("describe", DESCRIBE);
    const d = deps();
    expect((await handleOperation(req, "describe", d)).status).toBe(200);
    const again = await handleOperation(req, "describe", d);
    expect([again.status, again.body]).toEqual([409, '{"error":{"code":"replayed"}}']);
  });

  it("tells the site's log why a request did not verify, and the response nothing", async () => {
    const lines: string[] = [];
    const d = deps({ log: (l) => { lines.push(l); } });
    const answers = [
      await handleOperation(request("describe", DESCRIBE, { key: otherBoard }), "describe", d),
      await handleOperation(request("describe", DESCRIBE, { keyId: "op-other" }), "describe", d),
      await handleOperation(request("describe", DESCRIBE, { keyId: "op-old" }), "describe", d),
      // A key id that has no key id's shape is a stranger's text: the log gets the cause and no id.
      await handleOperation(request("describe", DESCRIBE, { keyId: "not a key id" }), "describe", d),
    ];
    // One status, one body and the same headers, whatever the cause.
    for (const r of answers) expect(r).toEqual(answers[0]);
    expect([answers[0]!.status, answers[0]!.body]).toEqual(NOT_VERIFIED);
    expect(lines).toEqual([
      "[wire] not verified: bad_signature (key op-t1)",
      "[wire] not verified: no_key (key op-other)",
      "[wire] not verified: key_retired (key op-old)",
      "[wire] not verified: no_key",
    ]);
  });

  it("answers a key whose record had a problem exactly as a key it does not hold, and tells only the log (unusable_key)", async () => {
    const keys = loadWireKeys([
      { id: "op-t1", pairing: "site-test", direction: "operation", publicKey: board.publicKey, from: "2098-12-01T00:00:00Z" },
      // A store's own column that came along: the whole record is never used, though its key is the board's real one.
      { id: "op-extra", pairing: "site-test", direction: "operation", publicKey: board.publicKey, from: "2098-12-01T00:00:00Z", revokedAt: "2098-12-15T00:00:00Z" },
    ]);
    expect(keys.problems.length).toBeGreaterThan(0);
    for (const p of keys.problems) expect(p).toMatch(/^key 2: /);
    const lines: string[] = [];
    const d = deps({ pairing: () => ({ pairing: "site-test", keys }), log: (l) => { lines.push(l); } });
    const unusable = await handleOperation(request("describe", DESCRIBE, { keyId: "op-extra" }), "describe", d);
    const unknown = await handleOperation(request("describe", DESCRIBE, { keyId: "op-none" }), "describe", d);
    expect([unusable.status, unusable.body]).toEqual(NOT_VERIFIED);
    // The same status, body and headers: a code and nothing else, whatever the cause.
    expect(unusable).toEqual(unknown);
    expect(JSON.parse(unusable.body!)).toEqual({ error: { code: "bad_signature" } });
    expect(lines).toEqual(["[wire] not verified: unusable_key (key op-extra)", "[wire] not verified: no_key (key op-none)"]);
    // The sound key beside it still works.
    expect((await handleOperation(request("describe", DESCRIBE), "describe", d)).status).toBe(200);
  });

  it("answers the same when the log throws or its promise rejects", async () => {
    for (const log of [() => { throw new Error("log down"); }, async () => { throw new Error("log down later"); }]) {
      const r = await handleOperation(request("describe", DESCRIBE, { key: otherBoard }), "describe", deps({ log }));
      expect([r.status, r.body]).toEqual(NOT_VERIFIED);
      const ok = await handleOperation(request("things.get", body("things.get", { id: "T-1", mode: "extra" })), "things.get", deps({ log }));
      expect([ok.status, code(ok)]).toEqual([500, "internal"]);
    }
  });

  it("hands a wire header sent twice to the check as it arrived, and the check reads it as absent", async () => {
    // Contract section 2: a required header there twice is missing (`bad_request`), and a missing version is `bad_version`.
    const want: Record<string, string> = {
      "wire-version": "bad_version", "wire-key": "bad_request", "wire-time": "bad_request", "wire-nonce": "bad_request",
      "wire-body": "bad_request", "wire-signature": "bad_request",
    };
    for (const [name, expected] of Object.entries(want)) {
      const req = request("describe", DESCRIBE);
      const value = req.headers[name] as string;
      const once = Object.entries(req.headers) as [string, string][];
      // As a list of two values (raw pairs), as one value joined with a comma (a Fetch `Headers`), and under two spellings.
      const asList = headersOf([...once, [name, value]]);
      expect(asList[name], name).toEqual([value, value]);
      const joined = headersOf(new Headers([...once, [name, value]]));
      expect(joined[name], name).toBe(`${value}, ${value}`);
      const twoSpellings = headersOf([...once, [name.toUpperCase(), value]]);
      expect([twoSpellings[name], twoSpellings[name.toUpperCase()]], name).toEqual([value, value]);
      for (const headers of [asList, joined, twoSpellings]) {
        const r = await handleOperation({ ...req, headers }, "describe", deps());
        expect([r.status, code(r)], name).toEqual([400, expected]);
      }
    }
  });

  it("reads a wire-retry that is there twice as no retry key at all, never as a malformed one (section 2)", async () => {
    type Sent = Record<string, string | string[]>;
    // A header there twice: as a list of two values, as one value joined with a comma, and under two spellings.
    const twice = (headers: Sent, value: string): Sent[] => [
      { ...headers, "wire-retry": [value, value] },
      { ...headers, "wire-retry": `${value}, ${value}` },
      { ...headers, "wire-retry": value, "Wire-Retry": value },
    ];
    const before = hides;
    const get = body("things.get", { id: "T-1" }), hide = body("things.hide", { id: "T-1" });
    const key = "retry-twice-00000001";

    // A read signed with no retry key: the header is not there, and a read needs none. A malformed value twice is not there either.
    for (const value of [key, "-not-a-retry-key"]) {
      const req = request("things.get", get);
      for (const headers of twice(req.headers as Sent, value)) {
        const r = await handleOperation({ ...req, headers }, "things.get", deps());
        expect([r.status, r.body], value).toEqual([200, '{"data":{"id":"T-1","title":"A title"}}']);
      }
    }
    // A write signed with no retry key: it has none, and a write needs one.
    {
      const req = request("things.hide", hide);
      for (const headers of twice(req.headers as Sent, key)) {
        const r = await handleOperation({ ...req, headers }, "things.hide", deps());
        expect([r.status, code(r)]).toEqual([400, "missing_retry_key"]);
      }
    }
    // A write signed with that retry key: the receiver signs an empty retry line, so the signature does not verify.
    {
      const req = request("things.hide", hide, { retry: key });
      expect(req.headers["wire-retry"]).toBe(key);
      for (const headers of twice(req.headers as Sent, key)) {
        const r = await handleOperation({ ...req, headers }, "things.hide", deps());
        expect([r.status, r.body]).toEqual(NOT_VERIFIED);
      }
    }
    expect(hides).toBe(before);
  });

  it("folds a header's name and the method for A to Z only: the Kelvin sign is not a K, and a long s is not an S (section 2)", async () => {
    // Both fold to the real letter under Unicode's rules, which is why an adapter must never fold with them.
    expect(["wire-\u212aey".toLowerCase(), "PO\u017fT".toUpperCase()]).toEqual(["wire-key", "POST"]);
    const req = request("describe", DESCRIBE);
    const { "wire-key": key, ...rest } = req.headers;
    // `wire-key` spelt with the Kelvin sign is another header: the real one is missing.
    for (const headers of [{ ...rest, "wire-\u212aey": key }, headersOf([...Object.entries(rest), ["wire-\u212aey", key]] as [string, string][])]) {
      const kelvin = await handleOperation({ ...req, headers }, "describe", deps());
      expect([kelvin.status, kelvin.body]).toEqual([400, '{"error":{"code":"bad_request"}}']);
    }
    // The method spelt with a long s is not POST.
    const longS = await handleOperation({ ...req, method: "PO\u017fT" }, "describe", deps());
    expect([longS.status, longS.body]).toEqual([400, '{"error":{"code":"bad_request"}}']);
    // The letters A to Z do fold: every name in capitals and the method in lowercase is the same request.
    const capitals = Object.fromEntries(Object.entries(req.headers).map(([name, value]) => [name.toUpperCase(), value]));
    expect((await handleOperation({ ...req, method: "post", headers: capitals }, "describe", deps())).status).toBe(200);
  });

  it("refuses a body of 256 KiB and one byte as body_too_large, before the body is hashed", async () => {
    // The headers are signed for another body. Were the hash looked at first, the answer would be body_mismatch, as it is at the cap.
    const req = request("describe", DESCRIBE);
    const over = await handleOperation({ ...req, body: Buffer.alloc(WIRE_BODY_MAX_BYTES + 1, 0x20) }, "describe", deps());
    expect([over.status, over.body]).toEqual([413, '{"error":{"code":"body_too_large"}}']);
    const atCap = await handleOperation({ ...req, body: Buffer.alloc(WIRE_BODY_MAX_BYTES, 0x20) }, "describe", deps());
    expect([atCap.status, atCap.body]).toEqual([400, '{"error":{"code":"body_mismatch"}}']);
  });

  it("refuses a body that is not exactly op, input and marked, or an input that does not fit, as bad_input", async () => {
    const before = hides;
    const cases: readonly (readonly [op: string, text: string, retry?: string])[] = [
      ["describe", body("describe", { a: 1 })],
      ["describe", body("things.get")],
      ["describe", '{"op":"describe","input":{}}'],
      ["describe", '{"op":"describe","input":{},"marked":0}'],
      ["describe", '{"op":"describe","input":{},"marked":false,"extra":1}'],
      ["describe", '{"op":"describe","op":"describe","input":{},"marked":false}'],
      ["describe", "not json"],
      ["things.get", body("things.get", {})],
      ["things.get", body("things.get", { id: "T-1", other: 1 })],
      ["things.get", body("things.get", { id: "not an id" })],
      ["things.get", body("things.get", { id: "T-1", mode: "other" })],
      ["things.get", body("things.get", { id: "T-1", mode: null })],
      ["things.hide", body("things.hide", { id: "T-1", note: "x".repeat(11) }), "retry-bad-input-0001"],
      ["things.hide", body("things.hide", { id: "T-1", note: "" }), "retry-bad-input-0002"],
      ["things.hide", body("things.hide", { id: "T-1", note: 5 }), "retry-bad-input-0003"],
    ];
    for (const [op, text, retry] of cases) {
      const r = await handleOperation(request(op, text, { retry }), op, deps());
      expect([r.status, code(r)], text).toEqual([400, "bad_input"]);
    }
    expect(hides).toBe(before);
  });

  it("answers the body's own shape first: a malformed body is bad_input whatever the path names", async () => {
    // Contract section 5, the order: the body's shape, then the operation. A well-formed body for an operation the site does not
    // offer is unknown_operation; a body that is not one is bad_input, sent to that same operation.
    const unknown = await handleOperation(request("nope.op", body("nope.op")), "nope.op", deps());
    expect([unknown.status, code(unknown)]).toEqual([404, "unknown_operation"]);
    for (const text of ["not json", '{"op":"nope.op"}', body("things.get"), '{"input,marked":1,"op":"nope.op"}']) {
      const r = await handleOperation(request("nope.op", text), "nope.op", deps());
      expect([r.status, code(r)], text).toEqual([400, "bad_input"]);
    }
  });

  it("answers a read whose data fits, and refuses one that does not", async () => {
    const ok = await handleOperation(request("things.get", body("things.get", { id: "T-1" })), "things.get", deps());
    expect([ok.status, ok.body]).toEqual([200, '{"data":{"id":"T-1","title":"A title"}}']);
    const lines: string[] = [];
    const extra = await handleOperation(request("things.get", body("things.get", { id: "T-1", mode: "extra" })), "things.get", deps({ log: (l) => { lines.push(l); } }));
    expect([extra.status, code(extra)]).toEqual([500, "internal"]);
    expect(extra.body).not.toContain("never");
    expect(lines).toEqual(["[wire] things.get answered data that does not fit its declaration"]);
    const badId = await handleOperation(request("things.get", body("things.get", { id: "X-1" })), "things.get", deps());
    expect(code(badId)).toBe("internal");
  });

  it("answers a refusal, a failure and a slow read with their codes", async () => {
    expect(code(await handleOperation(request("things.get", body("things.get", { id: "T-none" })), "things.get", deps()))).toBe("not_found");
    const lines: string[] = [];
    const t = await handleOperation(request("things.get", body("things.get", { id: "T-1", mode: "throw" })), "things.get", deps({ log: (l) => { lines.push(l); } }));
    expect([t.status, code(t)]).toEqual([500, "internal"]);
    expect(lines).toEqual(["[wire] a request failed: Error"]);
    const slow = await handleOperation(request("things.get", body("things.get", { id: "T-1", mode: "slow" })), "things.get", deps());
    expect([slow.status, code(slow)]).toEqual([503, "unavailable"]);
  });

  it("runs a write once per retry key", async () => {
    const d = deps();
    hides = 0;
    const hide = body("things.hide", { id: "T-1" });
    expect(code(await handleOperation(request("things.hide", hide), "things.hide", d))).toBe("missing_retry_key");
    expect(code(await handleOperation(request("things.hide", hide, { retry: "-retry-hide-00000001" }), "things.hide", d))).toBe("bad_retry_key");
    const first = await handleOperation(request("things.hide", hide, { retry: "retry-hide-000000001" }), "things.hide", d);
    const again = await handleOperation(request("things.hide", hide, { retry: "retry-hide-000000001" }), "things.hide", d);
    expect([first.status, first.body]).toEqual([200, '{"data":{"changed":true}}']);
    expect(again.body).toBe(first.body);
    expect(hides).toBe(1);
    const other = await handleOperation(request("things.hide", body("things.hide", { id: "T-2" }), { retry: "retry-hide-000000001" }), "things.hide", d);
    expect([other.status, code(other)]).toEqual([409, "conflict"]);
    expect(hides).toBe(1);
  });

  it("hands marked to the operation, which may refuse a marked request itself", async () => {
    const d = deps();
    marks.length = 0;
    await handleOperation(request("things.get", body("things.get", { id: "T-1" }, true)), "things.get", d);
    await handleOperation(request("things.get", body("things.get", { id: "T-1" }, false)), "things.get", d);
    expect(marks).toEqual([true, false]);

    hides = 0;
    const refusedMarked = await handleOperation(request("things.hide", body("things.hide", { id: "T-9" }, true), { retry: "retry-marked-0000001" }), "things.hide", d);
    expect([refusedMarked.status, code(refusedMarked)]).toEqual([400, "bad_input"]);
    expect(hides).toBe(0);
    // `marked` is inside the signed body: the same retry key with marked false is another body.
    const sameKey = await handleOperation(request("things.hide", body("things.hide", { id: "T-9" }, false), { retry: "retry-marked-0000001" }), "things.hide", d);
    expect(code(sameKey)).toBe("conflict");
    const unmarked = await handleOperation(request("things.hide", body("things.hide", { id: "T-9" }, false), { retry: "retry-marked-0000002" }), "things.hide", d);
    expect([unmarked.status, unmarked.body]).toEqual([200, '{"data":{"changed":true}}']);
    expect(hides).toBe(1);
  });

  it("asks the site's limiter first, before anything is verified", async () => {
    const asked: [string, string | undefined][] = [];
    const lines: string[] = [];
    const inner = testNonces();
    let claims = 0;
    const d = deps({
      allow: (pairing, source) => { asked.push([pairing, source]); return asked.length <= 2; },
      nonces: { claim: (scope, nonce) => { claims++; return inner.claim(scope, nonce); }, forgetBefore: (cutoff) => inner.forgetBefore(cutoff) },
      log: (l) => { lines.push(l); },
    });
    expect((await handleOperation(request("describe", DESCRIBE), "describe", d)).status).toBe(200);
    // A request that will not verify is counted too: the limiter is asked before the signature is looked at.
    const unsigned = await handleOperation({ ...request("describe", DESCRIBE, { pairing: "x" }), source: "203.0.113.7" }, "describe", d);
    expect([unsigned.status, unsigned.body]).toEqual(NOT_VERIFIED);
    // Over the limit: a good request and one with no headers at all get the same answer, and nothing is verified or claimed.
    const good = await handleOperation(request("describe", DESCRIBE), "describe", d);
    const empty = await handleOperation({ method: "POST", path: "/wire/v0/ops/describe", headers: {}, body: new Uint8Array() }, "describe", d);
    expect([good.status, good.body]).toEqual([429, '{"error":{"code":"rate_limited"}}']);
    expect(empty).toEqual(good);
    expect(asked).toEqual([["site-test", undefined], ["site-test", "203.0.113.7"], ["site-test", undefined], ["site-test", undefined]]);
    expect(claims).toBe(1);
    expect(lines).toEqual(["[wire] not verified: bad_signature (key op-t1)"]);
  });
});

describe("the limit, before any check (contract section 3)", () => {
  it("answers requests past the limit rate_limited, with their headers and body never read: nothing is hashed or verified for them", async () => {
    const LIMIT = 3;
    let asked = 0, reads = 0, claims = 0;
    const lines: string[] = [];
    const d = deps({
      allow: () => ++asked <= LIMIT,
      nonces: { claim: () => { claims++; return true; }, forgetBefore: async () => 0 },
      log: (l) => { lines.push(l); },
    });
    // Each request is signed by a key the site does not hold as that id: a bad signature. Its headers and body are behind getters,
    // so a hash of the body or a check of the signature cannot happen without being counted.
    const watched = (): WireHttpRequest => {
      const req = request("describe", DESCRIBE, { key: otherBoard });
      return {
        method: req.method, path: req.path,
        get headers() { reads++; return req.headers; },
        get body() { reads++; return req.body; },
      };
    };
    for (let i = 0; i < LIMIT; i++) {
      const r = await handleOperation(watched(), "describe", d);
      expect([r.status, r.body]).toEqual(NOT_VERIFIED);
    }
    const readWithinTheLimit = reads;
    expect(readWithinTheLimit).toBeGreaterThanOrEqual(2 * LIMIT);
    expect(lines).toHaveLength(LIMIT);
    for (let i = 0; i < 5; i++) {
      const r = await handleOperation(watched(), "describe", d);
      expect([r.status, r.body]).toEqual([429, '{"error":{"code":"rate_limited"}}']);
    }
    expect(asked).toBe(LIMIT + 5);
    expect(reads).toBe(readWithinTheLimit);
    expect(lines).toHaveLength(LIMIT);
    expect(claims).toBe(0);
  });
});

describe("reading a request", () => {
  it("stops one byte past the cap", async () => {
    const big = new Request("https://site.test/x", { method: "POST", body: Buffer.alloc(WIRE_BODY_MAX_BYTES * 2, 0x20) });
    expect((await readCapped(big.body)).length).toBe(WIRE_BODY_MAX_BYTES + 1);
    expect(Buffer.from(await readCapped(new Request("https://site.test/x", { method: "POST", body: "abc" }).body)).toString()).toBe("abc");
    expect((await readCapped(null)).length).toBe(0);
  });
  it("hands headers on as they were sent: a name untouched, and a name sent twice as a list", () => {
    // A Fetch `Headers` lowercases names itself; nothing here folds a name, since the check does (for A to Z only).
    expect(headersOf(new Headers({ "Wire-Version": "v0" }))).toEqual({ "wire-version": "v0" });
    expect(headersOf([["Wire-Key", "a"], ["wire-key", "b"], ["Wire-Key", "c"]])).toEqual({ "Wire-Key": ["a", "c"], "wire-key": "b" });
    expect(headersOf(new Map<string, string | string[]>([["wire-key", ["a", "b"]], ["wire-time", "1"]]))).toEqual({ "wire-key": ["a", "b"], "wire-time": "1" });
    // The Kelvin sign is not a `k`: a name spelt with it stays another name.
    expect(Object.keys(headersOf([["wire-\u212aey", "a"]]))).toEqual(["wire-\u212aey"]);
  });
});

describe.skipIf(!hasTestDb)("a write on Postgres (needs TEST_DATABASE_URL)", () => {
  let t: TestSchema;
  beforeAll(async () => { t = await freshSchema(); });
  afterAll(async () => { await t?.drop(); });

  it("acts once across two instances, and keeps its log entry and event with its answer", async () => {
    const one = postgresStores(t.sql), two = postgresStores(t.other);
    let runs = 0;
    const op: WireOperation<import("../src/postgres.js").Tx> = {
      name: "things.hide", write: true, input: [{ name: "id", type: "id" }],
      answer: [{ name: "changed", type: "yesNo", provenance: "code" }],
      async run(input, ctx) {
        runs++;
        await one.log.append({ pairing: ctx.pairing, keyId: ctx.keyId, retryKey: ctx.retryKey!, op: "things.hide", changed: true, before: { id: input.id }, after: null }, ctx.tx);
        await one.outbox.add({ id: `ev-${ctx.retryKey}`, pairing: ctx.pairing, kind: "site.things.hidden", at: "2098-12-31T23:59:30Z", fields: { count: 1 } }, ctx.tx);
        return { changed: true };
      },
    };
    const reg = createRegistry([op], EVENTS);
    const d1 = { pairing: () => SITE, registry: reg, nonces: one.nonces, answers: one.answers, now: () => NOW };
    const d2 = { ...d1, nonces: two.nonces, answers: two.answers };
    const hide = body("things.hide", { id: "T-1" });
    const [a, b] = await Promise.all([
      handleOperation(request("things.hide", hide, { retry: "retry-pg-00000000001" }), "things.hide", d1),
      handleOperation(request("things.hide", hide, { retry: "retry-pg-00000000001" }), "things.hide", d2),
    ]);
    expect([a.status, b.status, a.body, b.body]).toEqual([200, 200, '{"data":{"changed":true}}', '{"data":{"changed":true}}']);
    expect(runs).toBe(1);
    expect(await one.log.byRetryKey("site-test", "retry-pg-00000000001")).toHaveLength(1);
    expect(await one.log.byRetryKey("site-other", "retry-pg-00000000001")).toEqual([]);
    expect(await one.outbox.get("ev-retry-pg-00000000001")).toMatchObject({ pairing: "site-test", sentAt: null, dead: false });
  });
});

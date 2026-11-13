import { createHash, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  answerFieldFits, answerFits, checkAnswerBody, checkEvent, checkOperationBody, decodeWireBody, describeProblems, errorBody, inputFits,
  loadWireKeys, parseWireJson, privateKeyFromSeed, publicKeyProblem, publicKeyToWire, signWire, verifyWire, WIRE_BODY_MAX_BYTES,
  WIRE_ERRORS, wireKeyProblems, wireWorkDone,
  type VerifySignature, type WireAnswerField, type WireDirection, type WireEventDecl, type WireInputField, type WireOperationDecl,
} from "../src/index.js";

// The contract's vectors, copied byte for byte (vectors/SOURCE.md). Every one is run here; a vector this file does not know how to
// run is a failure, never a skip.
const raw = readFileSync(new URL("../vectors/connector-wire-v0.json", import.meta.url));

/** SHA-256 of the copied file, as vectors/SOURCE.md records it. */
const FILE_SHA256 = "5d64090dc3fbd9257b5b032f5c9e9f74e043336f46256a173e322f268855df71";
/** The contract's pin (section 7): SHA-256 of the `vectors` array serialised as compact JSON, keys in the order given. */
const SIGNED_VECTORS_SHA256 = "84a50405f20e24a4cb74721b941043c031b567a1e52a5e8d01b88518f4d0ab2d";

interface SignedVector {
  name: string; pairing: string; direction: WireDirection; method: string; path: string; headers: Record<string, string>;
  body: string; write: boolean; usedBefore: string[]; now: number; expect: string;
}
type FieldVector = { name: string; expect: string } & (
  | { check: "answerValue"; field: WireAnswerField; value: unknown }
  | { check: "event"; events: WireEventDecl[]; body?: string; bodyHex?: string; field?: string }
  | { check: "describe"; describe: unknown }
  | { check: "input"; input: WireInputField[]; value: unknown }
  | { check: "answer"; answer: WireAnswerField[]; value: unknown }
  | { check: "operationBody"; operations: WireOperationDecl[]; op: string; body?: string; bodyHex?: string }
  | { check: "answerBody"; operations: WireOperationDecl[]; op: string; status: number; body?: string; bodyHex?: string }
  | { check: "publicKey"; publicKey: unknown }
  | { check: "key"; key: unknown }
  | { check: "body"; body?: string; bodyHex?: string }
);

const page = JSON.parse(raw.toString("utf8")) as {
  wire: string; now: number; pairing: string; seeds: Record<string, string>; keys: unknown[]; errorBody: string;
  vectors: SignedVector[]; fieldVectors: FieldVector[];
};

// "Load `keys` first" (section 7): once, ahead of every request.
const ring = loadWireKeys(page.keys);

/** A to Z only, as HTTP folds a header's name (section 2). */
const lower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
/**
 * A vector's headers as a receiver reads them (section 2): names in lowercase, and a header that is there twice (a value holding a
 * comma, or two spellings of one name) left out, because it is absent.
 */
function asRead(v: SignedVector): Record<string, string> {
  const names = Object.keys(v.headers).map(lower);
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(v.headers)) {
    const n = lower(name);
    if (!value.includes(",") && names.filter((x) => x === n).length === 1) out[n] = value;
  }
  return out;
}

/** The checks that come before the key and the signature (section 3, steps 1 to 4): a request refused there runs no verify. */
const BEFORE_THE_KEY = ["bad_version", "bad_request", "bad_time", "stale", "future", "body_too_large", "body_mismatch"];

/** What a receiver answers to a signed vector, the one-use numbers it claimed, and how many signature checks it ran. */
async function received(v: SignedVector): Promise<{ answer: string; claimed: string[]; verifies: number }> {
  const used = new Set(v.usedBefore);
  const claimed: string[] = [];
  let verifies = 0;
  const verifySignature: VerifySignature = (signedString, publicKey, signature) => {
    verifies++;
    return edVerify(null, signedString, publicKey, signature);
  };
  const r = await verifyWire(
    { direction: v.direction, method: v.method, path: v.path, headers: v.headers, body: v.body },
    {
      pairing: v.pairing, keys: ring, now: new Date(v.now * 1000), write: v.write, verifySignature,
      claimNonce: (_scope, nonce) => {
        claimed.push(nonce);
        if (used.has(nonce)) return false;
        used.add(nonce);
        return true;
      },
    },
  );
  return { answer: r.ok ? "ok" : r.code, claimed, verifies };
}

describe("the copied vectors", () => {
  it("are the file the source note names", () => {
    expect(createHash("sha256").update(raw).digest("hex")).toBe(FILE_SHA256);
  });
  it("hold the 69 signed vectors the page pins by hash: 14 pass, 55 are refused", () => {
    expect(createHash("sha256").update(JSON.stringify(page.vectors)).digest("hex")).toBe(SIGNED_VECTORS_SHA256);
    expect(page.vectors).toHaveLength(69);
    expect(page.vectors.filter((v) => v.expect === "ok")).toHaveLength(14);
    expect(page.vectors.filter((v) => v.expect !== "ok")).toHaveLength(55);
    expect(new Set(page.vectors.map((v) => v.name)).size).toBe(69);
    for (const v of page.vectors) expect(["ok", ...WIRE_ERRORS], v.name).toContain(v.expect);
    const tally: Record<string, number> = {};
    for (const v of page.vectors) tally[v.expect] = (tally[v.expect] ?? 0) + 1;
    expect(tally).toEqual({
      ok: 14, bad_version: 4, bad_request: 11, bad_time: 2, stale: 3, future: 1, body_mismatch: 2, bad_signature: 22,
      missing_retry_key: 4, bad_retry_key: 4, bad_nonce: 1, replayed: 1,
    });
  });
  it("hold the 302 field vectors, as many of each check and answer as the page says", () => {
    expect(page.fieldVectors).toHaveLength(302);
    expect(new Set(page.fieldVectors.map((v) => v.name)).size).toBe(302);
    const tally: Record<string, Record<string, number>> = {};
    for (const v of page.fieldVectors) {
      const row = (tally[v.check] ??= {});
      row[v.expect] = (row[v.expect] ?? 0) + 1;
    }
    expect(tally).toEqual({
      answerValue: { fits: 9, refused: 25 },
      event: { ok: 5, bad_event: 16, unknown_event: 1, internal: 4 },
      describe: { ok: 19, refused: 105 },
      input: { fits: 6, refused: 19 },
      answer: { fits: 3, refused: 4 },
      operationBody: { ok: 5, bad_input: 18, unknown_operation: 1, internal: 4 },
      answerBody: { ok: 5, not_found: 1, rate_limited: 1, unavailable: 1, internal: 17 },
      publicKey: { ok: 1, refused: 15 },
      key: { ok: 2, refused: 9 },
      body: { ok: 2, refused: 4 },
    });
  });
  it("give each seed a public key the page holds", () => {
    const held = page.keys.map((k) => (k as { publicKey?: unknown }).publicKey);
    expect(Object.keys(page.seeds).length).toBeGreaterThan(0);
    for (const [name, seed] of Object.entries(page.seeds)) expect(held, name).toContain(publicKeyToWire(privateKeyFromSeed(Buffer.from(seed, "hex"))));
  });
  it("show the error body exactly", () => {
    expect(errorBody("replayed")).toBe(page.errorBody);
  });
});

describe("the keys, loaded once", () => {
  it("lists the seven records the page says have a problem, by position, and holds every record", () => {
    // Section 7: an `until` that is not a moment, a small-order point, a malformed id, a malformed pairing id, a key the record
    // does not have, the later of two records under one id, and the later of two under an id whose earlier record has a problem.
    // They are records 6 to 11 and record 13 of the thirteen; record 12 is the key valid from the receiver's clock exactly.
    expect(page.keys).toHaveLength(13);
    expect(ring.size).toBe(13);
    for (const p of ring.problems) expect(p).toMatch(/^key \d+: /);
    expect([...new Set(ring.problems.map((p) => /^key (\d+): /.exec(p)?.[1]))]).toEqual(["6", "7", "8", "9", "10", "11", "13"]);
  });
});

describe("the 69 signed vectors", () => {
  for (const v of page.vectors) {
    it(`${v.name}: ${v.expect}`, async () => {
      const r = await received(v);
      expect(r.answer).toBe(v.expect);
      // Exactly one signature check for every request that reaches the key, whatever its cause; none before.
      expect(r.verifies).toBe(BEFORE_THE_KEY.includes(v.expect) ? 0 : 1);
      // The one-use number is checked last: a request refused earlier never uses one up.
      expect(r.claimed).toEqual(v.expect === "ok" || v.expect === "replayed" ? [asRead(v)["wire-nonce"]] : []);
    });
  }

  it("checks and imports no key while answering", async () => {
    const before = wireWorkDone();
    for (const v of page.vectors) await received(v);
    expect(wireWorkDone()).toEqual(before);
  });

  const passing = page.vectors.filter((v) => v.expect === "ok");
  it("has fourteen to sign again", () => expect(passing).toHaveLength(14));
  for (const v of passing) {
    it(`re-signs "${v.name}" byte for byte`, () => {
      // From what the receiver reads: names in any case are the lowercase ones, a `wire-retry` holding a comma is no retry key (that
      // vector was signed with none), and the method signs as POST whatever its case.
      const read = asRead(v);
      const keyId = read["wire-key"]!;
      const seed = page.seeds[keyId];
      expect(seed, "a passing vector's key has a seed").toMatch(/^[0-9a-f]{64}$/);
      const headers = signWire({
        direction: v.direction, method: v.method, path: v.path, body: v.body, keyId, pairing: v.pairing,
        privateKey: privateKeyFromSeed(Buffer.from(seed!, "hex")),
        time: Number(read["wire-time"]), nonce: read["wire-nonce"]!, retry: read["wire-retry"],
      });
      // Every header, every byte: the same names, and each value the same string.
      expect(headers).toEqual(read);
      expect(Object.keys(headers).sort()).toEqual(Object.keys(read).sort());
    });
  }
});

/**
 * A vector's body, in whichever of its two forms the vector gives (section 7b): text (`body`) or, where its bytes are the point, hex
 * (`bodyHex`). Every check that takes a body reads it through here, so none silently reads a form it was not written for.
 */
const bodyOf = (v: { body?: unknown; bodyHex?: unknown }): string | Uint8Array => {
  const hasText = v.body !== undefined, hasHex = v.bodyHex !== undefined;
  if (hasText === hasHex) throw new Error("a body vector gives body or bodyHex, one of them");
  if (hasHex) {
    if (typeof v.bodyHex !== "string" || !/^([0-9a-f]{2})*$/.test(v.bodyHex)) throw new Error("bodyHex is hex");
    return Buffer.from(v.bodyHex, "hex");
  }
  if (typeof v.body !== "string") throw new Error("body is text");
  return v.body;
};

/** What a checker answers to a field vector (section 7b). */
function fieldAnswer(v: FieldVector): { expect: string; field?: string } {
  switch (v.check) {
    case "answerValue": return { expect: answerFieldFits(v.field, v.value) ? "fits" : "refused" };
    case "event": {
      const r = checkEvent(bodyOf(v), v.events);
      return r.ok ? { expect: "ok" } : { expect: r.code, ...(r.field !== undefined ? { field: r.field } : {}) };
    }
    case "describe": return { expect: describeProblems(v.describe).length === 0 ? "ok" : "refused" };
    case "input": return { expect: inputFits(v.input, v.value) ? "fits" : "refused" };
    case "answer": return { expect: answerFits(v.answer, v.value) ? "fits" : "refused" };
    case "operationBody": {
      const r = checkOperationBody(bodyOf(v), v.op, v.operations);
      return { expect: r.ok ? "ok" : r.code };
    }
    case "answerBody": {
      const r = checkAnswerBody(bodyOf(v), v.status, v.op, v.operations);
      return { expect: r.ok ? "ok" : r.code };
    }
    case "publicKey": return { expect: publicKeyProblem(v.publicKey) === null ? "ok" : "refused" };
    case "key": return { expect: wireKeyProblems(v.key).length === 0 ? "ok" : "refused" };
    case "body": {
      // A body a receiver parses at all (section 6): decoded, nested no deeper than 32, no key twice.
      const text = decodeWireBody(bodyOf(v));
      return { expect: text !== null && parseWireJson(text) !== null ? "ok" : "refused" };
    }
    default: throw new Error(`a check this test does not run: ${String((v as { check?: unknown }).check)}`);
  }
}

describe("the 302 field vectors", () => {
  const CHECKS = ["answerValue", "event", "describe", "input", "answer", "operationBody", "answerBody", "publicKey", "key", "body"];
  it("are of the ten checks and no other", () => {
    expect([...new Set(page.fieldVectors.map((v) => v.check as string))].sort()).toEqual([...CHECKS].sort());
  });
  it("throws at a check it does not know: a new kind of vector is a failure, never a skip", () => {
    expect(() => fieldAnswer({ name: "a vector of a later page", check: "somethingNew", expect: "ok" } as unknown as FieldVector)).toThrow(/a check this test does not run: somethingNew/);
  });
  it("give every body in one of its two forms, text or hex", () => {
    const withBody = page.fieldVectors.filter((v) => v.check === "event" || v.check === "operationBody" || v.check === "answerBody" || v.check === "body");
    expect(withBody).toHaveLength(26 + 28 + 25 + 6);
    for (const v of withBody) expect(() => bodyOf(v), v.name).not.toThrow();
    expect(() => bodyOf({})).toThrow();
    expect(() => bodyOf({ body: "{}", bodyHex: "7b7d" })).toThrow();
  });
  it("name a field at fault in nine event vectors, and in no other vector", () => {
    // `field` on an answerValue vector is the declaration it checks a value against, not a field at fault.
    const naming = page.fieldVectors.filter((v) => v.check === "event" && v.field !== undefined);
    expect(naming).toHaveLength(9);
    for (const v of naming) expect(v.expect, v.name).toBe("bad_event");
    for (const v of page.fieldVectors) if (v.check !== "event" && v.check !== "answerValue") expect("field" in v, v.name).toBe(false);
  });
  for (const v of page.fieldVectors) {
    it(`${v.check}: ${v.name}: ${v.expect}`, () => {
      const got = fieldAnswer(v);
      expect(got.expect).toBe(v.expect);
      // The field at fault: an event vector that gives one gets exactly that field, and a vector that gives none gets none (an
      // event refused for anything but a declared field, and every other check: section 6, "Which field a refusal names").
      expect(got.field).toBe(v.check === "event" ? v.field : undefined);
    });
  }
});

describe("the body's size", () => {
  const key = privateKeyFromSeed(Buffer.from(page.seeds["board-op-1"]!, "hex"));
  const path = "/wire/v0/ops/describe";
  const ctx = () => ({ pairing: page.pairing, keys: ring, now: new Date(page.now * 1000), write: false, claimNonce: () => true });
  const sign = (body: string | Uint8Array) => signWire({
    direction: "operation", method: "POST", path, body, keyId: "board-op-1", pairing: page.pairing, privateKey: key, time: page.now,
    nonce: "AAAAAAAAAAAAAAAAAAAAAA",
  });

  it("refuses a body over 256 KiB as body_too_large, before its hash is looked at", async () => {
    const body = Buffer.alloc(WIRE_BODY_MAX_BYTES + 1, 0x20);
    const r = await verifyWire({ direction: "operation", method: "POST", path, headers: sign("{}"), body }, ctx());
    expect(r).toEqual({ ok: false, code: "body_too_large" });
  });

  it("accepts exactly 256 KiB", async () => {
    const body = Buffer.alloc(WIRE_BODY_MAX_BYTES, 0x20);
    const r = await verifyWire({ direction: "operation", method: "POST", path, headers: sign(body), body }, ctx());
    expect(r).toEqual({ ok: true, keyId: "board-op-1", retry: null });
  });
});

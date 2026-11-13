/**
 * The generic connector's wire contract, v0, unstable. The written spec and its test vectors (connector-wire-v0.md and
 * test/golden/connector-wire-v0.json) are what a business's own site builds against, never this file. This file imports nothing but
 * node:crypto: it is the whole contract, and the board's own files import from it.
 *
 * Two directions, a signing key pair each: the board signs operations it sends to the site with its operation key, and the site signs events
 * it sends to the board with its event key. Each side keeps its private key and gives the other only the public one, so pairing shows no
 * secret, and a copy of the board's database cannot forge the site's events. A key pair belongs to exactly one pairing (staging and production
 * are separate pairings), and the pairing's id is signed, so a request made for one pairing is refused at another. In v0 a rotation sends
 * nothing on the wire: the owner enters the new public key (`wireKeyProblems` refuses a key record that is not a usable one), and both keys
 * of a direction are valid for the overlap (each with its own id and validity). A receiver loads its keys once (`loadWireKeys`), which checks
 * each: no check of a key runs while a request is answered. After a breach the owner pairs again, never automatically.
 *
 * Every request is a POST that carries the version, the key's id, a timestamp, a one-use number and the SHA-256 of its exact body, signed with
 * Ed25519 with the direction, method, path and pairing (`canonical`). A request outside the time window, with a number already used or a body
 * that does not match its hash is refused with a fixed code (`WIRE_ERRORS`), never a sentence. A key the receiver does not hold for this
 * direction and pairing, a key out of its validity and a bad signature all get one answer, `bad_signature`, after the same work (one signature
 * check, against a decoy key when no live key matches), so a stranger learns nothing about which keys exist; the cause goes only to the
 * receiver's own log callback. A write carries a retry key, so a timeout never acts twice.
 *
 * Every value on the wire is a typed field, declared one way for an operation's input, an event and an operation's answer: a scalar narrowed
 * by its type's own keys, a list of one scalar, or a list of one-level records. Each type has a closed list of keys; any other key is refused,
 * never ignored, and no declaration carries a regular expression or a JSON Schema. A named field may be `optional: true`: then its key may be
 * absent, and nothing else changes. Free text (`text`, always with a `maxLength`) appears in an input and in an answer, never in an event; in
 * an answer each field states its provenance: the least trusted source any value of it can have. An operation whose answer holds any outside
 * field says `freeText: true`, and its answer is outside text. Outside content that is not a field (a photo, a document, a message's words)
 * never rides on an event: the event carries its id, and the board reads it through an operation whose answer is declared outside.
 *
 * What a site or a stranger sends is never trusted to be well formed: no function here throws on any value it is given, and no problem line
 * or log value carries its text (a thing is named by its position, and a key only when it is one of the contract's own words). A declaration
 * is copied, checked and frozen once; the copy is what takes values, so the caller's object is neither changed nor trusted again.
 *
 * Pure: no clock (the caller passes `now`), no store (the caller passes `claimNonce`; `nonceMemory` is an in-process one that forgets after
 * NONCE_KEEP_SECONDS), no key kept. The caller stores the keys per pairing, loads them, and passes `checkEvent`, `checkOperationBody` and
 * `checkAnswerBody` its own declarations.
 */
import { createHash, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";

export const WIRE_VERSION = "v0";
/** A request's timestamp may be at most this far from the receiver's clock, either way; exactly this far is inside. */
export const WIRE_WINDOW_SECONDS = 300;
/**
 * How long a receiver keeps a used one-use number: twice the window and a second. A request stamped a whole window ahead is still inside the
 * window two windows later, to the second, so its number is kept one second past that.
 */
export const NONCE_KEEP_SECONDS = 2 * WIRE_WINDOW_SECONDS + 1;
/** How long a site keeps a write's answer under its retry key. */
export const RETRY_KEEP_HOURS = 24;
/** The most a request's body may be. */
export const WIRE_BODY_MAX_BYTES = 256 * 1024;
/** The most levels of objects and lists a body may nest, the body's own object being the first. Deeper is refused as any malformed body is. */
export const WIRE_BODY_MAX_DEPTH = 32;
/** The most an answer's body may be; past it the board reads the answer as `internal`. */
export const WIRE_ANSWER_MAX_BYTES = 1024 * 1024;
/** The longest the board waits for an answer. Longer work answers `{"data":{"accepted":true}}` at once and reports by event. */
export const WIRE_ANSWER_SECONDS = 10;
/** The codes a sender may try again later (with a fresh time and number), as with no answer at all; every other refusal is never retried. */
export const WIRE_RETRY_LATER = ["rate_limited", "unavailable", "internal"] as const;
/** The board's answer to an event it recorded, or already had under the same id. */
export const EVENT_RECORDED = JSON.stringify({ data: { recorded: true } });

export const WIRE_DIRECTIONS = ["operation", "event"] as const;
export type WireDirection = (typeof WIRE_DIRECTIONS)[number];
/** The one method. */
export const WIRE_METHOD = "POST";

/**
 * The headers, written here in lowercase and read whatever their ASCII case. A header whose value is empty, or that is there twice (under two
 * spellings, as a list of values, or as one value holding a comma), is absent.
 */
export const WIRE_HEADERS = {
  version: "wire-version", key: "wire-key", time: "wire-time", nonce: "wire-nonce", body: "wire-body", retry: "wire-retry", signature: "wire-signature",
} as const;

// Every pattern here matches the whole string.
export const WIRE_KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
/** A pairing's id: one per connection and place (staging and production are two). */
export const WIRE_PAIRING_ID = /^[A-Za-z0-9._-]{1,64}$/;
/** 16 random bytes, base64url without padding. */
export const WIRE_NONCE = /^[A-Za-z0-9_-]{22}$/;
/** A retry key: 16 to 64 of letters, digits, _ and -, starting with a letter or a digit, so every retry key is also an id (WIRE_ID). */
export const WIRE_RETRY_KEY = /^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$/;
/** An Ed25519 signature: 64 bytes in base64url without padding, in its one spelling (86 characters, the last carrying no spare bits). */
export const WIRE_SIGNATURE = /^[A-Za-z0-9_-]{85}[AQgw]$/;
/** Whole seconds, at most 12 digits. */
const WIRE_TIME = /^[0-9]{1,12}$/;
/** A path: no query string and no fragment. */
const WIRE_PATH = /^\/[A-Za-z0-9._~\/-]{0,511}$/;

/** Every refusal, by fixed code. The answer to one is `{"error":{"code":"<code>"}}` and nothing else. */
export const WIRE_ERRORS = [
  // The request itself (checked by `verifyWire`, in this order). `bad_signature` is the one answer to every failure of the key or the signature.
  "bad_version", "bad_request", "bad_time", "stale", "future", "body_too_large", "body_mismatch", "bad_signature",
  "missing_retry_key", "bad_retry_key", "bad_nonce", "replayed",
  // What it asked (the site's for an operation, the board's for an event). `conflict`: a retry key used again with another body; nothing is done.
  "unknown_operation", "bad_input", "not_found", "conflict", "rate_limited", "unavailable", "internal", "unknown_event", "bad_event",
] as const;
export type WireError = (typeof WIRE_ERRORS)[number];
export const errorBody = (code: WireError): string => JSON.stringify({ error: { code } });
/** The status of the one answer to a request whose key or signature does not verify, whatever the cause. */
export const WIRE_NOT_VERIFIED_STATUS = 401;

/** A public key of one direction of one pairing, as entered: its id, the raw 32-byte Ed25519 key in base64url, and when it is valid. */
export interface WireKey {
  readonly id: string; readonly pairing: string; readonly direction: WireDirection; readonly publicKey: string; readonly from: string; readonly until?: string;
}

export interface WireRequest {
  readonly direction: WireDirection;
  readonly method: string;
  readonly path: string;
  /**
   * The request's headers as a plain object: each name to its value, or to the list of its values when the name was sent more than once. An
   * adapter makes this from whatever its HTTP library gives (a Fetch `Headers`, a `Map`): those are not read here.
   */
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  readonly body: Uint8Array | string;
}

const bytes = (b: Uint8Array | string): Buffer => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b));
/** A to Z and a to z only: a header's name and a method fold case as HTTP does, never as Unicode does (the Kelvin sign is not a `k`). */
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
const asciiUpper = (s: string): string => s.replace(/[a-z]/g, (c) => String.fromCharCode(c.charCodeAt(0) - 32));
/** SHA-256 of the exact body bytes, base64url without padding. */
export const bodyHash = (body: Uint8Array | string): string => createHash("sha256").update(bytes(body)).digest("base64url");

/** The signed string: one field a line, in this order. A retry key is "" when there is none. */
export function canonical(p: { direction: WireDirection; method: string; path: string; time: string; nonce: string; body: string; key: string; retry: string;
  pairing: string }): string {
  return ["wire", WIRE_VERSION, p.direction, asciiUpper(p.method), p.path, p.time, p.nonce, p.body, p.key, p.retry, p.pairing].join("\n");
}

const publicKeyOf = (raw: string): KeyObject => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: raw }, format: "jwk" });
/** The headers for a request, signed with the sender's private key of its direction and pairing. The caller makes the nonce and passes the time. */
export function signWire(p: { direction: WireDirection; method: string; path: string; body: Uint8Array | string; keyId: string; pairing: string;
  privateKey: KeyObject; time: number; nonce: string; retry?: string }): Record<string, string> {
  const h = bodyHash(p.body);
  const time = String(Math.floor(p.time));
  const line = canonical({ direction: p.direction, method: p.method, path: p.path, time, nonce: p.nonce, body: h, key: p.keyId, retry: p.retry ?? "", pairing: p.pairing });
  const signature = edSign(null, Buffer.from(line, "utf8"), p.privateKey).toString("base64url");
  return {
    [WIRE_HEADERS.version]: WIRE_VERSION, [WIRE_HEADERS.key]: p.keyId, [WIRE_HEADERS.time]: time, [WIRE_HEADERS.nonce]: p.nonce,
    [WIRE_HEADERS.body]: h, ...(p.retry !== undefined ? { [WIRE_HEADERS.retry]: p.retry } : {}), [WIRE_HEADERS.signature]: signature,
  };
}

// ── A key, when it is entered or loaded ───────────────────────────────────────────────────────────────────────

// Curve25519's field and the Edwards curve -x² + y² = 1 + d·x²·y² (RFC 8032 §5.1).
const P = 2n ** 255n - 19n;
const mod = (a: bigint): bigint => ((a % P) + P) % P;
const pow = (base: bigint, e: bigint): bigint => { let r = 1n, b = mod(base); for (let k = e; k > 0n; k >>= 1n) { if (k & 1n) r = (r * b) % P; b = (b * b) % P; } return r; };
const inv = (a: bigint): bigint => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
type Point = { x: bigint; y: bigint };
/** A point from its 32 bytes (RFC 8032 §5.1.3), or null: a y not below p, no x for that y, or x = 0 with the sign bit set. */
function pointOf(b: Buffer): Point | null {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(b[i]!);
  const sign = y >> 255n;
  y &= (1n << 255n) - 1n;
  if (y >= P) return null;
  const u = mod(y * y - 1n), v = mod(D * y * y + 1n);
  let x = pow(u * inv(v), (P + 3n) / 8n);
  if (mod(v * x * x) !== u) x = mod(x * SQRT_M1);
  if (mod(v * x * x) !== u || (x === 0n && sign === 1n)) return null;
  if ((x & 1n) !== sign) x = P - x;
  return { x, y };
}
/** Two points added (the complete Edwards formula: it holds for every pair, doubling included). */
const addPoints = (a: Point, b: Point): Point => {
  const t = mod(D * a.x * b.x * a.y * b.y);
  return { x: mod((a.x * b.y + a.y * b.x) * inv(1n + t)), y: mod((a.y * b.y + a.x * b.x) * inv(1n - t)) };
};

/** The costly work on keys, counted: curve checks and key imports. Both happen when a key is entered or loaded, never while a request is answered. */
const work = { curveChecks: 0, keyImports: 0 };
/** How many curve checks and key imports this process has done so far, for a test or a measurement: answering a request adds to neither. */
export const wireWorkDone = (): { curveChecks: number; keyImports: number } => ({ ...work });
const importKey = (raw: string): KeyObject => { work.keyImports++; return publicKeyOf(raw); };

const KEY_SPELLING = "a public key is 32 bytes in base64url without padding";
/**
 * Why a public key cannot be used, in fixed words, or null when it can. A public key is 32 bytes in base64url without padding (43 characters,
 * in its one spelling), a point on the curve in its one encoding, and never one of the eight small-order points, against which a forged
 * signature can verify for any request. It does curve arithmetic (about a millisecond), so it is called when a key is entered or loaded
 * (`wireKeyProblems`, `loadWireKeys`), never while a request is answered.
 */
export function publicKeyProblem(raw: unknown): string | null {
  if (typeof raw !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(raw)) return KEY_SPELLING;
  const b = Buffer.from(raw, "base64url");
  if (b.length !== 32 || b.toString("base64url") !== raw) return KEY_SPELLING;
  work.curveChecks++;
  const point = pointOf(b);
  if (point === null) return "a public key is a point on the curve, in its one encoding";
  const two = addPoints(point, point), four = addPoints(two, two), eight = addPoints(four, four);
  return eight.x === 0n && eight.y === 1n ? "a public key is never a small-order point" : null;
}

const KEY_RECORD_KEYS = ["id", "pairing", "direction", "publicKey", "from", "until"];
function keyRecordProblems(key: unknown, publicKey: string | null): string[] {
  if (!isObject(key)) return ["a key is { id, pairing, direction, publicKey, from, until }"];
  const out: string[] = [];
  if (typeof key.id !== "string" || !WIRE_KEY_ID.test(key.id)) out.push("a key's id is 1 to 64 of letters, digits, . _ and -");
  if (typeof key.pairing !== "string" || !WIRE_PAIRING_ID.test(key.pairing)) out.push("a key's pairing is a pairing id: 1 to 64 of letters, digits, . _ and -");
  if (!(WIRE_DIRECTIONS as readonly unknown[]).includes(key.direction)) out.push(`a key's direction is ${WIRE_DIRECTIONS.join(" or ")}`);
  if (publicKey !== null) out.push(publicKey);
  const from = typeof key.from === "string" && realDateTime(key.from) ? Date.parse(key.from) : Number.NaN;
  if (Number.isNaN(from)) out.push("a key's from is a UTC moment");
  if (key.until !== undefined) {
    const until = typeof key.until === "string" && realDateTime(key.until) ? Date.parse(key.until) : Number.NaN;
    if (Number.isNaN(until)) out.push("a key's until is a UTC moment, or it is not there");
    else if (until <= from) out.push("a key's until is after its from");
  }
  if (Object.keys(key).some((k) => !KEY_RECORD_KEYS.includes(k))) out.push(`a key has only ${KEY_RECORD_KEYS.join(", ")}`);
  return out;
}
/**
 * Problems with a whole key record, as it is entered: its id and pairing id (their patterns), its direction, its public key
 * (`publicKeyProblem`), `from` a UTC moment, and `until` a later UTC moment or not there. Empty: the key may be stored. In fixed words.
 */
export const wireKeyProblems = (key: unknown): string[] => guarded(() => keyRecordDecided(key).problems, [NOT_JSON]);
/**
 * A key record's problems, decided on a plain copy of it: each of its fields is read once, and the copy is what is checked and what a key is
 * imported from, so a record cannot show one public key to the check and another to the import.
 */
function keyRecordDecided(key: unknown): { copy: unknown; problems: string[] } {
  let copy: unknown;
  try { copy = jsonCopy(key, { left: 256 }, 0); }
  catch (e) { return { copy: null, problems: [e instanceof RangeError ? `a key has only ${KEY_RECORD_KEYS.join(", ")}` : NOT_JSON] }; }
  return { copy, problems: keyRecordProblems(copy, publicKeyProblem(isObject(copy) ? copy.publicKey : undefined)) };
}

// ── Checking a request ────────────────────────────────────────────────────────────────────────────────────────

/**
 * The decoy: a fixed Ed25519 public key (raw, base64url) the signature is checked against when no usable live key matches, so every request
 * that reaches the key does the same work. No live key is it, and a signature that happens to verify against it is still refused.
 */
const DECOY_PUBLIC_KEY = "jUq-B0_vkinTtEHf6k-Y-AWxorOgauZFgQ7-znf9UEQ";
let decoy: KeyObject | undefined;
const decoyKey = (): KeyObject => (decoy ??= importKey(DECOY_PUBLIC_KEY));

/**
 * A loaded key: what the request path looks up. Its validity as numbers (NaN where it is not a moment: never live), whether it may be used
 * (only a record with no problem at all), and its key ready to verify with (the decoy's, when it may not be used).
 */
interface LoadedKey { readonly id: string; readonly pairing: string; readonly direction: WireDirection; readonly from: number; readonly until: number; readonly usable: boolean; readonly publicKey: KeyObject }
const rings = new WeakMap<object, readonly LoadedKey[]>();
/**
 * The keys a receiver holds, loaded: every key checked once (`wireKeyProblems`, the curve check among them) and made ready to verify with,
 * and the decoy with them. `verifyWire` takes only this, so no check of a key runs while a request is answered. `problems` lists what was
 * wrong with any key, by its position in the list given, in fixed words. **A key record with any problem is never used**: a malformed id or
 * pairing id, a key the record does not have (a store's own column), a validity that is not a moment, an unusable public key. It stays in the
 * ring only so a request that names it does the one verify against the decoy, as a request naming no key does. Two records with the same id,
 * pairing and direction are a problem of the later one: the earlier is the key, and the later is never used.
 */
export interface WireKeyring { readonly size: number; readonly problems: readonly string[] }
/** Loads the keys a receiver holds (from its store, at start and whenever a key is entered or changed). It never throws. */
export function loadWireKeys(keys: readonly unknown[]): WireKeyring {
  const loaded: LoadedKey[] = [], positions: number[] = [], problems: string[] = [];
  const spare = decoyKey();
  const list: readonly unknown[] = guarded(() => (Array.isArray(keys) ? [...keys] : []), []);
  list.forEach((record, i) => {
    const before = loaded.length;
    const read = guarded(() => {
      // The record's fields are read once, into a plain copy: that copy is what is checked, looked up and imported from.
      const { copy: k, problems: found } = keyRecordDecided(record);
      const named = isObject(k) && typeof k.id === "string" && typeof k.pairing === "string" && (WIRE_DIRECTIONS as readonly unknown[]).includes(k.direction);
      if (named) {
        const twin = loaded.findIndex((e) => e.id === k.id && e.pairing === k.pairing && e.direction === k.direction);
        if (twin >= 0) found.push(`the same id, pairing and direction as key ${positions[twin]! + 1}: the earlier one is the key`);
      }
      for (const p of found) if (problems.length <= WIRE_PROBLEMS_MAX) problems.push(`key ${i + 1}: ${p}`);
      if (!named) return true;
      const from = typeof k.from === "string" && realDateTime(k.from) ? Date.parse(k.from) : Number.NaN;
      const until = k.until === undefined ? Number.POSITIVE_INFINITY : typeof k.until === "string" && realDateTime(k.until) ? Date.parse(k.until) : Number.NaN;
      // Usable only with no problem at all: its public key is imported only then, and otherwise the decoy stands in its place.
      let usable = found.length === 0, key = spare;
      if (usable) { try { key = importKey(k.publicKey as string); } catch { usable = false; } }
      loaded.push({ id: k.id as string, pairing: k.pairing as string, direction: k.direction as WireDirection, from, until, usable, publicKey: key });
      positions.push(i);
      return true;
    }, false);
    // A key record that cannot even be read is not held at all.
    if (!read) { loaded.length = before; positions.length = before; if (problems.length <= WIRE_PROBLEMS_MAX) problems.push(`key ${i + 1}: ${NOT_JSON}`); }
  });
  const ring: WireKeyring = Object.freeze({ size: loaded.length, problems: Object.freeze(capped(problems)) });
  rings.set(ring, Object.freeze(loaded));
  return ring;
}

/** How the Ed25519 signature is checked: node:crypto's by default. A receiver may pass its platform's own; it is called exactly once a request. */
export type VerifySignature = (signedString: Buffer, publicKey: KeyObject, signature: Buffer) => boolean;
const ed25519Verify: VerifySignature = (s, k, sig) => edVerify(null, s, k, sig);

/**
 * Why a request's key or signature did not verify, for the receiver's own log only (`onUnverified`); it is never in the result a route answers
 * from. No key of that id held for this pairing and direction (`no_key`: unknown, malformed, another pairing's, the other direction's, or no
 * pairing at all), a held key outside its validity or with a validity that is not a moment (`key_retired`), a held key whose record had any
 * problem when it was loaded (`unusable_key`), or a signature that is not well formed or does not verify (`bad_signature`).
 */
export type WireUnverifiedCause = "no_key" | "key_retired" | "unusable_key" | "bad_signature";

export interface WireVerifyContext {
  readonly pairing: string;
  /** The receiver's keys, loaded (`loadWireKeys`): never a list of key records, which would have to be checked while answering. */
  readonly keys: WireKeyring;
  readonly now: Date;
  readonly write: boolean;
  readonly claimNonce: ClaimNonce;
  /**
   * Told why a request answered `bad_signature`, for the receiver's own log. Never send it. The key id is the request's own, a stranger's
   * text until the signature verifies: it is passed only when it has a key id's shape, otherwise null. A logger that throws, or whose
   * promise rejects, changes nothing.
   */
  readonly onUnverified?: (cause: WireUnverifiedCause, keyId: string | null) => void | Promise<void>;
  readonly verifySignature?: VerifySignature;
}

/**
 * A received request at one pairing, checked in a fixed order: version (a missing one is `bad_version` too); the method (POST only), every
 * required header present (an empty value, or a header there twice, is absent; names are read whatever their ASCII case) and a path matching its
 * pattern; time (digits, then inside the window, either way, exactly
 * the window being inside); body (size, then hash); key and signature together; retry key (required on a write; when present, on a read too,
 * it is signed and well formed); and last the one-use number, so a request that fails any other check never uses one up.
 *
 * The key and the signature are one check with one answer, `bad_signature`, and the same work whatever the cause: the key is looked up among
 * the loaded keys (held for this pairing and this direction, inside its validity, usable when it was loaded), exactly one Ed25519 verify runs
 * (against the decoy when no usable live key matches), and only then are the conditions combined (the signature's own shape among them), with
 * no return in between. Nothing here checks or imports a key: that was done when the keys were loaded, so the first request that names a held
 * key costs what any other does. Nothing about the key is checked before the time and the body, so a request's answer never depends on whether
 * its key id is held. The cause goes to `onUnverified` only. The receiving route rate-limits before calling this: hashing the body costs up to
 * WIRE_BODY_MAX_BYTES for anyone. `claimNonce` records the number for the key and answers false if it was already used; the number is compared
 * as a string, never decoded. The receiver keeps it NONCE_KEEP_SECONDS.
 */
export type ClaimNonce = (scope: { pairing: string; keyId: string }, nonce: string) => boolean | Promise<boolean>;
export async function verifyWire(req: WireRequest, ctx: WireVerifyContext):
  Promise<{ ok: true; keyId: string; retry: string | null } | { ok: false; code: WireError }> {
  // The request is read once, into plain values, and nothing it holds can make this throw: headers that cannot be read answer as a request
  // with no headers does (`bad_version`). Header names fold ASCII case only, and so does the method (`post` is POST). A header that
  // is there twice is absent: under two spellings, as a list of more than one value, or as one value holding a comma (how an HTTP library
  // joins a header sent twice; no wire header's own value holds one).
  const sent = new Map<string, string | undefined>();
  let method: unknown, path: unknown, given: unknown;
  try {
    const headers: unknown = req.headers;
    if (headers !== null && typeof headers === "object") {
      for (const [name, raw] of Object.entries(headers)) {
        const lower = asciiLower(name);
        const v: unknown = Array.isArray(raw) && raw.length === 1 ? raw[0] : raw;
        sent.set(lower, sent.has(lower) || typeof v !== "string" || v === "" || v.includes(",") ? undefined : v);
      }
    }
  } catch { sent.clear(); }
  try { method = req.method; path = req.path; given = req.body; } catch { method = undefined; }
  const h = (name: string): string | undefined => sent.get(name);
  if (h(WIRE_HEADERS.version) !== WIRE_VERSION) return { ok: false, code: "bad_version" };
  const keyId = h(WIRE_HEADERS.key), time = h(WIRE_HEADERS.time), nonce = h(WIRE_HEADERS.nonce), body = h(WIRE_HEADERS.body), signature = h(WIRE_HEADERS.signature);
  const retry = h(WIRE_HEADERS.retry);
  if (typeof method !== "string" || asciiUpper(method) !== WIRE_METHOD || (typeof given !== "string" && !(given instanceof Uint8Array))) return { ok: false, code: "bad_request" };
  if (!keyId || !time || !nonce || !body || !signature || typeof path !== "string" || !WIRE_PATH.test(path)) return { ok: false, code: "bad_request" };
  const now = ctx.now.getTime();
  if (!WIRE_TIME.test(time)) return { ok: false, code: "bad_time" };
  const skew = Number(time) - Math.floor(now / 1000);
  if (skew < -WIRE_WINDOW_SECONDS) return { ok: false, code: "stale" };
  if (skew > WIRE_WINDOW_SECONDS) return { ok: false, code: "future" };
  if (bytes(given).length > WIRE_BODY_MAX_BYTES) return { ok: false, code: "body_too_large" };
  if (bodyHash(given) !== body) return { ok: false, code: "body_mismatch" };
  // The key and the signature: the same steps for every request, the conditions combined only at the end. A lookup and one verify; no key is
  // checked or imported here.
  const held = rings.get(ctx.keys) ?? NO_KEYS;
  const key = held.find((k) => k.id === keyId && k.pairing === ctx.pairing && k.direction === req.direction);
  const live = key !== undefined && now >= key.from && now < key.until;
  const usable = live && key.usable;
  const publicKey = usable ? key.publicKey : decoyKey();
  const line = canonical({ direction: req.direction, method, path, time, nonce, body, key: keyId, retry: retry ?? "", pairing: ctx.pairing });
  let good = false;
  try { good = (ctx.verifySignature ?? ed25519Verify)(Buffer.from(line, "utf8"), publicKey, Buffer.from(signature, "base64url")); } catch { good = false; }
  const shaped = WIRE_SIGNATURE.test(signature);
  const cause: WireUnverifiedCause | null = key === undefined ? "no_key" : !live ? "key_retired" : !usable ? "unusable_key" : good !== true || !shaped ? "bad_signature" : null;
  if (cause !== null) {
    try {
      const told: unknown = ctx.onUnverified?.(cause, WIRE_KEY_ID.test(keyId) ? keyId : null);
      if (told !== null && typeof told === "object" && typeof (told as { then?: unknown }).then === "function") (told as PromiseLike<unknown>).then(undefined, () => undefined);
    } catch { /* a logger's failure is not the request's */ }
    return { ok: false, code: "bad_signature" };
  }
  if (ctx.write && retry === undefined) return { ok: false, code: "missing_retry_key" };
  if (retry !== undefined && !WIRE_RETRY_KEY.test(retry)) return { ok: false, code: "bad_retry_key" };
  if (!WIRE_NONCE.test(nonce)) return { ok: false, code: "bad_nonce" };
  if (!(await ctx.claimNonce({ pairing: ctx.pairing, keyId }, nonce))) return { ok: false, code: "replayed" };
  return { ok: true, keyId, retry: retry ?? null };
}
const NO_KEYS: readonly LoadedKey[] = Object.freeze([]);

/** An in-process store of used one-use numbers, per pairing and key, each forgotten NONCE_KEEP_SECONDS after it was used. */
export function nonceMemory(clock: () => Date): ClaimNonce {
  const used = new Map<string, number>();
  return (scope, nonce) => {
    const now = clock().getTime();
    for (const [k, until] of used) if (until <= now) used.delete(k);
    const k = `${scope.pairing}\n${scope.keyId}\n${nonce}`;
    if (used.has(k)) return false;
    used.set(k, now + NONCE_KEEP_SECONDS * 1000);
    return true;
  };
}

// ── Typed fields: an operation's input, an event, and an operation's answer ───────────────────────────────────

export const WIRE_SCALAR_TYPES = ["number", "choice", "id", "date", "dateTime", "yesNo"] as const;
export const WIRE_FIELD_TYPES = [...WIRE_SCALAR_TYPES, "list"] as const;
export type WireScalarType = (typeof WIRE_SCALAR_TYPES)[number];
export type WireFieldType = (typeof WIRE_FIELD_TYPES)[number];
/**
 * One value's type and narrowing: a choice's options, a number's bounds, an id's prefix. There is no pattern: a declaration never carries a
 * regular expression, so nothing a site declares is ever run as one.
 */
export interface WireScalarDecl { readonly type: WireScalarType; readonly of?: readonly string[]; readonly prefix?: string; readonly min?: number; readonly max?: number }
/**
 * Free text, in an input or an answer only: a string of at most `maxLength` Unicode code points (1 to WIRE_TEXT_MAX), well formed (no lone
 * surrogate) and with no U+0000. `maxLength` is required: no text is unbounded.
 */
export interface WireTextDecl { readonly type: "text"; readonly maxLength: number }
/** A named field's name, and whether its key may be absent: `optional` is `true` or it is not there (absent means required). */
export interface WireNamed { readonly name: string; readonly optional?: true }
/** A list of one scalar type: `of` is the item's declaration (no name, no provenance, never optional: the list's are the item's). */
export interface WireScalarList extends WireNamed { readonly type: "list"; readonly of: WireScalarDecl; readonly maxItems?: number }
/**
 * A list of records: `of` is the record's fields, each named, typed and narrowed as a field is, never a list or a record (one level deep). A row
 * holds exactly those fields (an optional one may be absent), each fitting; a missing, extra or ill-typed one refuses the whole list. In an
 * answer each record field states its own provenance, which applies to its value in every row, and the list states none of its own.
 */
export interface WireRecordList<F> extends WireNamed { readonly type: "list"; readonly of: readonly F[]; readonly maxItems?: number }
/** An event's record field. */
export type WireRecordField = WireScalarDecl & WireNamed;
/** A field of an event: a scalar, a list of one scalar type, or a list of records, at most `maxItems` long. Never text. */
export type WireFieldDecl = (WireScalarDecl & WireNamed) | WireScalarList | WireRecordList<WireRecordField>;
/** An input's record field: an event's, or text. */
export type WireInputRecordField = (WireScalarDecl | WireTextDecl) & WireNamed;
/** A field of an operation's input: an event's kind of field, or text (top level or in a record). */
export type WireInputField = ((WireScalarDecl | WireTextDecl) & WireNamed) | WireScalarList | WireRecordList<WireInputRecordField>;
/** The most items a list holds, and the default. */
export const WIRE_LIST_MAX = 100;
/** The most fields a record, an event or an operation's input has. */
export const WIRE_RECORD_MAX_FIELDS = 32;
/** The most top-level fields an operation's answer has. */
export const WIRE_ANSWER_MAX_FIELDS = 64;
/** The most operations, and the most events, a `describe` lists. */
export const WIRE_DESCRIBE_MAX_OPERATIONS = 128;
export const WIRE_DESCRIBE_MAX_EVENTS = 128;
/** The most options a choice has. */
export const WIRE_CHOICE_MAX = 100;
/** The most code points a text's `maxLength` may state. The body's cap bounds its bytes. */
export const WIRE_TEXT_MAX = 20_000;
/** The most problems a check lists; past it, one line says there are more. */
export const WIRE_PROBLEMS_MAX = 50;
/** How strongly an event's sender is verified, strongest first. The board's own sender strengths are these. */
export const WIRE_SENDER_STRENGTHS = ["verified", "platform", "carrier", "typed"] as const;
/** Who sent an event, and how strongly that is verified; `system` is an event no person caused (a scheduled load finished). */
export const WIRE_EVENT_SENDERS = [...WIRE_SENDER_STRENGTHS, "system"] as const;
export type WireEventSender = (typeof WIRE_EVENT_SENDERS)[number];
/** An event the board accepts from the site: its kind, its sender's strength, and its typed fields. */
export interface WireEventDecl { readonly kind: string; readonly sender: WireEventSender; readonly fields: readonly WireFieldDecl[] }

/** An id on the wire: letters, digits and . _ : - only, 1 to 80; it matches the whole string. A choice's options are ids too. */
export const WIRE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/;
/** An id field's prefix: the start every value of it has, 1 to 40 characters of an id; it matches the whole string. */
export const WIRE_ID_PREFIX = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$/;
/** Every field's name, top level and in a record: a lowercase letter, then letters and digits, 1 to 64 (so never `__proto__`); the whole string. */
export const WIRE_FIELD_NAME = /^[a-z][a-zA-Z0-9]{0,63}$/;
/** A day, `YYYY-MM-DD`, in the years 0001 to 9999; the whole string. */
const WIRE_DATE = /^\d{4}-\d{2}-\d{2}$/;
/** A moment in UTC: `YYYY-MM-DDTHH:MM:SSZ` or, with milliseconds, `YYYY-MM-DDTHH:MM:SS.mmmZ` with exactly three digits; the whole string. */
const WIRE_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
/**
 * An event's kind: lowercase dotted names, the contributor first, `<contributor>.<name>` and deeper (`shop.feed.loaded`), two to four parts,
 * each a lowercase letter then up to 39 of a-z, 0-9 and _; it matches the whole string. Defined here, once: a board holds every kind it
 * declares to this same pattern, so a kind a board declares is always one a site can send.
 */
export const WIRE_EVENT_KIND = /^[a-z][a-z0-9_]{0,39}(\.[a-z][a-z0-9_]{0,39}){1,3}$/;
/** An operation's name: a lowercase letter, then letters, digits, _ and ., 1 to 64; it matches the whole string. `describe` is the contract's own. */
export const WIRE_OPERATION_NAME = /^[a-z][a-zA-Z0-9_.]{0,63}$/;

const realDate = (v: string) => !v.startsWith("0000") && !Number.isNaN(Date.parse(`${v}T00:00:00Z`)) && new Date(`${v}T00:00:00Z`).toISOString().startsWith(v);
const realDateTime = (v: string) => WIRE_DATE_TIME.test(v) && !Number.isNaN(Date.parse(v)) && realDate(v.slice(0, 10)) && new Date(v).toISOString().slice(0, 19) === v.slice(0, 19);
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const has = (o: object, key: string) => Object.hasOwn(o, key);
/**
 * Whether an object has exactly these keys: as many keys as names, and each name its own key. Never a comparison of the keys joined into one
 * string, which a key holding the joining character would pass (`{"input,marked":1,"op":"x"}` has two keys, not three).
 */
const hasExactly = (o: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => has(o, k));

/**
 * A body as JSON, refusing a duplicate key in any object (I-JSON, RFC 7493 §2.3): `JSON.parse` keeps the last of two and says nothing, so two
 * readers could see two different values. Null when the text is not JSON, repeats a key, or nests objects and lists more than
 * WIRE_BODY_MAX_DEPTH deep (the body's own object is the first level). Numbers are IEEE 754 doubles, as JSON.parse reads
 * them: an integer past 2^53 is the nearest double, and one too large for a double is infinite, which fits no number field.
 */
export function parseWireJson(text: string): { value: unknown } | null {
  // Only a string is scanned for repeated keys, so only a string is parsed: anything else (null, bytes) is refused here, never read around the scan.
  if (typeof text !== "string") return null;
  // Nesting is counted before anything is parsed, in a loop: a body of a hundred thousand brackets is refused here, never handed to a parser
  // that might recurse on it.
  for (let i = 0, depth = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 34) { for (i++; i < text.length && text.charCodeAt(i) !== 34; i++) if (text.charCodeAt(i) === 92) i++; }
    else if (c === 123 || c === 91) { if (++depth > WIRE_BODY_MAX_DEPTH) return null; }
    else if (c === 125 || c === 93) depth--;
  }
  let value: unknown;
  try { value = JSON.parse(text); } catch { return null; }
  // The text is valid JSON now, so a scan of its strings and brackets is enough to find each object's keys.
  const stack: { keys: Set<string> | null; wantKey: boolean }[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top?.keys && top.wantKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) return null;
        top.keys.add(key);
        top.wantKey = false;
      }
      i = j;
    } else if (c === "{") stack.push({ keys: new Set(), wantKey: true });
    else if (c === "[") stack.push({ keys: null, wantKey: false });
    else if (c === "}" || c === "]") stack.pop();
    else if (c === ",") { const top = stack[stack.length - 1]; if (top?.keys) top.wantKey = true; }
  }
  return { value };
}

const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
/**
 * A body's text from its raw bytes: decoded as UTF-8, refusing bytes that are not valid UTF-8 and a byte-order mark at the start. Null when
 * refused, or when the body is neither bytes nor a string (a string is taken as already decoded, and a leading U+FEFF refused the same).
 */
export function decodeWireBody(body: unknown): string | null {
  let text: string;
  if (typeof body === "string") text = body;
  else if (body instanceof Uint8Array) { try { text = utf8.decode(body); } catch { return null; } }
  else return null;
  return text.charCodeAt(0) === 0xfeff ? null : text;
}
const NOT_JSON = "not a JSON value";
/** What a check answers when the value it was given cannot even be read (a getter that throws): never a throw of its own. */
function guarded<T>(f: () => T, otherwise: T): T { try { return f(); } catch { return otherwise; } }

function scalarFits(f: WireScalarDecl, v: unknown): boolean {
  switch (f.type) {
    case "number": return typeof v === "number" && Number.isFinite(v) && (f.min === undefined || v >= f.min) && (f.max === undefined || v <= f.max);
    case "choice": return typeof v === "string" && Array.isArray(f.of) && f.of.includes(v);
    case "id": return typeof v === "string" && WIRE_ID.test(v) && (f.prefix === undefined || v.startsWith(f.prefix));
    case "date": return typeof v === "string" && WIRE_DATE.test(v) && realDate(v);
    case "dateTime": return typeof v === "string" && realDateTime(v);
    case "yesNo": return typeof v === "boolean";
    default: return false;
  }
}
const textCap = (m: unknown): number => (Number.isInteger(m) && (m as number) >= 1 && (m as number) <= WIRE_TEXT_MAX ? (m as number) : -1);
/** A text's value: a string of 1 to maxLength code points, each a real one (a surrogate only in its pair), none U+0000. The empty string is not a text. */
function textFits(maxLength: unknown, v: unknown): boolean {
  const max = textCap(maxLength);
  if (typeof v !== "string" || max < 0 || v.length > 2 * max) return false;
  let points = 0;
  for (let i = 0; i < v.length; i++, points++) {
    const c = v.charCodeAt(i);
    if (c === 0 || (c >= 0xdc00 && c <= 0xdfff)) return false;
    if (c >= 0xd800 && c <= 0xdbff) {
      const low = v.charCodeAt(i + 1);
      if (!(low >= 0xdc00 && low <= 0xdfff)) return false;
      i++;
    }
  }
  return points >= 1 && points <= max;
}
/** One value of a scalar, or (only where text is allowed: an input or an answer) of text. */
const leafFits = (f: { readonly type: string; readonly maxLength?: unknown }, v: unknown, text: boolean): boolean =>
  f.type === "text" ? text && textFits(f.maxLength, v) : scalarFits(f as WireScalarDecl, v);
/** A list's cap: its maxItems, or the default; a maxItems out of 1 to WIRE_LIST_MAX lets nothing fit. */
const listCap = (m: unknown): number => (m === undefined ? WIRE_LIST_MAX : Number.isInteger(m) && (m as number) >= 1 && (m as number) <= WIRE_LIST_MAX ? (m as number) : -1);
type AnyField = { readonly name: string; readonly type: string; readonly of?: unknown; readonly maxItems?: unknown; readonly maxLength?: unknown; readonly optional?: unknown };
function fits(f: Omit<AnyField, "name">, v: unknown, text: boolean): boolean {
  if (f.type !== "list") return leafFits(f, v, text);
  const of = f.of;
  if (!Array.isArray(v) || v.length > listCap(f.maxItems) || of === null || typeof of !== "object") return false;
  return Array.isArray(of) ? v.every((x) => objectFits(of, x, text)) : v.every((x) => scalarFits(of as WireScalarDecl, x));
}
/**
 * An object holding exactly its declared fields (a row, an operation's input, an answer's data): every key is a declared field's name, every
 * field that is not optional is its own key, and every value present fits its field (`null` fits nothing, an optional field included). Keys
 * are checked by name, never counted.
 */
function objectFits(fields: readonly AnyField[], v: unknown, text: boolean): boolean {
  if (!isObject(v)) return false;
  return Object.keys(v).every((k) => fields.some((f) => f.name === k)) && fields.every((f) => (has(v, f.name) ? fits(f, v[f.name], text) : f.optional === true));
}
const deepFreeze = (v: unknown): void => {
  if (v === null || typeof v !== "object") return;
  Object.freeze(v);
  for (const x of Object.values(v)) deepFreeze(x);
};
/**
 * The most a single declaration (one operation, one event, one list of fields) can hold and still be inside every cap above, counted as the
 * copy counts: one for each object, each list, each key and each item. The largest is an operation of WIRE_RECORD_MAX_FIELDS input fields and
 * WIRE_ANSWER_MAX_FIELDS answer fields, each a list of WIRE_RECORD_MAX_FIELDS record fields, each a choice of WIRE_CHOICE_MAX options; this is
 * a little above it. So a declaration inside the caps is always inside this, and one past this is past a cap: reading stops there.
 */
export const WIRE_DECLARATION_MAX_VALUES = (WIRE_RECORD_MAX_FIELDS + WIRE_ANSWER_MAX_FIELDS) * (10 + WIRE_RECORD_MAX_FIELDS * (10 + WIRE_CHOICE_MAX)) + 16;
const TOO_LARGE = "it holds more than a declaration inside the caps can";
/**
 * A plain copy of a JSON value: strings, numbers, booleans, null, lists and plain objects (their own keys; a key whose value is undefined is
 * left out), each read once. Anything else (a function, a class instance, a hole in a list) is not JSON, and a value larger or deeper than
 * any declaration inside the caps is too large (a RangeError).
 */
function jsonCopy(v: unknown, budget: { left: number }, depth: number): unknown {
  if (v === null || typeof v === "string" || typeof v === "boolean" || typeof v === "number") return v;
  if (typeof v !== "object") throw new TypeError(NOT_JSON);
  if (depth > 8 || --budget.left < 0) throw new RangeError(TOO_LARGE);
  if (Array.isArray(v)) {
    const list: unknown[] = [];
    for (let i = 0; i < v.length; i++) { if (--budget.left < 0) throw new RangeError(TOO_LARGE); list.push(jsonCopy(v[i], budget, depth + 1)); }
    return list;
  }
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) throw new TypeError(NOT_JSON);
  const out = Object.create(null) as Record<string, unknown>;
  for (const k of Object.keys(v)) {
    if (--budget.left < 0) throw new RangeError(TOO_LARGE);
    const x = (v as Record<string, unknown>)[k];
    if (x !== undefined) out[k] = jsonCopy(x, budget, depth + 1);
  }
  return out;
}
/**
 * The one decision about a declaration: a plain copy of it, and that copy's problems. Every problem list this file gives
 * (`describeProblems`, `eventDeclProblems`, `inputProblems`, `fieldDeclProblems`) and every use of a declaration to take a value (`sound`)
 * comes through here, so the two can never disagree: a declaration is used exactly when this finds no problem with it.
 */
function decided(d: unknown, check: (copy: unknown) => string[], where = ""): { copy: unknown; problems: string[] } {
  let copy: unknown;
  try { copy = jsonCopy(d, { left: WIRE_DECLARATION_MAX_VALUES }, 0); }
  catch (e) { return { copy: null, problems: [`${where}${e instanceof RangeError ? TOO_LARGE : NOT_JSON}`] }; }
  return { copy, problems: check(copy) };
}
/**
 * Each declaration is checked once (per kind of check), as a copy: the copy is made, checked and, when it has no problem, frozen whole, and
 * that frozen copy is what takes values from then on. The caller's object is never changed, and a later change to it is never read: it cannot
 * ride the remembered answer. A declaration with any problem (or that is not a JSON value) is remembered as unusable: nothing fits it.
 */
const soundEventFields = new WeakMap<object, unknown>(), soundAnswerFields = new WeakMap<object, unknown>(), soundEvents = new WeakMap<object, unknown>();
const soundInputs = new WeakMap<object, unknown>(), soundAnswers = new WeakMap<object, unknown>(), soundOperations = new WeakMap<object, unknown>();
function sound<T>(memo: WeakMap<object, unknown>, d: unknown, problems: (copy: unknown) => string[]): T | null {
  if (d === null || typeof d !== "object") return null;
  if (memo.has(d)) return memo.get(d) as T | null;
  let kept: unknown = null;
  try {
    const { copy, problems: found } = decided(d, problems);
    if (found.length === 0) { deepFreeze(copy); kept = copy; }
  } catch { kept = null; }
  memo.set(d, kept);
  return kept as T | null;
}
/**
 * Whether a value fits an event's field: a scalar; a list of at most maxItems items, each fitting the item's declaration; or a list of at most
 * maxItems rows, each fitting the record. A field whose declaration has any problem fits nothing, and text never fits.
 */
export const fieldFits = (f: WireFieldDecl, v: unknown): boolean => guarded(() => {
  const d = sound<AnyField>(soundEventFields, f, (c) => placedFieldProblems("field", c, "event", new Set()));
  return d !== null && fits(d, v, false);
}, false);
/** Whether a value fits an operation's answer field: as an event's, and a `text` field (or a record's text field) holds a string within its maxLength. */
export const answerFieldFits = (f: WireAnswerField, v: unknown): boolean => guarded(() => {
  const d = sound<AnyField>(soundAnswerFields, f, (c) => answerFieldProblems("field", c, new Set()));
  return d !== null && fits(d, v, true);
}, false);
/**
 * Whether an operation's `input` object fits the operation's declared input fields: every key declared, every field that is not optional
 * present, each value fitting. Input fields whose declaration has any problem take nothing. `checkOperationBody` checks the whole body.
 */
export const inputFits = (fields: readonly WireInputField[], v: unknown): boolean => guarded(() => {
  const d = sound<readonly AnyField[]>(soundInputs, fields, (c) => inputFieldsProblems("input", c));
  return d !== null && objectFits(d, v, true);
}, false);
/** Whether an answer's `data` object fits the operation's declared answer fields, the same way. `checkAnswerBody` checks the whole body. */
export const answerFits = (fields: readonly WireAnswerField[], v: unknown): boolean => guarded(() => {
  const d = sound<readonly AnyField[]>(soundAnswers, fields, (c) => answerFieldsProblems("answer", c));
  return d !== null && objectFits(d, v, true);
}, false);

// ── Declarations: one closed list of keys per type ──────────────────────────────────────────────────────────

/**
 * The keys a declaration of each type may carry besides `type` (and, where its place allows, `name`, `optional` and `provenance`): one closed
 * list per type. Any other key is refused, never ignored: a narrowing on a type it does not belong to (a list with a prefix, an id with min,
 * a scalar with maxItems), a JSON Schema keyword (`enum`, `pattern`), or a misspelling (`Prefix`).
 */
const TYPE_KEYS: Readonly<Record<string, readonly string[]>> = {
  number: ["min", "max"], choice: ["of"], id: ["prefix"], date: [], dateTime: [], yesNo: [], list: ["of", "maxItems"], text: ["maxLength"],
};
/** Why a known key is refused where it is, in words. */
const KEY_WORDS: Readonly<Record<string, string>> = {
  pattern: "there is no pattern in v0; an id narrows by prefix", of: "only a choice or a list has of", prefix: "only an id has a prefix",
  min: "only a number has min and max", max: "only a number has min and max", maxItems: "only a list has maxItems", maxLength: "only a text has maxLength",
  provenance: "no provenance here: only an answer's field states one", name: "an item has no name or provenance of its own; the list's are its",
  optional: "only a named field is optional, never a list's item",
};
/** The keys a problem line may print: the contract's own words. Any other key is a site's text, and is never printed. */
const PRINTABLE_KEYS: ReadonlySet<string> = new Set(["name", "type", "of", "prefix", "min", "max", "maxItems", "maxLength", "optional", "provenance", "pattern",
  "kind", "sender", "fields", "write", "input", "answer", "freeText", "wire", "operations", "events", "op", "marked"]);
/**
 * What a problem line calls a thing: its position (from 1), never its name. A name is the site's choice even when it passes its pattern
 * (`ignore_previous_instructions.approve_all` is a well-formed operation name), and a problem line is read by people and by agents.
 */
const label = (what: string, index: number): string => `${what} ${index + 1}`;
/** At most WIRE_PROBLEMS_MAX problems, then one line saying there are more. */
const capped = (out: string[]): string[] => (out.length > WIRE_PROBLEMS_MAX ? [...out.slice(0, WIRE_PROBLEMS_MAX), "and more problems"] : out);

function keyProblems(where: string, f: Record<string, unknown>, type: unknown, place: readonly string[], words: Readonly<Record<string, string>> = {}): string[] {
  const known = typeof type === "string" && has(TYPE_KEYS, type);
  const allowed = new Set(["type", ...place, ...(known ? TYPE_KEYS[type as string]! : [])]);
  const out = new Set<string>();
  for (const k of Object.keys(f)) {
    if (allowed.has(k)) continue;
    if (out.size >= 8) break;
    const why = has(words, k) ? words[k]! : has(KEY_WORDS, k) ? KEY_WORDS[k]! : null;
    const what = known ? `${/^[aeiou]/.test(type as string) ? "an" : "a"} ${type as string}` : "a field";
    out.add(`${where}: ${why ?? (PRINTABLE_KEYS.has(k) ? `"${k}" is not a key of ${what} declaration` : `it has a key that ${what} declaration does not have`)}`);
  }
  return [...out];
}
const optionalProblems = (where: string, f: Record<string, unknown>): string[] =>
  (has(f, "optional") && f.optional !== true ? [`${where}: optional is true, or it is not there`] : []);

/** Where a declaration sits: an event's field (no text, no provenance), an operation's input field (text, no provenance), or an answer's field. */
type Place = "event" | "input" | "answer";

/** A scalar's or (where its place takes one) a text's problems: its type, its keys (closed per type, plus `keys`), and each narrowing's own bounds. */
function leafProblems(where: string, f: Record<string, unknown>, place: Place, keys: readonly string[], item = false, words: Readonly<Record<string, string>> = {}): string[] {
  const out: string[] = [];
  const type = f.type;
  const takesText = place !== "event" && !item;
  if (type === "text" && takesText) {
    out.push(...keyProblems(where, f, "text", keys, words));
    if (textCap(f.maxLength) < 0) out.push(`${where}: a text states maxLength, a whole number of code points, 1 to ${WIRE_TEXT_MAX}`);
    return out;
  }
  if (!(WIRE_SCALAR_TYPES as readonly unknown[]).includes(type)) out.push(`${where}: a value is ${WIRE_SCALAR_TYPES.join(", ")}${takesText ? ", or text" : "; never free text"}`);
  out.push(...keyProblems(where, f, type, keys, words));
  if (type === "choice") {
    const of = f.of;
    if (!Array.isArray(of) || of.length < 1 || of.length > WIRE_CHOICE_MAX || !of.every((x) => typeof x === "string" && WIRE_ID.test(x)) || new Set(of).size !== of.length) {
      out.push(`${where}: a choice lists its options: 1 to ${WIRE_CHOICE_MAX}, each an id, each once`);
    }
  }
  if (type === "id" && has(f, "prefix") && (typeof f.prefix !== "string" || !WIRE_ID_PREFIX.test(f.prefix))) out.push(`${where}: a prefix is 1 to 40 characters of an id`);
  if (type === "number" && ((has(f, "min") && !Number.isFinite(f.min)) || (has(f, "max") && !Number.isFinite(f.max))
    || (typeof f.min === "number" && typeof f.max === "number" && f.min > f.max))) out.push(`${where}: min and max are finite numbers, min at most max`);
  return out;
}

const nameProblems = (where: string, name: unknown, names: Set<string>): string[] => {
  if (typeof name !== "string" || !WIRE_FIELD_NAME.test(name)) return [`${where}: a field's name is a lowercase letter, then letters and digits, 1 to 64`];
  if (names.has(name)) return [`${where}: declared twice`];
  names.add(name);
  return [];
};

/**
 * Problems with a record's fields: 1 to WIRE_RECORD_MAX_FIELDS, each an object with a name used once, a scalar narrowed as a field is (in an
 * input or an answer also text), never a list or a record; in an answer each with its provenance (text never the site's code's own),
 * elsewhere none.
 */
function recordProblems(where: string, fields: readonly unknown[], place: Place): string[] {
  const out: string[] = [];
  if (fields.length < 1 || fields.length > WIRE_RECORD_MAX_FIELDS) out.push(`${where}: a record has 1 to ${WIRE_RECORD_MAX_FIELDS} fields`);
  const names = new Set<string>();
  fields.slice(0, WIRE_RECORD_MAX_FIELDS).forEach((x, i) => {
    if (!isObject(x)) { out.push(`${where} record field ${i + 1}: a field is an object, never a list or a record`); return; }
    const at = `${where} record ${label("field", i)}`;
    out.push(...nameProblems(at, x.name, names), ...optionalProblems(at, x));
    if (x.type === "list") { out.push(`${at}: a record is one level deep: its field is never a list or a record`); return; }
    if (place === "answer") {
      if (!(WIRE_PROVENANCE as readonly unknown[]).includes(x.provenance)) out.push(`${at}: provenance is one of ${WIRE_PROVENANCE.join(", ")}`);
      if (x.type === "text" && x.provenance === "code") out.push(`${at}: text is never the site's code's own`);
    }
    out.push(...leafProblems(at, x, place, place === "answer" ? ["name", "optional", "provenance"] : ["name", "optional"]));
  });
  return out;
}

/** One field's type, narrowing and list shape, at its place; its name, `optional` and own provenance are the callers', who check them. */
function declProblems(where: string, f: unknown, place: Place): string[] {
  if (!isObject(f)) return [`${where}: a field is an object`];
  if (f.type !== "list") return leafProblems(where, f, place, ["name", "optional", "provenance"]);
  const out = keyProblems(where, f, "list", ["name", "optional", "provenance"]);
  const of = f.of;
  if (of === null || typeof of !== "object") return [...out, `${where}: a list's of is its item's declaration, or its record's fields`];
  if (Array.isArray(of)) out.push(...recordProblems(where, of, place));
  else if ((of as { type?: unknown }).type === "list") out.push(`${where}: a list is one level deep`);
  else out.push(...leafProblems(`${where} item`, of as Record<string, unknown>, place, [], true, { name: KEY_WORDS.name!, provenance: KEY_WORDS.name! }));
  if (has(f, "maxItems") && listCap(f.maxItems) < 0) out.push(`${where}: maxItems is a whole number, 1 to ${WIRE_LIST_MAX}`);
  return out;
}
/**
 * Problems with one whole field at its place (an event's by default, or an input's or an answer's): its name, `optional`, its provenance
 * (required in an answer, refused elsewhere), its type, narrowing and list shape. The same decision `fieldFits` and `answerFieldFits` use:
 * a lone field takes a value exactly when this lists nothing.
 */
export const fieldDeclProblems = (where: string, f: unknown, place: Place = "event"): string[] =>
  guarded(() => capped(decided(f, (c) => (place === "answer" ? answerFieldProblems(where, c, new Set()) : placedFieldProblems(where, c, place, new Set()))).problems), [NOT_JSON]);

/** Problems with one event or input field: its name, `optional`, no provenance anywhere in it, and its declaration. */
function placedFieldProblems(where: string, f: unknown, place: "event" | "input", names: Set<string>): string[] {
  if (!isObject(f)) return [`${where}: a field is an object`];
  const out = [...nameProblems(where, f.name, names), ...optionalProblems(where, f)];
  if (has(f, "provenance")) out.push(`${where}: ${KEY_WORDS.provenance}`);
  return [...out, ...declProblems(where, f, place)];
}

function inputFieldsProblems(where: string, input: unknown): string[] {
  if (!Array.isArray(input)) return [`${where}: input is a list of field declarations, as an event's fields; never a JSON Schema`];
  const out: string[] = [];
  if (input.length > WIRE_RECORD_MAX_FIELDS) out.push(`${where}: an input has at most ${WIRE_RECORD_MAX_FIELDS} fields`);
  const names = new Set<string>();
  input.slice(0, WIRE_RECORD_MAX_FIELDS).forEach((f, i) => out.push(...placedFieldProblems(`${where} ${label("field", i)}`, f, "input", names)));
  return out;
}
/**
 * Problems with an operation's input: a list of at most WIRE_RECORD_MAX_FIELDS field declarations, typed as an event's fields and also text
 * (no provenance), each name once. Never a JSON Schema: the input says exactly what the site takes, in the wire's own types.
 */
export const inputProblems = (where: string, input: unknown): string[] => guarded(() => capped(decided(input, (c) => inputFieldsProblems(where, c)).problems), [NOT_JSON]);

type EventChecked = { ok: true; kind: string; id: string; at: string; sender: WireEventSender; fields: Readonly<Record<string, unknown>> }
  | { ok: false; code: "unknown_event" | "bad_event" | "internal"; field?: string };
function eventCheck(body: unknown, decls: unknown): EventChecked {
  const text = decodeWireBody(body);
  const parsed = text === null ? null : parseWireJson(text);
  if (!parsed || !isObject(parsed.value)) return { ok: false, code: "bad_event" };
  const o = parsed.value;
  if (!hasExactly(o, ["event", "id", "at", "fields"]) || typeof o.event !== "string") return { ok: false, code: "bad_event" };
  // A list past the describe's cap is unsound as a whole: nothing in it is used.
  if (Array.isArray(decls) && decls.length > WIRE_DESCRIBE_MAX_EVENTS) return { ok: false, code: "internal" };
  const found = (Array.isArray(decls) ? (decls as unknown[]) : []).filter((d) => isObject(d) && d.kind === o.event);
  if (found.length === 0) return { ok: false, code: "unknown_event" };
  const decl = found.length === 1 ? sound<WireEventDecl>(soundEvents, found[0], (c) => eventProblems(c, 0)) : null;
  if (decl === null) return { ok: false, code: "internal" };
  if (typeof o.id !== "string" || !WIRE_ID.test(o.id) || typeof o.at !== "string" || !realDateTime(o.at)) return { ok: false, code: "bad_event" };
  if (!isObject(o.fields)) return { ok: false, code: "bad_event" };
  const fields = o.fields;
  if (!Object.keys(fields).every((name) => decl.fields.some((f) => f.name === name))) return { ok: false, code: "bad_event" };
  for (const f of decl.fields) if (has(fields, f.name) ? !fits(f, fields[f.name], false) : f.optional !== true) return { ok: false, code: "bad_event", field: f.name };
  return { ok: true, kind: decl.kind, id: o.id, at: o.at, sender: decl.sender, fields: Object.freeze({ ...fields }) };
}
/**
 * An event's body, after `verifyWire` passed (its raw bytes, or its text): decoded as UTF-8 (`decodeWireBody`), then
 * `{ "event": kind, "id": the site's one id for this event, "at": when, "fields": {...} }` and nothing else, with no key twice anywhere.
 * Checked in this order: the body is a JSON object, nested no deeper than WIRE_BODY_MAX_DEPTH, with exactly those four keys and a string
 * `event` (else `bad_event`); the board's list of declarations, which past WIRE_DESCRIBE_MAX_EVENTS answers `internal` for every kind, in it
 * or not; the kind is one the board declared (else `unknown_event`, whatever else is wrong with the body); the board's own declaration has
 * no problem and is not declared twice (else `internal`, which the site tries again later); `id` and `at` are well formed; no field is
 * there that the board did not declare; every declared field that is not optional is present, and every one present fits (else `bad_event`).
 * `field` is given only for that last step, and names the first field at fault in the order the board declared them, whatever order the
 * body gives them in; a fault anywhere else, an undeclared key among them, names no field.
 * An undeclared key is the sender's text, and is never given back. The board records the sender strength from
 * the declaration, never from the body, and answers `EVENT_RECORDED`.
 */
export function checkEvent(body: Uint8Array | string, decls: readonly WireEventDecl[]): EventChecked {
  return guarded<EventChecked>(() => eventCheck(body, decls), { ok: false, code: "internal" });
}

/** An object's keys outside a closed list, as problems (a key's own text only when it is one of the contract's words). */
const extraKeys = (where: string, o: Record<string, unknown>, keys: readonly string[]): string[] =>
  [...new Set(Object.keys(o).filter((k) => !keys.includes(k)).slice(0, 8)
    .map((k) => `${where}: ${PRINTABLE_KEYS.has(k) ? `"${k}" is not one of its keys` : "it has a key that is not one of its keys"} (${keys.join(", ")})`))];

function eventProblems(d: unknown, index: number): string[] {
  if (!isObject(d) || typeof d.kind !== "string" || !Array.isArray(d.fields)) return ["an event is { kind, sender, fields }"];
  const at = label("event", index);
  const out: string[] = [];
  if (!WIRE_EVENT_KIND.test(d.kind)) out.push(`${at}: a kind is lowercase dotted names, <contributor>.<name> or deeper`);
  if (!(WIRE_EVENT_SENDERS as readonly unknown[]).includes(d.sender)) out.push(`${at}: sender is one of ${WIRE_EVENT_SENDERS.join(", ")}`);
  out.push(...extraKeys(at, d, ["kind", "sender", "fields"]));
  if (d.fields.length > WIRE_RECORD_MAX_FIELDS) out.push(`${at}: an event has at most ${WIRE_RECORD_MAX_FIELDS} fields`);
  const names = new Set<string>();
  d.fields.slice(0, WIRE_RECORD_MAX_FIELDS).forEach((f, i) => out.push(...placedFieldProblems(`${at} ${label("field", i)}`, f, "event", names)));
  return out;
}
/** Problems with an event declaration (the board's, when it pairs). */
export const eventDeclProblems = (d: unknown): string[] => guarded(() => capped(decided(d, (c) => eventProblems(c, 0)).problems), [NOT_JSON]);

// ── describe ──────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Where an answer field came from: the site's own code, a person inside the business, a person outside it, or a model reading outside text.
 * A field declares the least trusted provenance any of its values can have; the owner approving exact words does not change it.
 */
export const WIRE_PROVENANCE = ["code", "inside", "outside", "modelFromOutside"] as const;
export type WireProvenance = (typeof WIRE_PROVENANCE)[number];
/** An answer's record field: a scalar or text, with its provenance (which applies to its value in every row). */
export type WireAnswerRecordField = (WireScalarDecl | WireTextDecl) & WireNamed & { readonly provenance: WireProvenance };
/**
 * An answer field: typed and narrowed as an event's (or `text`, which is always free text), with its provenance; or a list of records, whose
 * fields each state their own provenance and which states none.
 */
export type WireAnswerField =
  | ((((WireScalarDecl | WireTextDecl) & WireNamed) | WireScalarList) & { readonly provenance: WireProvenance })
  | (WireRecordList<WireAnswerRecordField> & { readonly provenance?: never });
export interface WireOperationDecl {
  readonly name: string;
  readonly write: boolean;
  /** What the operation takes, as typed fields: the input object holds exactly these (an optional one may be absent). Never a JSON Schema. */
  readonly input: readonly WireInputField[];
  readonly answer: readonly WireAnswerField[];
  /** True when any answer field is text, outside or a model's reading of outside text: the answer is outside text and marks the run that reads it. */
  readonly freeText: boolean;
}
/** The answer to the `describe` operation: what the site implements, compared with the blueprint when pairing and at each health check. */
export interface WireDescribe { readonly wire: typeof WIRE_VERSION; readonly operations: readonly WireOperationDecl[]; readonly events: readonly WireEventDecl[] }

/** Problems with one answer field: its name, its provenance (a list of records states none; each record field one), and its declaration. */
function answerFieldProblems(where: string, f: unknown, names: Set<string>): string[] {
  if (!isObject(f)) return [`${where}: an answer field is an object`];
  const out = [...nameProblems(where, f.name, names), ...optionalProblems(where, f)];
  if (f.type === "list" && Array.isArray(f.of)) {
    if (has(f, "provenance")) out.push(`${where}: a list of records has no provenance of its own; each of its fields states one`);
  } else if (!(WIRE_PROVENANCE as readonly unknown[]).includes(f.provenance)) out.push(`${where}: provenance is one of ${WIRE_PROVENANCE.join(", ")}`);
  if (f.type === "text" && f.provenance === "code") out.push(`${where}: text is never the site's code's own`);
  return [...out, ...declProblems(where, f, "answer")];
}
function answerFieldsProblems(where: string, answer: unknown): string[] {
  if (!Array.isArray(answer)) return [`${where}: answer is a list of field declarations`];
  const out: string[] = [];
  if (answer.length > WIRE_ANSWER_MAX_FIELDS) out.push(`${where}: an answer has at most ${WIRE_ANSWER_MAX_FIELDS} fields`);
  const names = new Set<string>();
  answer.slice(0, WIRE_ANSWER_MAX_FIELDS).forEach((f, i) => {
    if (!isObject(f)) { out.push(`${where}: an answer field is an object`); return; }
    out.push(...answerFieldProblems(`${where} ${label("field", i)}`, f, names));
  });
  return out;
}

function operationProblems(op: unknown, index: number, names: Set<string>): string[] {
  if (!isObject(op)) return ["an operation is an object"];
  const at = label("operation", index);
  const out: string[] = [];
  if (typeof op.name !== "string" || !WIRE_OPERATION_NAME.test(op.name) || op.name === "describe") out.push(`${at}: a name is lowercase-first letters, digits, _ and ., and describe is the contract's own`);
  else if (names.has(op.name)) out.push(`${at}: listed twice`);
  else names.add(op.name);
  out.push(...extraKeys(at, op, ["name", "write", "input", "answer", "freeText"]));
  if (typeof op.write !== "boolean" || typeof op.freeText !== "boolean" || !has(op, "input") || !Array.isArray(op.answer)) {
    return [...out, `${at}: write, freeText, input and answer are required`];
  }
  out.push(...inputFieldsProblems(`${at} input`, op.input), ...answerFieldsProblems(at, op.answer));
  // A list of records is outside when any of its fields is.
  const isOutside = (f: unknown): boolean => isObject(f) && (f.provenance === "outside" || f.provenance === "modelFromOutside" || f.type === "text");
  const outside = op.answer.slice(0, WIRE_ANSWER_MAX_FIELDS).some((f) => isOutside(f) || (isObject(f) && f.type === "list" && Array.isArray(f.of) && f.of.slice(0, WIRE_RECORD_MAX_FIELDS).some(isOutside)));
  if (outside && !op.freeText) out.push(`${at}: its answer holds outside or free text, so freeText is true`);
  return out;
}

/**
 * Problems with a site's `describe` answer. Empty: it is well formed (whether it fits the blueprint is the board's next question). It lists at
 * most WIRE_DESCRIBE_MAX_OPERATIONS operations and WIRE_DESCRIBE_MAX_EVENTS events, each name and each kind once; `wire`, `operations` and
 * `events` are required, as are an operation's five keys and an event's three. It never throws, whatever it is given (a value that cannot be
 * read is one problem, "not a JSON value"), lists at most WIRE_PROBLEMS_MAX problems, and prints none of the site's text.
 */
export const describeProblems = (d: unknown): string[] => guarded(() => capped(describeAll(d)), [NOT_JSON]);
function describeAll(d: unknown): string[] {
  if (!isObject(d)) return ["describe is an object"];
  const out: string[] = [];
  if (d.wire !== WIRE_VERSION) out.push(`wire is ${WIRE_VERSION}`);
  const operations = d.operations, events = d.events;
  if (!Array.isArray(operations) || !Array.isArray(events)) return [...out, "operations and events are lists"];
  out.push(...extraKeys("describe", d, ["wire", "operations", "events"]));
  if (operations.length > WIRE_DESCRIBE_MAX_OPERATIONS) out.push(`describe lists at most ${WIRE_DESCRIBE_MAX_OPERATIONS} operations`);
  if (events.length > WIRE_DESCRIBE_MAX_EVENTS) out.push(`describe lists at most ${WIRE_DESCRIBE_MAX_EVENTS} events`);
  const names = new Set<string>();
  for (let i = 0; i < operations.length && i < WIRE_DESCRIBE_MAX_OPERATIONS && out.length <= WIRE_PROBLEMS_MAX; i++) {
    // Each operation and each event is decided as it is when it is used: on its own copy, by the same function.
    out.push(...decided(operations[i], (c) => operationProblems(c, i, names), `${label("operation", i)}: `).problems);
  }
  const kinds = new Set<string>();
  for (let i = 0; i < events.length && i < WIRE_DESCRIBE_MAX_EVENTS && out.length <= WIRE_PROBLEMS_MAX; i++) {
    const { copy: e, problems: found } = decided(events[i], (c) => eventProblems(c, i), `${label("event", i)}: `);
    out.push(...found);
    if (isObject(e) && typeof e.kind === "string") {
      if (kinds.has(e.kind)) out.push(`${label("event", i)}: an event kind is declared once`);
      kinds.add(e.kind);
    }
  }
  return out;
}

// ── An operation's body ───────────────────────────────────────────────────────────────────────────────────────

/** `describe`, the contract's own operation: a read that takes nothing. */
const DESCRIBE_INPUT: readonly AnyField[] = Object.freeze([]);
/**
 * The site's declaration of the operation `name`, as a checked copy: "none" when it declares none, null when it lists it twice, it has a
 * problem, or the list itself is longer than a describe may be.
 */
function operationOf(name: unknown, operations: unknown): WireOperationDecl | "none" | null {
  // A list past the describe's cap is unsound as a whole: nothing in it is used.
  if (Array.isArray(operations) && operations.length > WIRE_DESCRIBE_MAX_OPERATIONS) return null;
  const found = (Array.isArray(operations) ? (operations as unknown[]) : []).filter((o) => isObject(o) && o.name === name);
  if (found.length === 0) return "none";
  return found.length === 1 ? sound<WireOperationDecl>(soundOperations, found[0], (c) => operationProblems(c, 0, new Set())) : null;
}

type BodyChecked = { ok: true; op: string; input: Readonly<Record<string, unknown>>; marked: boolean } | { ok: false; code: "unknown_operation" | "bad_input" | "internal" };
function operationBodyCheck(body: unknown, name: unknown, operations: unknown): BodyChecked {
  // The body's own shape first, as an event's is: its bytes, its JSON, its three keys and the path's name in `op`.
  const text = decodeWireBody(body);
  const parsed = text === null ? null : parseWireJson(text);
  if (!parsed || !isObject(parsed.value)) return { ok: false, code: "bad_input" };
  const o = parsed.value;
  if (!hasExactly(o, ["op", "input", "marked"]) || typeof name !== "string" || o.op !== name) return { ok: false, code: "bad_input" };
  // Then the list (past its cap, nothing in or out of it is answered), the operation, and its declaration. `describe` is in no list.
  let fields: readonly AnyField[] = DESCRIBE_INPUT;
  if (name !== "describe") {
    const decl = operationOf(name, operations);
    if (decl === "none") return { ok: false, code: "unknown_operation" };
    if (decl === null) return { ok: false, code: "internal" };
    fields = decl.input;
  }
  if (typeof o.marked !== "boolean" || !isObject(o.input) || !objectFits(fields, o.input, true)) return { ok: false, code: "bad_input" };
  return { ok: true, op: name, input: Object.freeze({ ...o.input }), marked: o.marked };
}
/**
 * An operation's body at the site, after `verifyWire` passed (its raw bytes, or its text): decoded as UTF-8 (`decodeWireBody`), then
 * `{ "op": name, "input": {...}, "marked": true | false }` and nothing else, with no key twice anywhere. Checked in the order an event is:
 * first the body's own shape (UTF-8, JSON nested no deeper than WIRE_BODY_MAX_DEPTH, no key twice, exactly the three keys, and `op` equal to
 * `name`, the operation the path names), else `bad_input`; then the site's list, which past WIRE_DESCRIBE_MAX_OPERATIONS answers `internal`
 * for every operation, in it or not; then the operation, which the site declares (else `unknown_operation`); then its declaration, with no
 * problem and listed once (else `internal`); and last `marked`, a boolean, and `input`, holding exactly the declared input fields, each
 * present value fitting (else `bad_input`, and nothing is done). `describe` is in no list: its body is checked whatever the list holds.
 *
 * `marked` is true when the run that asked had received outside text. False says only that it had not: it is never trust in the words of a
 * text field, which are data either way. A site may refuse a marked request for an operation, in its own code.
 */
export function checkOperationBody(body: Uint8Array | string, name: string, operations: readonly WireOperationDecl[]): BodyChecked {
  return guarded<BodyChecked>(() => operationBodyCheck(body, name, operations), { ok: false, code: "internal" });
}

// ── An operation's answer ─────────────────────────────────────────────────────────────────────────────────────

type AnswerChecked = { ok: true; data: Readonly<Record<string, unknown>> } | { ok: false; code: WireError };
function answerBodyCheck(body: unknown, status: unknown, name: unknown, operations: unknown): AnswerChecked {
  const internal: AnswerChecked = { ok: false, code: "internal" };
  const size = typeof body === "string" ? Buffer.byteLength(body, "utf8") : body instanceof Uint8Array ? body.length : Number.POSITIVE_INFINITY;
  if (size > WIRE_ANSWER_MAX_BYTES) return internal;
  const text = decodeWireBody(body);
  const parsed = text === null ? null : parseWireJson(text);
  if (!parsed || !isObject(parsed.value) || typeof status !== "number" || !Number.isInteger(status)) return internal;
  const o = parsed.value;
  if (status >= 400 && status <= 599) {
    const e = o.error;
    if (!hasExactly(o, ["error"]) || !isObject(e) || !hasExactly(e, ["code"]) || typeof e.code !== "string") return internal;
    const code = (WIRE_ERRORS as readonly string[]).indexOf(e.code);
    return code < 0 ? internal : { ok: false, code: WIRE_ERRORS[code]! };
  }
  if (status < 200 || status > 299 || !hasExactly(o, ["data"]) || !isObject(o.data)) return internal;
  if (name === "describe") return describeAll(o.data).length === 0 ? { ok: true, data: Object.freeze({ ...o.data }) } : internal;
  const decl = operationOf(name, operations);
  if (decl === "none" || decl === null || !objectFits(decl.answer, o.data, true)) return internal;
  return { ok: true, data: Object.freeze({ ...o.data }) };
}
/**
 * An operation's answer at the board: the body (its raw bytes, or its text), the HTTP status, the operation asked, and the site's
 * declarations as the board holds them (its `describe`). Anything that is not exactly an answer is `internal`: a body past
 * WIRE_ANSWER_MAX_BYTES, bytes that are not UTF-8, text that is not JSON or repeats a key, a status that is neither 2xx nor 4xx or 5xx.
 *  - A 2xx answer is `{ "data": {...} }` and nothing else, and `data` holds exactly the operation's declared answer fields, each present value
 *    fitting (for `describe`, a well-formed describe). An operation the board does not hold a sound declaration of has no answer it can read.
 *  - A 4xx or 5xx answer is `{ "error": { "code": c } }` and nothing else, `c` one of WIRE_ERRORS: that code. Any other code, or any other
 *    shape, is `internal`: a site's own words are never read as a code.
 */
export function checkAnswerBody(body: Uint8Array | string, status: number, name: string, operations: readonly WireOperationDecl[]): AnswerChecked {
  return guarded<AnswerChecked>(() => answerBodyCheck(body, status, name, operations), { ok: false, code: "internal" });
}

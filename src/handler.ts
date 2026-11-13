/**
 * The site's request handler for operations, framework-neutral: the raw body bytes and headers in, a status, headers and body out.
 * A site mounts it at `POST /wire/v0/ops/<name>` in whatever framework it uses, reading the body with `readCapped` before any parsing
 * (the body's hash is what was signed).
 *
 * Order: the site's limit (`allow`), before the body is hashed or a signature checked (contract section 3: rate-limit first). Then the
 * request checks (`verifyWire`, the contract's order, the one-use number last) against the pairing's keys, loaded ahead of time, for
 * every method. A site that is not paired goes the same way, as a site that holds no key: the limit, then the same checks in the same
 * order, the one verification (against the decoy) among them, so a request that reaches the key is `bad_signature` with status 401
 * (section 3, step 5: an unpaired site's key is simply not held) and nothing in an answer tells a paired site from an unpaired one.
 * A request that is not a `POST` is answered as the contract answers it (section 3, step 2: `bad_request`, after the
 * version; section 4: in the error body every refusal has), never by a status of the handler's own. The headers go to that check as
 * they were sent: it folds their names and the method (A to Z only) and reads a wire header that is there twice as absent, so
 * nothing here joins, folds or refuses a header first. Then the body and the operation (`checkOperationBody`, the contract's order:
 * the body's own shape first, UTF-8 JSON nested no deeper than 32 with exactly `op`, `input` and `marked` and `op` the path's name,
 * else `bad_input` whatever the path names; then an operation the site does not offer is `unknown_operation`; then `marked` and
 * `input`, exactly the declared typed fields, else `bad_input`). Then the work (a read within the deadline, a write once per pairing
 * and retry key, in the transaction that keeps its answer), and the answer, which must be exactly the declared fields and at most
 * 1 MiB.
 *
 * Every answer is `Cache-Control: no-store` and `X-Robots-Tag: noindex`. An error is exactly `{"error":{"code":"..."}}`: no sentence,
 * nothing from the request echoed. Why a request was refused or failed goes to the site's own `log` only, never into the response.
 */
import type { WireRegistry } from "./registry.js";
import { WireRefusal } from "./registry.js";
import type { AnswerStore, NonceStore, WireAnswer } from "./stores.js";
import {
  bodyHash, loadWireKeys, verifyWire, WIRE_ANSWER_MAX_BYTES, WIRE_ANSWER_SECONDS, WIRE_BODY_MAX_BYTES, WIRE_NOT_VERIFIED_STATUS,
  type WireError, type WireKeyring,
} from "./wire.js";

/** HTTP status for each code. `bad_signature` is always 401, whatever its cause. */
export const WIRE_STATUS: Readonly<Record<WireError, number>> = {
  bad_version: 400, bad_request: 400, bad_time: 400, stale: 401, future: 401, body_too_large: 413, body_mismatch: 400,
  bad_signature: WIRE_NOT_VERIFIED_STATUS, missing_retry_key: 400, bad_retry_key: 400, bad_nonce: 400, replayed: 409,
  unknown_operation: 404, bad_input: 400, not_found: 404, conflict: 409, rate_limited: 429, unavailable: 503, internal: 500,
  unknown_event: 400, bad_event: 400,
};

const COMMON = { "cache-control": "no-store", "x-robots-tag": "noindex" } as const;

/**
 * The site's pairing as it holds it: its id and the board's operation public keys for it, **loaded** (`loadWireKeys`). Load them at
 * start and whenever a key is entered or changed, never per request: loading checks each key (about a millisecond of curve
 * arithmetic), and answering a request only looks one up. Read the keyring's `problems` then, for the site's own log: a key record
 * with any problem is never used. Null: not paired, and every request is answered as at a paired site that holds no key.
 */
export interface SitePairing {
  readonly pairing: string;
  readonly keys: WireKeyring;
}

export interface HandlerDeps<Tx> {
  /**
   * The site's pairing, or null while it is not paired. A pairing that cannot be read (this throws) is answered as no pairing is, and
   * why goes to `log` only.
   */
  readonly pairing: () => SitePairing | null;
  readonly registry: WireRegistry<Tx>;
  readonly nonces: NonceStore;
  readonly answers: AnswerStore<Tx>;
  readonly now: () => Date;
  /**
   * The site's limit, asked first: before the body is hashed or any signature is checked, since both cost work for anyone who sends a
   * request. True if this pairing (and this source, when the route gave one) may make another request now; it counts the request.
   * False is answered `rate_limited`. It is asked about every request, verified or not, so limit by source as well as by pairing or a
   * stranger can use up the pairing's allowance. A site that is not paired has no pairing id: it is asked with the empty string, which
   * is no pairing's id. Unset: no limit here, and the route must limit before it calls the handler.
   */
  readonly allow?: (pairing: string, source: string | undefined) => boolean | Promise<boolean>;
  /**
   * The site's own log. It gets one line for each thing the response never says: why a key or signature did not verify (`no_key`,
   * `key_retired`, `unusable_key` or `bad_signature`, with the key id only when it has a key id's shape), an answer that did not fit
   * or was over 1 MiB, a failure. Never send these lines anywhere a caller can read them. A log that throws, or whose promise
   * rejects, changes nothing about the answer. Unset: nowhere.
   */
  readonly log?: (line: string) => void | Promise<void>;
  /** How long a read may take before `unavailable`. Default WIRE_ANSWER_SECONDS. */
  readonly deadlineMs?: number;
}

export interface WireHttpRequest {
  readonly method: string;
  /** The path exactly as requested, query string included. */
  readonly path: string;
  /**
   * The headers as they were sent, as a plain object: each name (in any case) to its value, or to the list of its values when it was
   * sent more than once. A Node server's `req.headers` is one already; `headersOf` makes one from a Fetch `Headers`, a `Map` or raw
   * pairs. Never join, fold or drop a header before this: the check reads a wire header that is there twice as absent.
   */
  readonly headers: Readonly<Record<string, string | readonly string[] | undefined>>;
  /** The raw body bytes (from `readCapped`). */
  readonly body: Uint8Array;
  /** Who sent it, as the site's own server knows it (an address). Given to `allow` and to nothing else. */
  readonly source?: string;
}

export interface WireHttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  /** Always JSON: `{"data": ...}` or `{"error":{"code":"..."}}`. */
  readonly body: string;
}

/**
 * Headers as the plain object `verifyWire` takes, from anything iterable as [name, value or values]: a Fetch `Headers`, a `Map`, a
 * list of raw pairs. Each name is kept exactly as it was given, and a name given more than once keeps all its values, as a list.
 * Nothing is joined, folded or dropped here: the check folds names itself (A to Z only, as HTTP does) and reads a wire header that is
 * there twice (a list, two spellings, or one value holding a comma, which is how a Fetch `Headers` hands a repeat over) as absent.
 */
export function headersOf(entries: Iterable<readonly [string, string | readonly string[]]>): Record<string, string | string[]> {
  const seen = new Map<string, string[]>();
  for (const [name, value] of entries) {
    let values = seen.get(name);
    if (!values) seen.set(name, (values = []));
    if (typeof value === "string") values.push(value);
    else values.push(...value);
  }
  // Own properties whatever the name (`__proto__` included): made from entries, never assigned.
  return Object.fromEntries([...seen].map(([name, values]) => [name, values.length === 1 ? values[0]! : values]));
}

/** A body that did not arrive within its time: the site answers it as it answers any broken request. */
export class BodyReadTimeout extends Error {
  constructor() {
    super("the request body did not arrive in time");
    this.name = "BodyReadTimeout";
  }
}

type Chunk = Uint8Array | string;
type BodySource = ReadableStream<Uint8Array> | AsyncIterable<Chunk> | null | undefined;

/**
 * Reads at most `limit + 1` bytes of a request body, so an oversized body is known without holding all of it. Takes a web stream
 * (Fetch `Request.body`) or a Node stream (anything async-iterable, such as `IncomingMessage`). Throws `BodyReadTimeout` when the
 * whole read takes longer than `timeoutMs` (default 10 seconds); the stream is cancelled or destroyed then, as it is past the cap.
 */
export async function readCapped(source: BodySource, options: { limit?: number; timeoutMs?: number } = {}): Promise<Uint8Array> {
  const limit = options.limit ?? WIRE_BODY_MAX_BYTES;
  const timeoutMs = options.timeoutMs ?? WIRE_ANSWER_SECONDS * 1000;
  if (!source) return new Uint8Array(0);
  const chunks: Buffer[] = [];
  let size = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stop: () => Promise<void> = async () => {};
  const timedOut = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new BodyReadTimeout()), timeoutMs); });
  const read = async () => {
    if (typeof (source as ReadableStream).getReader === "function") {
      const reader = (source as ReadableStream<Uint8Array>).getReader();
      stop = async () => { void reader.cancel().catch(() => {}); };
      while (size <= limit) {
        const { done, value } = await reader.read();
        if (done) return;
        chunks.push(Buffer.from(value));
        size += value.length;
      }
      await stop();
    } else {
      const iterable = source as AsyncIterable<Chunk> & { destroy?: () => void };
      const it = iterable[Symbol.asyncIterator]();
      stop = async () => { iterable.destroy?.(); void it.return?.()?.catch(() => {}); };
      while (size <= limit) {
        const { done, value } = await it.next();
        if (done) return;
        const b = typeof value === "string" ? Buffer.from(value, "utf8") : Buffer.from(value);
        chunks.push(b);
        size += b.length;
      }
      await stop();
    }
  };
  try {
    await Promise.race([read(), timedOut]);
  } catch (err) {
    await stop();
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const all = Buffer.concat(chunks);
  return all.length > limit + 1 ? all.subarray(0, limit + 1) : all;
}

export const errorAnswer = (code: WireError): WireAnswer => ({ status: WIRE_STATUS[code], body: { error: { code } } });

type Log = (line: string) => void;
/** The site's log, made safe: a log that throws, or whose promise rejects, is not the request's failure. */
function safeLog(log: HandlerDeps<never>["log"]): Log {
  return (line) => {
    try {
      const told: unknown = log?.(line);
      if (told !== null && typeof told === "object" && typeof (told as { then?: unknown }).then === "function") {
        (told as PromiseLike<unknown>).then(undefined, () => undefined);
      }
    } catch { /* a log's failure is not the request's */ }
  };
}

function respond(answer: WireAnswer, log: Log): WireHttpResponse {
  const text = JSON.stringify(answer.body);
  if ("data" in answer.body && Buffer.byteLength(text, "utf8") > WIRE_ANSWER_MAX_BYTES) {
    log("[wire] an answer was over 1 MiB");
    return respond(errorAnswer("internal"), log);
  }
  return { status: answer.status, headers: { ...COMMON, "content-type": "application/json" }, body: text };
}

/** The codes an operation may refuse with (`WireRefusal`). Any other refusal becomes `internal`. */
const REFUSALS: ReadonlySet<string> = new Set(["not_found", "conflict", "bad_input", "unavailable"]);

async function answer<Tx>(req: WireHttpRequest, name: string, site: SitePairing, deps: HandlerDeps<Tx>, log: Log): Promise<WireAnswer> {
  // Rate-limit first: verifying hashes up to 256 KiB and runs a signature check for anyone who sends a request.
  if (deps.allow && !(await deps.allow(site.pairing, req.source))) return errorAnswer("rate_limited");

  const op = name === "describe" ? undefined : deps.registry.operation(name);
  const checked = await verifyWire(
    { direction: "operation", method: req.method, path: req.path, headers: req.headers, body: req.body },
    {
      pairing: site.pairing, keys: site.keys, now: deps.now(), write: op?.write ?? false,
      // Store methods are always called as methods, so a store written as a class keeps its `this`.
      claimNonce: (scope, nonce) => deps.nonces.claim(scope, nonce),
      // The cause is for the site's own log only: the answer is `bad_signature` and nothing else, whatever it was.
      onUnverified: (cause, keyId) => log(`[wire] not verified: ${cause}${keyId === null ? "" : ` (key ${keyId})`}`),
    },
  );
  if (!checked.ok) return errorAnswer(checked.code);

  // The signed path names the same operation as the route and the body: `op` is the path's name, part of the body's own shape.
  if (!req.path.endsWith(`/ops/${name}`)) return errorAnswer("bad_input");
  // The body and the operation, in the contract's order: the body's own shape (bad_input, whatever the path names), then an
  // operation the site does not offer (unknown_operation), then `marked` and `input` (bad_input).
  const body = deps.registry.checkBody(req.body, name);
  if (!body.ok) return errorAnswer(body.code);
  // `describe` is the contract's own operation: a read that takes nothing.
  if (!op) return { status: 200, body: { data: deps.registry.describe } };
  const input = body.input;
  const marked = body.marked;

  // The answer is checked before it is kept: data that does not fit, or is over 1 MiB, is `internal`, and a write's whole transaction
  // rolls back with it (internal is retry-later, so it is never kept).
  const finish = (data: Record<string, unknown>): WireAnswer => {
    if (!deps.registry.answerFits(op, data)) {
      log(`[wire] ${op.name} answered data that does not fit its declaration`);
      return errorAnswer("internal");
    }
    if (Buffer.byteLength(JSON.stringify({ data }), "utf8") > WIRE_ANSWER_MAX_BYTES) {
      log(`[wire] ${op.name} answered more than 1 MiB`);
      return errorAnswer("internal");
    }
    return { status: 200, body: { data } };
  };
  const refusal = (err: unknown): WireAnswer => {
    if (!(err instanceof WireRefusal)) throw err;
    if (REFUSALS.has(err.code)) return errorAnswer(err.code);
    log(`[wire] ${op.name} refused with a code it may not use`);
    return errorAnswer("internal");
  };
  const deadline = deps.deadlineMs ?? WIRE_ANSWER_SECONDS * 1000;

  if (op.write) {
    const claim = { pairing: site.pairing, retryKey: checked.retry!, bodyHash: bodyHash(req.body), op: op.name };
    return deps.answers.once(claim, async (tx) => {
      let data: Record<string, unknown>;
      try {
        // In a savepoint: a refusal undoes whatever the operation did before it, and the refusal is still kept as the answer.
        data = await deps.answers.savepoint(tx, (sp) =>
          op.run(input, { pairing: site.pairing, keyId: checked.keyId, retryKey: checked.retry, marked, tx: sp, signal: new AbortController().signal }));
      } catch (err) {
        return refusal(err);
      }
      return finish(data);
    });
  }

  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const late = new Promise<"late">((resolve) => {
      timer = setTimeout(() => { abort.abort(new Error("deadline")); resolve("late"); }, deadline);
    });
    // The operation is called inside a promise, so one that throws at once (a function that is not async) refuses or fails exactly
    // as one that rejects later does: a `WireRefusal` is its answer, never `internal`.
    const started = new Promise<Record<string, unknown>>((resolve) => {
      resolve(op.run(input, { pairing: site.pairing, keyId: checked.keyId, retryKey: checked.retry, marked, tx: undefined, signal: abort.signal }));
    });
    const work = started.then(finish, refusal);
    // Past the deadline nobody waits for the work: its later failure must not go unhandled.
    work.catch(() => {});
    const result = await Promise.race([work, late]);
    return result === "late" ? errorAnswer("unavailable") : result;
  } finally {
    // Whatever happened above, the deadline's timer never outlives the request.
    clearTimeout(timer);
  }
}

/**
 * What a site that is not paired answers from: no pairing id (the empty string is no pairing's id) and a keyring that holds no key,
 * loaded once, here, ahead of any request. Every key id is then simply not held (contract section 3, step 5), and the check does for
 * it what it does for any key that is not held: the one verification, against the decoy.
 */
const NOT_PAIRED: SitePairing = Object.freeze({ pairing: "", keys: loadWireKeys([]) });

/** Handles one request for the operation `name` (the last path segment). Never throws: a failure is `internal`. */
export async function handleOperation<Tx>(req: WireHttpRequest, name: string, deps: HandlerDeps<Tx>): Promise<WireHttpResponse> {
  const log = safeLog(deps.log);
  // Paired or not, every request goes the same way: the limit, then the checks, whatever its method. Not paired, or a pairing that
  // cannot be read: the same path with no key held, so the answers are a paired site's. Why it could not be read is for the log only.
  let site: SitePairing;
  try {
    site = deps.pairing() ?? NOT_PAIRED;
  } catch (err) {
    log(`[wire] the pairing could not be read (${err instanceof Error ? err.name : "unknown error"}); answering as a site that is not paired`);
    site = NOT_PAIRED;
  }
  try {
    return respond(await answer(req, name, site, deps, log), log);
  } catch (err) {
    log(`[wire] a request failed: ${err instanceof Error ? err.name : "unknown error"}`);
    return respond(errorAnswer("internal"), log);
  }
}

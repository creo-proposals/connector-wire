/**
 * The sending side, for both ends: `callOperation` (the board calling a site's operation) and `sendEvent` (a site sending an event to
 * the board), plus `drainOutbox`, a site's loop over its outbox. Each request goes to an `https://` address and no other, on the paired
 * address's own host and no other, at a path that fits the contract's pattern for a path (anything else is refused before anything is
 * signed or sent), is signed fresh (a new time and one-use number), never follows a redirect, waits at most 10 seconds and reads at
 * most 1 MiB of answer. The answer is read with the contract's own reader
 * (`checkAnswerBody`, which takes the HTTP status): anything that is not exactly an answer is `internal`. Whether to try again later or
 * never follows the contract's rules: later on `rate_limited`, `unavailable`, `internal` or no answer at all; never on any other code.
 */
import type { KeyObject } from "node:crypto";
import { readCapped } from "./handler.js";
import { newNonce } from "./keys.js";
import type { WireRegistry } from "./registry.js";
import { nextTry, type OutboxStore } from "./stores.js";
import {
  checkAnswerBody, signWire, WIRE_ANSWER_MAX_BYTES, WIRE_ANSWER_SECONDS, WIRE_OPERATION_NAME, WIRE_RETRY_LATER,
  type WireError, type WireOperationDecl,
} from "./wire.js";

/** Who signs: this side's private key of the direction, its id, and the pairing. */
export interface Signer {
  readonly pairing: string;
  readonly keyId: string;
  readonly privateKey: KeyObject;
}

export interface SendOptions {
  /** Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /** Defaults to the clock. */
  readonly now?: () => Date;
  /** At most WIRE_ANSWER_SECONDS (10 s), the default. */
  readonly timeoutMs?: number;
}

/**
 * What came back, as the contract reads it. `retry`: "later" (send again with a fresh time and number, the same retry key or event
 * id) or "never". An answer that is not exactly an answer is read as `internal`, later: a body over 1 MiB, bytes that are not UTF-8,
 * text that is not JSON or repeats a key, a status that is neither 2xx nor 4xx or 5xx, data that does not fit the declaration, a code
 * that is not one of the contract's or a sentence beside it. `problem` is for this side's own log: `noAnswer` when nothing came back
 * (a timeout or a dropped connection; there is no code), `redirect` when the answer was a redirect (never followed, read as
 * `internal`).
 */
export type SendResult =
  | { readonly ok: true; readonly data: Readonly<Record<string, unknown>> }
  | { readonly ok: false; readonly code: WireError | null; readonly problem?: "noAnswer" | "redirect"; readonly retry: "later" | "never" };

const later = (code: WireError | null, problem?: "noAnswer" | "redirect"): SendResult => ({ ok: false, code, retry: "later", ...(problem ? { problem } : {}) });
const retryFor = (code: WireError): "later" | "never" => ((WIRE_RETRY_LATER as readonly string[]).includes(code) ? "later" : "never");

/** What the answer is read against: the operation asked, and the declarations held for it. */
interface Asked {
  readonly op: string;
  readonly operations: readonly WireOperationDecl[];
}

async function post(url: string, path: string, body: string, signer: Signer, direction: "operation" | "event", retry: string | undefined,
  asked: Asked, options: SendOptions): Promise<SendResult> {
  const timeoutMs = Math.min(options.timeoutMs ?? WIRE_ANSWER_SECONDS * 1000, WIRE_ANSWER_SECONDS * 1000);
  const now = (options.now ?? (() => new Date()))();
  const headers = signWire({
    direction, method: "POST", path, body, keyId: signer.keyId, pairing: signer.pairing, privateKey: signer.privateKey,
    // The header is Unix time in whole seconds.
    time: Math.floor(now.getTime() / 1000), nonce: newNonce(), ...(retry !== undefined ? { retry } : {}),
  });
  const started = Date.now();
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  let res: Response;
  try {
    res = await (options.fetch ?? fetch)(url, {
      method: "POST", body, redirect: "manual", signal: abort.signal,
      headers: { ...headers, "content-type": "application/json" },
    });
  } catch {
    clearTimeout(timer);
    return later(null, "noAnswer");
  }
  try {
    // A redirect is never followed and never an answer: the paired address is the only one.
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      await res.body?.cancel().catch(() => {});
      return later("internal", "redirect");
    }
    let raw: Uint8Array;
    try {
      // One byte past the cap is enough to know the answer is too large; the reader refuses it.
      raw = await readCapped(res.body, { limit: WIRE_ANSWER_MAX_BYTES, timeoutMs: Math.max(1, timeoutMs - (Date.now() - started)) });
    } catch {
      return later(null, "noAnswer");
    }
    const r = checkAnswerBody(raw, res.status, asked.op, asked.operations);
    return r.ok ? { ok: true, data: r.data } : { ok: false, code: r.code, retry: retryFor(r.code) };
  } finally {
    clearTimeout(timer);
  }
}

/** The contract's pattern for a path (section 2): a `/`, then at most 511 of letters, digits and `. _ ~ / -`. No query, no escape. */
const REQUEST_PATH = /^\/[A-Za-z0-9._~/-]{0,511}$/;

/** A path without the slashes it ends with: `/base/` and `/base` are one base, and `/` is none. */
function withoutTrailingSlashes(path: string): string {
  let end = path.length;
  while (end > 0 && path.charCodeAt(end - 1) === 0x2f) end--;
  return path.slice(0, end);
}

/**
 * A paired address, read once: the site's base or the board's events address. The contract's requests are HTTPS, and an answer is
 * trusted only because it came over TLS from the paired host (contract sections 2 and 8). So an address of any other scheme is
 * refused here, before anything is signed: there is no exception, for a local address or any other (a test passes its own `fetch`).
 * So is one that carries credentials (the host is what follows them), a query string or a fragment, even an empty one.
 */
function pairedAddress(address: string, who: string): URL {
  if (typeof address !== "string") throw new TypeError(`${who}: the address is a string`);
  const url = new URL(address);
  if (url.protocol !== "https:") throw new TypeError(`${who}: the address is https, never any other scheme`);
  if (url.username !== "" || url.password !== "") throw new TypeError(`${who}: the address carries no credentials`);
  if (url.search !== "" || url.hash !== "" || address.includes("?") || address.includes("#")) {
    throw new TypeError(`${who}: the address has no query string or fragment`);
  }
  return url;
}

/**
 * Where one request goes: `path` on the paired address's own host, and nowhere else. The path is the one that will be signed, so it is
 * held to the contract's pattern first, before anything is signed. Then the address is made from the paired address's origin and
 * that path, and it must be exactly that: the same origin, the same path, nothing more. A path that an address parser would read
 * another way (`//other.example/...` names a host; a backslash is read as a slash) never leaves here as an address: it is refused.
 */
function requestAddress(paired: URL, path: string, who: string): string {
  if (!REQUEST_PATH.test(path)) throw new TypeError(`${who}: the request's path does not fit the contract's pattern for a path`);
  const to = new URL(path, paired.origin);
  if (to.origin !== paired.origin || to.pathname !== path || to.search !== "" || to.hash !== "" || to.username !== "" || to.password !== "") {
    throw new TypeError(`${who}: the request would not go to the paired address's host at the path that is signed`);
  }
  return to.href;
}

/** The board's events address, checked: where an event goes, and the path it is signed for (the address's own path, as it is). */
function eventsAddress(eventsUrl: string, who: string): { url: string; path: string } {
  const paired = pairedAddress(eventsUrl, who);
  return { url: requestAddress(paired, paired.pathname, who), path: paired.pathname };
}

/** A call of a site's operation, as the board makes it. */
export interface OperationCall {
  /**
   * The site's base address, as paired: `https://`, no credentials, no query string, no fragment. Every request goes to this
   * address's host and no other; one that would not is refused before anything is signed.
   */
  readonly siteBase: string;
  readonly op: string;
  /** Exactly the operation's declared input fields. */
  readonly input: Readonly<Record<string, unknown>>;
  /**
   * True when the run that makes the request had received outside text (words from outside the business, or a model's reading of
   * them), false otherwise. It is inside the signed body, and it is never left out: there is no default.
   */
  readonly marked: boolean;
  /**
   * The site's operations as the board holds them (its `describe`): the answer is read against the declaration of `op` here, and an
   * operation with no sound declaration here has no answer the board can read (`internal`). `describe` itself needs none: `[]`.
   */
  readonly operations: readonly WireOperationDecl[];
  /** A write needs its retry key; send the same one on every retry. */
  readonly retryKey?: string;
}

/**
 * Calls a site's operation: POST `<siteBase>/wire/v0/ops/<op>` with exactly `{"op","input","marked"}`, signed with the board's
 * operation key, and reads the answer against the board's own copy of the site's declarations. The path is the base's own path and
 * `/wire/v0/ops/<op>`, joined as text; a base it cannot be sent to as signed, on the base's own host, throws a `TypeError` first.
 */
export async function callOperation(call: OperationCall, signer: Signer, options: SendOptions = {}): Promise<SendResult> {
  if (typeof call.marked !== "boolean") throw new TypeError("callOperation: marked is true or false");
  if (typeof call.op !== "string" || !WIRE_OPERATION_NAME.test(call.op)) throw new TypeError("callOperation: op is an operation's name");
  const base = pairedAddress(call.siteBase, "callOperation");
  const path = `${withoutTrailingSlashes(base.pathname)}/wire/v0/ops/${call.op}`;
  const url = requestAddress(base, path, "callOperation");
  const body = JSON.stringify({ op: call.op, input: call.input, marked: call.marked });
  return post(url, path, body, signer, "operation", call.retryKey, { op: call.op, operations: call.operations }, options);
}

/**
 * How the board's answer to an event is read: with the same reader as an operation's answer, against one declaration whose answer is
 * the single field `recorded`.
 */
const EVENT_ASKED: Asked = {
  op: "event",
  operations: [{ name: "event", write: true, input: [], answer: [{ name: "recorded", type: "yesNo", provenance: "code" }], freeText: false }],
};

/**
 * Sends one event to the board's address (`https://`, no credentials, no query string, no fragment, a path that fits the contract's
 * pattern: anything else throws before anything is signed), signed with the site's event key. It goes to that address's host and no
 * other. `body` is the event's JSON, from `registry.eventBody`. Only `{"data":{"recorded":true}}` is success.
 */
export async function sendEvent(eventsUrl: string, body: string, signer: Signer, options: SendOptions = {}): Promise<SendResult> {
  const to = eventsAddress(eventsUrl, "sendEvent");
  const r = await post(to.url, to.path, body, signer, "event", undefined, EVENT_ASKED, options);
  if (!r.ok) return r;
  return r.data.recorded === true ? r : later("internal");
}

/**
 * Sends the outbox's due events for the current pairing (the signer's), oldest first, at most `limit`. An event queued for any other
 * pairing is left as it is, unsent: after a site is paired again, an earlier pairing's events are never signed for the new one. Each
 * event is built again from the site's own declaration (an event that no
 * longer fits is marked dead, never sent), sent, then marked sent, tried again later (backing off up to a day), or dead. Run it after
 * a write that added events and on a schedule. An events address `sendEvent` would refuse throws before any event is touched.
 */
export async function drainOutbox<Tx>(
  outbox: OutboxStore<Tx>,
  registry: WireRegistry<Tx>,
  board: { eventsUrl: string; signer: Signer },
  options: SendOptions & { limit?: number } = {},
): Promise<{ sent: number; retry: number; dead: number }> {
  const now = options.now ?? (() => new Date());
  eventsAddress(board.eventsUrl, "drainOutbox");
  const counts = { sent: 0, retry: 0, dead: 0 };
  const pairing = board.signer.pairing;
  for (const e of await outbox.due(pairing, now(), options.limit ?? 50)) {
    // Whatever a store hands over, an event queued for another pairing is never signed for this one: it stays, untouched.
    if (e.pairing !== pairing) continue;
    let body: string;
    try {
      body = registry.eventBody(e.kind, e.id, e.at, e.fields);
    } catch {
      await outbox.markDead(e.id);
      counts.dead++;
      continue;
    }
    const r = await sendEvent(board.eventsUrl, body, board.signer, options);
    if (r.ok) {
      await outbox.markSent(e.id, now());
      counts.sent++;
    } else if (r.retry === "later") {
      await outbox.markRetry(e.id, nextTry(e.tries + 1, now()));
      counts.retry++;
    } else {
      await outbox.markDead(e.id);
      counts.dead++;
    }
  }
  return counts;
}

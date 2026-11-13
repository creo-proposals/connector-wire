import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  callOperation, checkEvent, createRegistry, drainOutbox, handleOperation, loadWireKeys, newKeyPair, readCapped, sendEvent,
  testAnswers, testNonces, testOutbox, verifyWire, WIRE_ANSWER_MAX_BYTES, wirePublicKey, type OperationCall, type Signer,
} from "../src/index.js";

// Keys made inside the test. Never real keys.
const boardOp = newKeyPair(), siteEv = newKeyPair();
const NOW = () => new Date();
const PAIRING = "site-test";
const boardSigner: Signer = { pairing: PAIRING, keyId: "op-1", privateKey: boardOp.privateKey };
const siteSigner: Signer = { pairing: PAIRING, keyId: "ev-1", privateKey: siteEv.privateKey };
// Each side's keys, loaded once, ahead of every request.
const siteKeys = loadWireKeys([{ id: "op-1", pairing: PAIRING, direction: "operation", publicKey: boardOp.publicKey, from: "2000-01-01T00:00:00Z" }]);
const boardKeys = loadWireKeys([{ id: "ev-1", pairing: PAIRING, direction: "event", publicKey: siteEv.publicKey, from: "2000-01-01T00:00:00Z" }]);
const EVENTS = [{ kind: "shop.feed.loaded", sender: "system" as const, fields: [{ name: "added", type: "number" as const, min: 0 }] }];

const registry = createRegistry([
  {
    name: "things.count", write: false, input: [], answer: [{ name: "count", type: "number", provenance: "code" }],
    run: async () => ({ count: 3 }),
  },
  {
    name: "things.hide", write: true, input: [{ name: "id", type: "id" }],
    answer: [{ name: "changed", type: "yesNo", provenance: "code" }], run: async () => ({ changed: true }),
  },
  {
    name: "things.marked", write: false, input: [], answer: [{ name: "marked", type: "yesNo", provenance: "code" }],
    run: async (_input, ctx) => ({ marked: ctx.marked }),
  },
], EVENTS);
// The site's operations as the board holds them: its describe.
const DECLARED = registry.describe.operations;
const call = (op: string, input: Record<string, unknown> = {}, over: Partial<OperationCall> = {}): OperationCall =>
  ({ siteBase: base, op, input, marked: false, operations: DECLARED, ...over });

type Route = (req: IncomingMessage, res: ServerResponse, body: Uint8Array) => void | Promise<void>;
let server: Server;
// The paired address is always https. The test's own fetch carries each request to the plain Node server below, which stands for
// the far side: nothing is ever sent to an address that is not https, so nothing here is.
const base = "https://site.test";
let local = "";
const viaLocal: typeof fetch = (input, init) => fetch(String(input).replace(base, local), init);
const VIA = { fetch: viaLocal };
const routes = new Map<string, Route>();
const nonces = testNonces();
const answers = testAnswers();
const recorded: string[] = [];

beforeAll(async () => {
  // The site, mounted on a plain Node server: the handler is framework-neutral.
  routes.set("/wire/v0/ops/", async (req, res, body) => {
    const url = new URL(req.url!, "http://x");
    const r = await handleOperation(
      { method: req.method!, path: url.pathname + url.search, headers: req.headers, body },
      url.pathname.split("/").pop()!,
      { pairing: () => ({ pairing: PAIRING, keys: siteKeys }), registry, nonces, answers, now: NOW },
    );
    res.writeHead(r.status, r.headers).end(r.body ?? undefined);
  });
  // A board that checks events as the contract says.
  const boardNonces = testNonces();
  routes.set("/hooks/site", async (req, res, body) => {
    const v = await verifyWire(
      { direction: "event", method: req.method!, path: "/hooks/site", headers: req.headers, body },
      { pairing: PAIRING, keys: boardKeys, now: new Date(), write: false, claimNonce: (s, n) => boardNonces.claim(s, n) },
    );
    if (!v.ok) return void res.writeHead(401).end(JSON.stringify({ error: { code: v.code } }));
    const e = checkEvent(body, EVENTS);
    if (!e.ok) return void res.writeHead(400).end(JSON.stringify({ error: { code: e.code } }));
    recorded.push(e.id);
    res.writeHead(200).end('{"data":{"recorded":true}}');
  });
  routes.set("/redirect", (_q, res) => void res.writeHead(302, { location: "/hooks/site" }).end());
  routes.set("/silent", () => {});
  // Answers that are right in every way but their size: the answer itself, then spaces (which JSON allows after a value) up to
  // exactly 1 MiB, and to one byte more. Only the size differs between the two.
  const padded = (answer: string, bytes: number): string => answer.padEnd(bytes, " ");
  routes.set("/atcap", (_q, res) => void res.writeHead(200).end(padded('{"data":{"recorded":true}}', WIRE_ANSWER_MAX_BYTES)));
  routes.set("/huge", (_q, res) => void res.writeHead(200).end(padded('{"data":{"recorded":true}}', WIRE_ANSWER_MAX_BYTES + 1)));
  routes.set("/atcap/wire/v0/ops/", (_q, res) => void res.writeHead(200).end(padded('{"data":{"count":3}}', WIRE_ANSWER_MAX_BYTES)));
  routes.set("/huge/wire/v0/ops/", (_q, res) => void res.writeHead(200).end(padded('{"data":{"count":3}}', WIRE_ANSWER_MAX_BYTES + 1)));
  routes.set("/repeat", (_q, res) => void res.writeHead(200).end('{"data":{"recorded":true,"recorded":true}}'));
  routes.set("/sentence", (_q, res) => void res.writeHead(404).end('{"error":{"code":"not_found","message":"words"}}'));
  routes.set("/madeup", (_q, res) => void res.writeHead(409).end('{"error":{"code":"made_up_code"}}'));
  routes.set("/errorin2xx", (_q, res) => void res.writeHead(200).end('{"error":{"code":"not_found"}}'));
  routes.set("/datain4xx", (_q, res) => void res.writeHead(400).end('{"data":{"recorded":true}}'));
  routes.set("/extra", (_q, res) => void res.writeHead(200).end('{"data":{"recorded":true,"more":1}}'));
  routes.set("/notutf8", (_q, res) => void res.writeHead(200).end(Buffer.concat([Buffer.from('{"data":{"recorded":true},"x":"'), Buffer.from([0xff]), Buffer.from('"}')])));
  for (const code of ["rate_limited", "unavailable", "internal", "bad_event", "replayed"]) {
    routes.set(`/code/${code}`, (_q, res) => void res.writeHead(code === "rate_limited" ? 429 : 400).end(JSON.stringify({ error: { code } })));
  }
  routes.set("/notrecorded", (_q, res) => void res.writeHead(200).end('{"data":{"recorded":false}}'));
  server = createServer(async (req, res) => {
    const body = await readCapped(req);
    const path = new URL(req.url!, "http://x").pathname;
    const route = [...routes].find(([p]) => (p.endsWith("/") ? path.startsWith(p) : path === p))?.[1];
    if (!route) return void res.writeHead(404).end();
    await route(req, res, body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  local = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
});

describe("calling an operation (the board's side)", () => {
  it("calls a read and a write through a real site", async () => {
    expect(await callOperation(call("things.count"), boardSigner, VIA)).toEqual({ ok: true, data: { count: 3 } });
    expect(await callOperation(call("describe", {}, { siteBase: `${base}/`, operations: [] }), boardSigner, VIA)).toEqual({ ok: true, data: registry.describe });
    const w = call("things.hide", { id: "T-1" }, { retryKey: "retry-send-00000001" });
    expect(await callOperation(w, boardSigner, VIA)).toEqual({ ok: true, data: { changed: true } });
    expect(await callOperation(w, boardSigner, VIA)).toEqual({ ok: true, data: { changed: true } });
  });
  it("sends marked inside the signed body, as given", async () => {
    expect(await callOperation(call("things.marked", {}, { marked: true }), boardSigner, VIA)).toEqual({ ok: true, data: { marked: true } });
    expect(await callOperation(call("things.marked"), boardSigner, VIA)).toEqual({ ok: true, data: { marked: false } });
    await expect(callOperation({ ...call("things.marked"), marked: undefined as never }, boardSigner, VIA)).rejects.toThrow(TypeError);
  });
  it("gets the site's refusals with their retry rule", async () => {
    expect(await callOperation(call("things.hide", { id: "T-1" }), boardSigner, VIA)).toEqual({ ok: false, code: "missing_retry_key", retry: "never" });
    expect(await callOperation(call("things.count"), { ...boardSigner, pairing: "site-other" }, VIA)).toEqual({ ok: false, code: "bad_signature", retry: "never" });
    expect(await callOperation(call("things.hide", { id: "not an id" }, { retryKey: "retry-send-00000002" }), boardSigner, VIA)).toEqual({ ok: false, code: "bad_input", retry: "never" });
    expect(await callOperation(call("things.other", {}, { operations: [] }), boardSigner, VIA)).toEqual({ ok: false, code: "unknown_operation", retry: "never" });
  });
  it("reads an answer it holds no declaration for, or another declaration, as internal", async () => {
    expect(await callOperation(call("things.count", {}, { operations: [] }), boardSigner, VIA)).toEqual({ ok: false, code: "internal", retry: "later" });
    const other = [{ name: "things.count", write: false, input: [], answer: [{ name: "total", type: "number" as const, provenance: "code" as const }], freeText: false }];
    expect(await callOperation(call("things.count", {}, { operations: other }), boardSigner, VIA)).toEqual({ ok: false, code: "internal", retry: "later" });
  });
  it("reads an answer of 1 MiB and one byte as internal, for its size alone: the same answer at exactly 1 MiB is read", async () => {
    expect(await callOperation(call("things.count", {}, { siteBase: `${base}/atcap` }), boardSigner, VIA)).toEqual({ ok: true, data: { count: 3 } });
    expect(await callOperation(call("things.count", {}, { siteBase: `${base}/huge` }), boardSigner, VIA)).toEqual({ ok: false, code: "internal", retry: "later" });
  });
  it("refuses a base address with a query, and a name that is not an operation's", async () => {
    await expect(callOperation(call("describe", {}, { siteBase: `${base}/?x=1` }), boardSigner, VIA)).rejects.toThrow(TypeError);
    await expect(callOperation(call("things/../x"), boardSigner, VIA)).rejects.toThrow(TypeError);
  });
});

describe("sending an event (the site's side)", () => {
  const body = (id: string, added = 1) => registry.eventBody("shop.feed.loaded", id, "2098-12-31T23:59:30Z", { added });
  it("is recorded by a board that checks it", async () => {
    expect(await sendEvent(`${base}/hooks/site`, body("ev-a"), siteSigner, VIA)).toEqual({ ok: true, data: { recorded: true } });
    expect(recorded).toContain("ev-a");
  });
  it("never follows a redirect: it is read as internal", async () => {
    expect(await sendEvent(`${base}/redirect`, body("ev-b"), siteSigner, VIA)).toEqual({ ok: false, code: "internal", problem: "redirect", retry: "later" });
    expect(recorded).not.toContain("ev-b");
  });
  it("gives up waiting within the time, and tries again later", async () => {
    const t0 = Date.now();
    expect(await sendEvent(`${base}/silent`, body("ev-c"), siteSigner, { ...VIA, timeoutMs: 100 })).toEqual({ ok: false, code: null, problem: "noAnswer", retry: "later" });
    expect(Date.now() - t0).toBeLessThan(2000);
    // A connection that fails outright is no answer too.
    const down: typeof fetch = async () => { throw new TypeError("fetch failed"); };
    expect(await sendEvent(`${base}/hooks/site`, body("ev-c"), siteSigner, { fetch: down })).toEqual({ ok: false, code: null, problem: "noAnswer", retry: "later" });
  });
  it("reads an answer of 1 MiB and one byte as internal, for its size alone: the same answer at exactly 1 MiB is read", async () => {
    expect(await sendEvent(`${base}/atcap`, body("ev-f"), siteSigner, VIA)).toEqual({ ok: true, data: { recorded: true } });
    expect(await sendEvent(`${base}/huge`, body("ev-f"), siteSigner, VIA)).toEqual({ ok: false, code: "internal", retry: "later" });
  });
  it("reads anything that is not exactly an answer as internal, later", async () => {
    for (const p of ["/repeat", "/sentence", "/madeup", "/errorin2xx", "/datain4xx", "/extra", "/notutf8", "/notrecorded"]) {
      expect(await sendEvent(`${base}${p}`, body("ev-d"), siteSigner, VIA), p).toEqual({ ok: false, code: "internal", retry: "later" });
    }
  });
  it("tries again later on the retry-later codes and never on the others", async () => {
    for (const c of ["rate_limited", "unavailable", "internal"]) expect((await sendEvent(`${base}/code/${c}`, body("ev-e"), siteSigner, VIA)), c).toEqual({ ok: false, code: c, retry: "later" });
    for (const c of ["bad_event", "replayed"]) expect((await sendEvent(`${base}/code/${c}`, body("ev-e"), siteSigner, VIA)), c).toEqual({ ok: false, code: c, retry: "never" });
  });
});

describe("the address a request is sent to", () => {
  const event = () => registry.eventBody("shop.feed.loaded", "ev-https", "2098-12-31T23:59:30Z", { added: 1 });

  it("is https, or nothing is signed and nothing is sent", async () => {
    const asked: string[] = [];
    const counting: typeof fetch = async (input) => { asked.push(String(input)); return new Response('{"data":{"recorded":true}}'); };
    for (const address of ["http://site.test", "HTTP://site.test", "http://127.0.0.1:8080", "http://localhost", "ws://site.test", "ftp://site.test"]) {
      await expect(callOperation(call("describe", {}, { siteBase: address, operations: [] }), boardSigner, { fetch: counting }), address).rejects.toThrow(TypeError);
      await expect(sendEvent(`${address}/hooks/site`, event(), siteSigner, { fetch: counting }), address).rejects.toThrow(TypeError);
      const outbox = testOutbox();
      await outbox.add({ id: "ev-https", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: { added: 1 } });
      await expect(drainOutbox(outbox, registry, { eventsUrl: `${address}/hooks/site`, signer: siteSigner }, { fetch: counting }), address).rejects.toThrow(TypeError);
      // The event is still waiting: an address that is refused is this side's own mistake, never the event's.
      expect(await outbox.get("ev-https"), address).toMatchObject({ tries: 0, sentAt: null, dead: false });
    }
    expect(asked).toEqual([]);
  });

  it("is used as given when it is https", async () => {
    const asked: string[] = [];
    const counting: typeof fetch = async (input) => { asked.push(String(input)); return new Response('{"data":{"recorded":true}}'); };
    expect(await sendEvent("https://board.test/hooks/site", event(), siteSigner, { fetch: counting })).toEqual({ ok: true, data: { recorded: true } });
    expect(asked).toEqual(["https://board.test/hooks/site"]);
  });
});

describe("the host a request is sent to", () => {
  const event = () => registry.eventBody("shop.feed.loaded", "ev-host", "2098-12-31T23:59:30Z", { added: 1 });
  // A fetch that only counts, and a signer whose private key is counted when it is read: nothing is signed without reading it.
  const watch = (signer: Signer) => {
    const asked: string[] = [];
    let keyReads = 0;
    const counting: typeof fetch = async (input) => { asked.push(String(input)); return new Response('{"data":{"recorded":true}}'); };
    const watched: Signer = { pairing: signer.pairing, keyId: signer.keyId, get privateKey() { keyReads++; return signer.privateKey; } };
    return { asked, counting, watched, keyReads: () => keyReads };
  };

  it("is the paired address's host and no other: a base that would lead to another host is refused, with nothing signed or sent", async () => {
    const w = watch(boardSigner);
    const hostile = [
      // An empty first segment: resolved against the paired host, `//other.example/...` names another host.
      "https://paired.example//other.example",
      "https://paired.example//other.example/",
      // A backslash is read as a slash in an https address, so these are the same thing.
      "https://paired.example/\\other.example",
      "https://paired.example\\\\other.example",
      // Credentials: the host is what follows them.
      "https://paired.example@other.example",
      "https://someone:word@paired.example",
    ];
    for (const siteBase of hostile) {
      await expect(callOperation(call("describe", {}, { siteBase, operations: [] }), w.watched, { fetch: w.counting }), siteBase).rejects.toThrow(TypeError);
    }
    expect(w.asked).toEqual([]);
    expect(w.keyReads()).toBe(0);
  });

  it("refuses a base whose path would fail the contract's pattern for a path (section 2), before anything is signed", async () => {
    const w = watch(boardSigner);
    const unfit = [
      "https://paired.example/a%20b",
      "https://paired.example/a b",
      "https://paired.example/café",
      "https://paired.example/a@b",
      // 513 characters and more with the operation's own part.
      `https://paired.example/${"a".repeat(500)}`,
      // A query or a fragment, even an empty one.
      "https://paired.example/base?x=1",
      "https://paired.example/base?",
      "https://paired.example/base#top",
      "https://paired.example/base#",
    ];
    for (const siteBase of unfit) {
      await expect(callOperation(call("describe", {}, { siteBase, operations: [] }), w.watched, { fetch: w.counting }), siteBase).rejects.toThrow(TypeError);
    }
    expect(w.asked).toEqual([]);
    expect(w.keyReads()).toBe(0);
  });

  it("takes a base with or without a trailing slash, and signs exactly the path it asks for", async () => {
    const seen: [url: string, verified: boolean][] = [];
    // The far side: it checks the request as a site does, at the path the request arrived on.
    const checking: typeof fetch = async (input, init) => {
      const v = await verifyWire(
        { direction: "operation", method: init!.method!, path: new URL(String(input)).pathname, headers: init!.headers as Record<string, string>, body: init!.body as string },
        { pairing: PAIRING, keys: siteKeys, now: new Date(), write: false, claimNonce: () => true },
      );
      seen.push([String(input), v.ok]);
      return new Response('{"data":{"count":3}}');
    };
    const bases = ["https://site.test", "https://site.test/", "https://site.test/base", "https://site.test/base/", "https://site.test:8443/base//"];
    for (const siteBase of bases) {
      expect(await callOperation(call("things.count", {}, { siteBase }), boardSigner, { fetch: checking }), siteBase).toEqual({ ok: true, data: { count: 3 } });
    }
    expect(seen).toEqual([
      ["https://site.test/wire/v0/ops/things.count", true],
      ["https://site.test/wire/v0/ops/things.count", true],
      ["https://site.test/base/wire/v0/ops/things.count", true],
      ["https://site.test/base/wire/v0/ops/things.count", true],
      ["https://site.test:8443/base/wire/v0/ops/things.count", true],
    ]);
  });

  it("holds the events address to the same rules: its own host, a path that fits the pattern, nothing signed or sent otherwise", async () => {
    const w = watch(siteSigner);
    const refused = [
      "https://board.example//other.example/hooks/site",
      "https://board.example/\\other.example/hooks/site",
      "https://board.example@other.example/hooks/site",
      "https://someone:word@board.example/hooks/site",
      "https://board.example/hooks/a%20b",
      "https://board.example/hooks/site?x=1",
      "https://board.example/hooks/site?",
      "https://board.example/hooks/site#top",
      "https://board.example/hooks/site#",
    ];
    for (const address of refused) {
      await expect(sendEvent(address, event(), w.watched, { fetch: w.counting }), address).rejects.toThrow(TypeError);
      // The outbox's sender refuses the address before it touches an event: the event is still waiting.
      const outbox = testOutbox();
      await outbox.add({ id: "ev-host", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: { added: 1 } });
      await expect(drainOutbox(outbox, registry, { eventsUrl: address, signer: w.watched }, { fetch: w.counting }), address).rejects.toThrow(TypeError);
      expect(await outbox.get("ev-host"), address).toMatchObject({ tries: 0, sentAt: null, dead: false });
    }
    expect(w.asked).toEqual([]);
    expect(w.keyReads()).toBe(0);
    // An address with no path of its own is the path `/`.
    expect(await sendEvent("https://board.test", event(), siteSigner, { fetch: w.counting })).toEqual({ ok: true, data: { recorded: true } });
    expect(w.asked).toEqual(["https://board.test/"]);
  });
});

describe("draining the outbox", () => {
  it("sends, retries later and marks dead by the rules", async () => {
    const outbox = testOutbox();
    await outbox.add({ id: "ev-ok", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: { added: 1 } });
    await outbox.add({ id: "ev-unfit", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:31Z", fields: { added: -5 } });
    // The board here checks times against its real clock, so the drain runs at the real time too.
    const now = new Date(Math.floor(Date.now() / 1000) * 1000);
    expect(await drainOutbox(outbox, registry, { eventsUrl: `${base}/hooks/site`, signer: siteSigner }, { ...VIA, now: () => now })).toEqual({ sent: 1, retry: 0, dead: 1 });
    expect((await outbox.get("ev-ok"))?.sentAt).toEqual(now);
    expect((await outbox.get("ev-unfit"))?.dead).toBe(true);

    await outbox.add({ id: "ev-busy", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:32Z", fields: { added: 2 } });
    expect(await drainOutbox(outbox, registry, { eventsUrl: `${base}/code/unavailable`, signer: siteSigner }, { ...VIA, now: () => now })).toEqual({ sent: 0, retry: 1, dead: 0 });
    expect(await outbox.get("ev-busy")).toMatchObject({ tries: 1, nextAt: new Date(now.getTime() + 60_000), dead: false });
    expect(await drainOutbox(outbox, registry, { eventsUrl: `${base}/code/bad_event`, signer: siteSigner }, { ...VIA, now: () => new Date(now.getTime() + 60_000) })).toEqual({ sent: 0, retry: 0, dead: 1 });
    expect(wirePublicKey(siteEv.publicKey)).not.toBeNull();
  });

  it("sends only the events queued for the pairing it signs for: after pairing again, an earlier pairing's events stay unsent", async () => {
    const outbox = testOutbox();
    await outbox.add({ id: "ev-before", pairing: "site-before", kind: "shop.feed.loaded", at: "2098-12-31T23:59:00Z", fields: { added: 1 } });
    await outbox.add({ id: "ev-now", pairing: PAIRING, kind: "shop.feed.loaded", at: "2098-12-31T23:59:30Z", fields: { added: 2 } });
    const now = new Date(Math.floor(Date.now() / 1000) * 1000);
    const board = { eventsUrl: `${base}/hooks/site`, signer: siteSigner };
    expect(await drainOutbox(outbox, registry, board, { ...VIA, now: () => now })).toEqual({ sent: 1, retry: 0, dead: 0 });
    expect(recorded).toContain("ev-now");
    expect(recorded).not.toContain("ev-before");
    // Never signed for the new pairing, and never counted as tried or dead: it is as it was queued.
    expect(await outbox.get("ev-before")).toMatchObject({ pairing: "site-before", tries: 0, sentAt: null, dead: false });
    // A store that hands over every due event, whatever its pairing, changes nothing: the sender itself leaves the others.
    const lax: typeof outbox = { ...outbox, due: (_pairing, at, limit) => outbox.due("site-before", at, limit) };
    expect(await drainOutbox(lax, registry, board, { ...VIA, now: () => now })).toEqual({ sent: 0, retry: 0, dead: 0 });
    expect(await outbox.get("ev-before")).toMatchObject({ pairing: "site-before", tries: 0, sentAt: null, dead: false });
    expect(recorded).not.toContain("ev-before");
  });
});

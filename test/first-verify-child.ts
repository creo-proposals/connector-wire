// Not a test: `first-verify.test.ts` compiles this file to JavaScript, beside a copy of the pure half, and runs it in a fresh process.
// It is a receiver that has loaded its keys and answered nothing yet. It answers requests that name a key it does not hold, then the
// first request that names the key it holds, timing each, and prints one line of JSON.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { loadWireKeys, signWire, verifyWire, wireWorkDone, type WireRequest } from "../src/wire.js";

const PAIRING = "site-test";
const PATH = "/wire/v0/ops/describe";
const BODY = '{"op":"describe","input":{},"marked":false}';
/** How many requests name a key that is not held, before the one that names the held key. The last hundred are the ones compared. */
const NOT_HELD = 300;

// A key made here, for this process only. Never a real key.
const pair = generateKeyPairSync("ed25519");
// The receiver's keys, loaded ahead of any request, as a site loads them at start.
const keys = loadWireKeys([
  { id: "op-held", pairing: PAIRING, direction: "operation", publicKey: pair.publicKey.export({ format: "jwk" }).x, from: "2000-01-01T00:00:00Z" },
]);

const now = new Date();
const time = Math.floor(now.getTime() / 1000);
const request = (keyId: string): WireRequest => ({
  direction: "operation", method: "POST", path: PATH, body: BODY,
  headers: signWire({
    direction: "operation", method: "POST", path: PATH, body: BODY, keyId, pairing: PAIRING, privateKey: pair.privateKey, time,
    nonce: randomBytes(16).toString("base64url"),
  }),
});
// Every request is made before any is timed, so only the receiver's own work is.
const notHeld = Array.from({ length: NOT_HELD }, () => request("op-not-held"));
const held = request("op-held");

const context = { pairing: PAIRING, keys, now, write: false, claimNonce: () => true };
async function timed(req: WireRequest): Promise<{ ns: number; answer: string }> {
  const start = process.hrtime.bigint();
  const r = await verifyWire(req, context);
  const ns = Number(process.hrtime.bigint() - start);
  return { ns, answer: r.ok ? "ok" : r.code };
}

const notHeldRuns: { ns: number; answer: string }[] = [];
for (const req of notHeld) notHeldRuns.push(await timed(req));
const workBefore = wireWorkDone();
const heldRun = await timed(held);
const workAfter = wireWorkDone();

const settled = notHeldRuns.slice(-100).map((r) => r.ns).sort((a, b) => a - b);
process.stdout.write(JSON.stringify({
  problems: keys.problems,
  notHeldAnswers: [...new Set(notHeldRuns.map((r) => r.answer))],
  // The median of the last hundred.
  notHeldNs: settled[Math.floor(settled.length / 2)],
  heldAnswer: heldRun.answer,
  heldNs: heldRun.ns,
  workBefore,
  workAfter,
}));

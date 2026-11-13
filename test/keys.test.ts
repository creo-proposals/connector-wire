import { describe, expect, it } from "vitest";
import { newKeyPair, newNonce, privateKeyFromSeed, publicKeyFromWire, publicKeyProblem, publicKeyToWire, seedOf, WIRE_NONCE, wirePublicKey } from "../src/index.js";

describe("key helpers", () => {
  it("round-trip a key pair through its seed and wire form", () => {
    const pair = newKeyPair();
    expect(publicKeyFromWire(pair.publicKey)).not.toBeNull();
    expect(wirePublicKey(pair.publicKey)).not.toBeNull();
    expect(publicKeyProblem(pair.publicKey)).toBeNull();
    expect(publicKeyToWire(privateKeyFromSeed(seedOf(pair.privateKey)))).toBe(pair.publicKey);
  });
  it("refuse a public key that is not 32 canonical bytes", () => {
    expect(publicKeyFromWire("AAAA")).toBeNull();
    expect(publicKeyFromWire("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=")).toBeNull();
    // Spare bits in the last character: another spelling of the same 32 bytes.
    expect(publicKeyFromWire("iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1x")).toBeNull();
    // A small-order point is never a key.
    expect(publicKeyFromWire(Buffer.alloc(32, 0).toString("base64url"))).toBeNull();
  });
  it("make one-use numbers of the right shape", () => {
    const a = newNonce();
    expect(a).toMatch(WIRE_NONCE);
    expect(newNonce()).not.toBe(a);
  });
});

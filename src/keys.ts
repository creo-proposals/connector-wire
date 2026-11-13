/**
 * Ed25519 key helpers for the wire's key forms: a public key is the raw 32 bytes in base64url without padding (the JWK `x`), and a
 * private key can be made from its 32-byte seed (RFC 8032 secret key; the JWK `d`). Pure: node:crypto only, nothing kept or logged.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { publicKeyProblem } from "./wire.js";

/** A fresh one-use number: 16 random bytes, base64url without padding. */
export const newNonce = (): string => randomBytes(16).toString("base64url");

// DER prefix of a PKCS#8 Ed25519 private key; the 32-byte seed follows it.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** An Ed25519 private key from its 32-byte seed. */
export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
}

/**
 * A public key from its wire form, or null when it may not be entered (`publicKeyProblem`: not 32 bytes in the one spelling, not a
 * point on the curve in its one encoding, or a small-order point). It does the curve check, so use it when a key is entered, never
 * while a request is answered: a receiver loads its keys ahead of time with `loadWireKeys`.
 */
export function wirePublicKey(text: string): KeyObject | null {
  if (publicKeyProblem(text) !== null) return null;
  try {
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: text }, format: "jwk" });
  } catch {
    return null;
  }
}
/** The same, under its older name. */
export const publicKeyFromWire = wirePublicKey;

/** The wire form of a key's public half (given the public or the private key). */
export function publicKeyToWire(key: KeyObject): string {
  const jwk = (key.type === "private" ? createPublicKey(key) : key).export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new Error("not an Ed25519 key");
  return jwk.x;
}

/**
 * A new key pair: the private key stays a KeyObject (store it as you store any secret; `seedOf` gives its 32-byte seed), and the public
 * half in its wire form, for the other side to enter.
 */
export function newKeyPair(): { privateKey: KeyObject; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey: publicKeyToWire(publicKey) };
}

/** The 32-byte seed of an Ed25519 private key. */
export function seedOf(privateKey: KeyObject): Buffer {
  const jwk = privateKey.export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || typeof jwk.d !== "string") throw new Error("not an Ed25519 private key");
  return Buffer.from(jwk.d, "base64url");
}

# Where `connector-wire-v0.json` comes from

`connector-wire-v0.json` is the contract's reference for its test vectors: a byte-for-byte copy of the JSON block in section 7
("Test vectors") of the written contract, the connector wire contract v0. Contract version: `v0, unstable`. It is pinned by the
hashes below, which the tests check.

**Where to read the contract:** [`CONTRACT.md`](../CONTRACT.md), at the root of this repository and of the package. It is the
contract's page, byte for byte (SHA-256 `5cdad7e13f9bdb693245b7b6e003ff6022291ea4c816181251f06b64827b9760`), and it holds this file's
bytes as its JSON block; `test/reference.test.ts` checks both.

- SHA-256 of the file: `5d64090dc3fbd9257b5b032f5c9e9f74e043336f46256a173e322f268855df71`.
- The contract pins its 69 signed vectors: the SHA-256 of the `vectors` array serialised as compact JSON (no spaces, keys in the
  order given) is `84a50405f20e24a4cb74721b941043c031b567a1e52a5e8d01b88518f4d0ab2d`.
- 69 signed vectors (14 pass, 55 are refused) and 302 field vectors (section 7b) across ten checks: `answerValue`, `event`,
  `describe`, `input`, `answer`, `operationBody`, `answerBody`, `publicKey`, `key` and `body`.
- Both hashes, both counts, each check's tally and every vector are checked by `test/vectors.test.ts`.

**TEST KEYS ONLY. Never pair with these.** The ids, kinds and values in the file are the contract's own examples, kept as written.

## The pure half of the code

`src/wire.ts` is the contract's reference for its pure half: the reviewed reference implementation, taken whole and unchanged. It
is pinned by its hash, SHA-256 `db040e298e851d28d8704d1dd3c28aec4edb839eab1f2eb88a20a2144a02c8e6`, which `test/reference.test.ts`
checks. It imports only `node:crypto`. Its words are the contract's own, kept as written.

Do not edit the JSON, `CONTRACT.md` or `src/wire.ts` by hand. When the contract publishes new vectors, copy its page, its block and
the reference again, update the hashes here and in the tests, and make every vector pass before anything else changes.

# connector-wire

The wire contract between a board and a business's own site, as a TypeScript library: both ends of one signed connection. Built from
the written contract (the connector wire contract, version v0, unstable) and its test vectors, copied byte for byte into
[`vectors/`](vectors/SOURCE.md). The pure half of the code (`src/wire.ts`: signing, checking a request, keys, typed fields, `describe`,
bodies and answers) is the contract's reviewed reference implementation, taken whole; a test holds it to its hash.

**The contract:** [`CONTRACT.md`](CONTRACT.md), in this repository and in the package. The pure half and the vectors are the
contract's reference, pinned by the hashes the tests check. Build against the page and its vectors.

**Versions track the contract:** 0.x is wire v0.x. A contract change is a new version here, with its new vectors passing first.

No runtime dependency beyond `node:crypto`. Node 20, 22 or 24. Nothing framework-specific. The Postgres stores use the `postgres`
client, an optional peer dependency, only through the `/postgres` entry. Licence: Apache-2.0.

## What is in it

| Area | Exports |
|---|---|
| Signing and checking | `signWire`, `verifyWire`, `canonical`, `bodyHash`, `nonceMemory`, `WIRE_ERRORS`, `errorBody` |
| Keys, as a receiver holds them | `loadWireKeys` (the keyring `verifyWire` takes), `wireKeyProblems`, `publicKeyProblem` |
| Bodies | `decodeWireBody`, `parseWireJson`, `checkOperationBody`, `checkAnswerBody`, `checkEvent` |
| Typed fields and `describe` | `inputFits`, `answerFits`, `fieldFits`, `answerFieldFits`, `describeProblems`, `inputProblems`, `eventDeclProblems`, `fieldDeclProblems` |
| Making keys | `newKeyPair`, `privateKeyFromSeed`, `seedOf`, `publicKeyToWire`, `publicKeyFromWire`, `wirePublicKey`, `newNonce` |
| A site's offer | `createRegistry`, `WireRefusal`, `RegistryProblems`, `isFreeText` |
| Receiving operations | `handleOperation`, `readCapped`, `headersOf`, `BodyReadTimeout`, `WIRE_STATUS` |
| Sending | `callOperation` (board), `sendEvent`, `drainOutbox` (site) |
| Stores | `NonceStore`, `AnswerStore`, `OutboxStore`, `LogStore`; `forgetExpired`; `test…` in-memory versions, **for tests only** |
| Postgres (`/postgres`) | `postgresStores`, `WIRE_SCHEMA_SQL` (also [`sql/0001_wire.sql`](sql/0001_wire.sql)) |

## A site

### Its operations

An operation is a name, whether it writes, its input and its answer in the wire's own typed fields, and the function that does it:

```ts
import { createRegistry, WireRefusal, type WireOperation } from "@creo-proposals/connector-wire";
import type { Tx } from "@creo-proposals/connector-wire/postgres";

const hide: WireOperation<Tx> = {
  name: "things.hide",
  write: true,
  // What it takes: typed fields, never a JSON Schema. The input object holds exactly these.
  input: [
    { name: "thingId", type: "id", prefix: "T-" },
    { name: "reason", type: "text", maxLength: 500, optional: true },
  ],
  // What it answers: typed fields, each with where its value came from.
  answer: [{ name: "changed", type: "yesNo", provenance: "code" }],
  async run(input, ctx) {
    // ctx.marked: the run that asked had received outside text. This operation chooses not to act for such a run.
    if (ctx.marked) throw new WireRefusal("bad_input");
    // ctx.tx: a savepoint of the transaction that will also keep this write's answer under its retry key. Do the write with it, log it
    // with it, add any outbox event with it: all of it commits with the answer, or none of it. An undo looks up the entries it undoes
    // with it too: `stores.log.byRetryKey(ctx.pairing, retryKey, ctx.tx)`.
    const rows = await ctx.tx!`UPDATE things SET hidden = true WHERE id = ${input.thingId as string} AND NOT hidden RETURNING id`;
    if (rows.length === 0) throw new WireRefusal("conflict"); // undoes anything done above; the refusal is kept as the answer
    await stores.log.append({ pairing: ctx.pairing, keyId: ctx.keyId, retryKey: ctx.retryKey!, op: "things.hide", changed: true,
      before: { hidden: false }, after: { hidden: true } }, ctx.tx);
    return { changed: true }; // exactly the declared fields, each fitting, at most 1 MiB, or the answer is `internal`
  },
};

const registry = createRegistry([hide /* , reads … */], [{ kind: "site.things.hidden", sender: "system", fields: [{ name: "count", type: "number", min: 0 }] }]);
```

**Typed fields** (contract section 6), the same for an input, an answer and an event:

| Type | Its own keys | A value |
|---|---|---|
| `number` | `min`, `max` | a finite number within them |
| `choice` | `of`: 1 to 100 ids | one of them |
| `id` | `prefix` | letters, digits and `. _ : -`, 1 to 80, starting with the prefix |
| `date`, `dateTime`, `yesNo` | none | `YYYY-MM-DD`; a UTC moment, with no fraction or exactly three digits; `true` or `false` |
| `text` | `maxLength`, required: 1 to 20,000 code points | a string of 1 to `maxLength` code points; the empty string is not a text |
| `list` | `of`, `maxItems` (1 to 100) | at most `maxItems` entries: each one scalar (`of: { type: "id" }`), or each a one-level record (`of: [fields]`, 1 to 32) |

- Any other key is refused, never ignored: no `pattern`, no JSON Schema keyword, no narrowing on a type it does not belong to.
- A named field may say `optional: true`: then its key may be absent. `null` still fits nothing, and there are no defaults.
- `text` is for an input and an answer, never an event. Input text is **data, whoever wrote it**: apply the site's own rules to it
  (no links, no markup, no control characters, as the site chooses) and never act on what the words say.
- An answer field states its `provenance` (`code`, `inside`, `outside`, `modelFromOutside`): the least trusted source any value of it
  can have. A list of records states it on each record field. A `text` is never `code`. An input or an event field states none.

**What the handler and registry hold to:**

- `describe` is generated from the registry, so it cannot drift from what the site does. A registry with any problem throws
  `RegistryProblems` when it is made: an operation name or event kind given twice or off its pattern, more than 128 operations or 128
  events, more than 64 top-level answer fields, more than 32 fields in a record, an event or an input, or any declaration the contract
  refuses. Problems name a thing by its position.
- A **body** is exactly `{"op": <the path's name>, "input": {...}, "marked": true | false}`, checked in the contract's order. Its own
  shape comes first: bytes that are not UTF-8, text that is not JSON or nests deeper than 32, a key twice, keys other than those
  three, or an `op` that is not the path's name are `bad_input`, **whatever the path names**. Then an operation the site does not
  offer is `unknown_operation`. Then a `marked` that is not a boolean or an `input` that does not fit is `bad_input`. Nothing is done.
- **`marked`** is `true` when the run that asked had received outside text. The function gets it as `ctx.marked` and may refuse a
  marked request itself. `marked: false` is not trust in the words of a text field.
- A **read** gets `ctx.tx` undefined and `ctx.signal`, aborted at its 10-second deadline. Work that takes longer declares the answer
  `[{ name: "accepted", type: "yesNo", provenance: "code" }]`, answers `{ accepted: true }` at once and reports its end by an event.
- A **write** runs once per pairing and retry key. A repeat with the same body gets the kept answer; another body is `conflict`.
- Refuse with `new WireRefusal("not_found" | "conflict" | "bad_input" | "unavailable")`. Anything else thrown is `internal`.

### Its keys

The site holds the board's operation public keys for its pairing, and **loads them ahead of any request**:

```ts
import { loadWireKeys, wireKeyProblems } from "@creo-proposals/connector-wire";

// When the owner enters a key: refuse it unless this is empty.
const problems = wireKeyProblems({ id, pairing, direction: "operation", publicKey, from });

// At start, and whenever a key is entered or changed: every record checked once and made ready to verify with.
const keys = loadWireKeys(await myStoredKeyRecords());
for (const line of keys.problems) console.warn(line); // "key 3: a key's until is after its from": by position, in fixed words
```

- A key record is exactly `{ id, pairing, direction, publicKey, from, until? }`: `from` and `until` are UTC moments
  (`YYYY-MM-DDTHH:MM:SSZ`), `until` after `from`. A record with any problem, or with any other key (a store's own column that came
  along), is never used. Two records with the same id, pairing and direction: the earlier is the key.
- A public key is 32 bytes in base64url without padding, a point on the curve, and never a small-order point.
- Loading does the costly checks, so answering a request only looks a key up. Never call `loadWireKeys` per request.
- To rotate, the owner enters the new public key under a new id and gives the old one an `until`; both work in the overlap. Load
  again. Nothing rotates over the wire in v0.
- The site's own event key: `newKeyPair()` gives the private key (keep it as any secret, for example its 32-byte `seedOf` in a secret
  variable; never log it) and the public key in wire form for the owner to enter on the board.

### Its route

```ts
import { handleOperation, headersOf, readCapped } from "@creo-proposals/connector-wire";
import { postgresStores } from "@creo-proposals/connector-wire/postgres";

const stores = postgresStores(sql); // apply WIRE_SCHEMA_SQL with the site's own migrations first

// POST /wire/v0/ops/:name, whatever the framework. Read the raw bytes before anything parses the body.
const url = new URL(request.url);
const res = await handleOperation(
  { method: request.method, path: url.pathname + url.search, headers: headersOf(request.headers), body: await readCapped(request.body),
    source: clientAddress },
  name,
  { pairing: () => myPairingOrNull(), registry, nonces: stores.nonces, answers: stores.answers, now: () => new Date(),
    allow: myLimiter, log: (line) => myLog.info(line) },
);
return new Response(res.body, { status: res.status, headers: res.headers });
```

- `myPairingOrNull()` returns `{ pairing, keys }` (this pairing's id and the keyring from `loadWireKeys`) or `null` while the site is
  not paired. **An unpaired site answers as a paired site that holds no key** (contract section 3, step 5): the limit first, then the
  same checks in the same order, so a request that reaches the key is `bad_signature` with status 401, and no answer tells a paired
  site from an unpaired one. A pairing that cannot be read (the function throws) is answered the same way; why goes to `log` only.
  Unpaired, `allow` is asked with the empty string as the pairing.
- A request that is not a `POST` is answered as the contract's checks answer it (`bad_request`, after the limit and the version
  check), so mount the route for every method where the framework allows it.
- **`allow(pairing, source)` is asked first**, before the body is hashed or a signature checked, because both cost work for anyone
  who sends a request. It is asked about every request, verified or not: limit by source as well as by pairing. Without `allow`, the
  route must limit before it calls the handler.
- A request whose key or signature does not verify gets one answer, `bad_signature` with status 401, whatever the cause. **Why** goes
  to `log` only (`no_key`, `key_retired`, `unusable_key` or `bad_signature`). Never send a log line to a caller.
- **Headers go to the check as they were sent.** `headersOf` makes the plain object the check takes from a Fetch `Headers`, a `Map`
  or raw pairs; a Node server's `req.headers` is one already. It keeps each name as given and a name sent twice as a list. Never
  join, lowercase or drop a header first: the check folds names and the method itself (A to Z only) and reads a wire header that is
  there twice (a list, two spellings, or one value holding a comma) as absent.
- `readCapped` takes a web or Node stream and throws `BodyReadTimeout` after 10 seconds.

### Its events: the outbox

Add an event in the same transaction as the thing it reports, then drain the outbox after such a write and on a schedule:

```ts
await stores.outbox.add({ id: `hidden-${ctx.retryKey}`, pairing: ctx.pairing, kind: "site.things.hidden", at: new Date().toISOString(),
  fields: { count: 1 } }, ctx.tx);

// A worker, every minute or so:
await drainOutbox(stores.outbox, registry, { eventsUrl: BOARD_EVENTS_URL, signer: { pairing, keyId: EVENT_KEY_ID, privateKey } });
```

Each event is rebuilt from the site's own declaration (one that no longer fits is marked dead), signed with the site's event key, sent
without following redirects, and marked sent, tried again later (1, 2, 4 … minutes, at most a day) or dead, by the contract's rules. An
event kind is two to four lowercase dotted parts, such as `site.things.hidden`.

An event is queued for a pairing (`pairing`, in a write `ctx.pairing`), and `drainOutbox` sends only the events queued for the pairing
it signs for. After the site is paired again, an earlier pairing's events stay in the outbox, unsent: they are never signed for the
new pairing.

### The log and clean-up

- `wire_log` is append-only: the table refuses UPDATE, DELETE and TRUNCATE, and nothing here removes a row. Keeping it, or ending
  that by a deliberate migration of the site's own, is the site owner's decision.
- `log.byRetryKey(pairing, retryKey, tx?)` gives back one write's entries, oldest first, at its own pairing only. In a write (an undo
  looking up what it undoes), pass `ctx.tx`: the lookup then runs in the write's transaction, on its connection and in its snapshot,
  and sees what that transaction appended before it commits. Without `tx` it runs on the pool and sees only committed entries.
- Run `forgetExpired({ nonces, answers, outbox }, new Date())` daily. It removes one-use numbers after 661 seconds (the contract's 601
  plus a margin), answers after 25 hours (the contract's 24 plus a margin: the app's clock and the database's differ), and sent events after 7 days (`sentKeepDays`). Unsent and dead events stay.

## A board

```ts
import { callOperation, checkEvent, loadWireKeys, verifyWire } from "@creo-proposals/connector-wire";

// Calling a site's operation. `marked` is required: true when the run that asks had received outside text. `operations` is the
// site's describe as the board holds it; the answer is read against it. A write carries its retry key, the same one on every retry.
const r = await callOperation(
  { siteBase: "https://site.example", op: "things.hide", input: { thingId: "T-1" }, marked: false, operations: held.operations, retryKey },
  { pairing, keyId, privateKey },
);
if (!r.ok && r.retry === "later") { /* try again later, same retry key */ }

// Receiving an event at its hook route: rate-limit, verify against keys loaded ahead of time, then check the raw body against the
// board's own declarations.
const siteEventKeys = loadWireKeys(storedKeyRecords); // at start and when a key changes, not per request
const v = await verifyWire({ direction: "event", method, path, headers, body }, { pairing, keys: siteEventKeys, now: new Date(), write: false, claimNonce });
const e = v.ok ? checkEvent(body, declarations) : null;
```

The sender sends only to an `https://` address, and only to the paired address's own host: `callOperation`, `sendEvent` and
`drainOutbox` throw a `TypeError`, before anything is signed, for an address of another scheme, one with credentials, a query string
or a fragment, one whose path would not fit the contract's pattern for a path (section 2: no space, no percent-escape, at most 512
characters with the operation's part), and one that would lead to another host (`https://paired.example//other.example`). A test
passes its own `fetch`. It never follows a redirect, waits at most 10 seconds and reads at most
1 MiB. Anything that is not exactly an answer (a
redirect, a body over the cap, bytes that are not UTF-8, a repeated key, data that does not fit, a code that is not one of the
contract's) is read as `internal`, which is tried again later.

## New in 0.3.1

- `log.byRetryKey` takes the write's transaction as an optional third argument, as `log.append` does:
  `byRetryKey(pairing, retryKey, tx?)`. An undo inside a write passes `ctx.tx` and needs no second connection. Calls with two
  arguments work as before; nothing on the wire changes.

## Moving from 0.2

- An operation's `input` is a list of typed fields, not a JSON Schema. The built-in JSON Schema checker is gone.
- A body carries `marked`; `callOperation` requires `marked` and `operations`.
- `verifyWire` and the handler's pairing take a keyring from `loadWireKeys`, not a list of key records.
- `signWire` takes `time` in Unix seconds, and checks nothing about what it is given.
- A key or signature that does not verify is `bad_signature` whatever the cause; the per-cause codes are gone from the wire.
- `allow` is asked before the request is verified. `text` needs `maxLength`. Retry keys start with a letter or a digit. One-use
  numbers are kept 601 seconds. `keyValidAt` and `fromBase64url` are gone.
- `verifyWire` and the handler take headers as a plain object of names to a string or a list of strings. `headersOf` no longer
  lowercases a name or joins a repeat; a wire header sent twice is absent (`bad_request`, or `bad_version` for the version).
- A malformed body is `bad_input` even for an operation the site does not offer, and a body nested deeper than 32 is refused.
- The sender refuses an address that is not `https://`, one with credentials, a query string or a fragment, one whose path does
  not fit the contract's pattern for a path, and one that would lead to a host other than its own.
- A request that is not a `POST` is `bad_request` (it was a plain 404). An unpaired site answers as a paired site that holds no key
  does (it was a plain 404 too): `plainNotFound` is gone, and a response's `body` is always a string.
- `log.byRetryKey` takes the pairing first: `byRetryKey(pairing, retryKey)`. A retry key is looked up at its own pairing only.
- An outbox event carries its `pairing`, `outbox.due` takes the pairing first (`due(pairing, now, limit)`), and `wire_outbox` has a
  `pairing` column: only the current pairing's events are sent.

## Installing

Each version is a tarball attached to its GitHub release, with a build-provenance attestation. Install it by the release URL; npm
records its integrity hash in the lockfile:

```sh
npm install https://github.com/<owner>/connector-wire/releases/download/v<version>/<tarball>.tgz
gh attestation verify <tarball>.tgz --repo <owner>/connector-wire
```

The tarball holds the build (`dist/`), the SQL, the vectors and the contract (`CONTRACT.md`); the repository holds no build output. It needs no install script, so it
installs the same with npm and with bun. CI packs it and installs it into an empty folder with both on every change.

## Tests

`npm test` runs every vector in the copied file: all 69 signed vectors (14 pass, 55 are refused; the 14 are signed again, byte for
byte), the hash the contract pins them by, and all 302 field vectors across its ten checks (`answerValue`, `event`, `describe`,
`input`, `answer`, `operationBody`, `answerBody`, `publicKey`, `key`, `body`). A vector of a check the tests do not know fails them.
The stores run one conformance suite against memory and, with
`TEST_DATABASE_URL` set, against Postgres (each run in a fresh schema, dropped after). One test starts fresh processes and times the
first request that names a held key against requests that name no held key (contract section 7). CI runs on Node 20, 22 and 24.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE).

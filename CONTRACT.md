# The generic connector's wire contract, v0 (unstable)

This page is for a business's own site or app that talks to its board. **Build against this page and its vectors, never against an implementation's source.** The reference implementation is `connector-wire.ts`; its tests hold the vectors below byte for byte. v0 is unstable: it may still change, and a change is announced here (§8 says what a change bumps).

Every pattern on this page **matches the whole string**.

## 1. Pairings and key pairs

A **pairing** is one connection between one board and one site in one place. Staging and production are two separate pairings. A pairing has an id, `^[A-Za-z0-9._-]{1,64}$` (it matches the whole string), which both sides know and which is **signed into every request**. A request made for one pairing is refused at any other.

Each pairing has two directions, each with its own key pair, and **a key pair belongs to exactly one pairing**:

| Direction | Who sends | Who signs | Who verifies |
|---|---|---|---|
| `operation` | the board, to the site | the board's **operation** private key | the site, with the board's operation public key |
| `event` | the site, to the board | the site's **event** private key | the board, with the site's event public key |

- **Algorithm:** Ed25519 (RFC 8032). A public key is the raw 32 bytes in base64url without padding (the JWK `x` value): 43 characters, in its one spelling (no padding, no spare bits in the last character, never standard base64).
- **Pairing exchanges public keys only.** Each side keeps its own private key. No secret is pasted anywhere, and a copy of either side's database cannot forge the other side's requests.
- **Check a key when it is entered, and refuse it unless all of this holds.** Its id and its pairing's id match their patterns; its direction is `operation` or `event`; `from` is a UTC moment (a `dateTime`, §6) and `until`, when there is one, a later UTC moment; and its public key holds to this: it is 32 bytes in that one spelling; it is a point on the curve in its one encoding (RFC 8032 §5.1.3: the `y` below the field's prime, an `x` exists for it, and no sign bit on `x = 0`); and it is **not one of the eight small-order points** (a point `P` with `8·P` the identity). Against a small-order key a forged signature verifies for any request, so such a key is never stored and, if one is stored anyway, never used (§3 step 5). §7b has vectors for each (`publicKey`, and `key` for the whole record).
- **Keys are checked when they are entered or loaded, never while a request is answered.** The curve check costs about a millisecond, a signature check a small fraction of that. A receiver that checked a key on its first use would answer the first request naming a held key many times slower than a request naming no key, and that difference lists the held key ids. So a receiver loads its keys ahead of time (at start, and whenever one is entered or changed): each is checked and made ready to verify with then, and answering a request only looks one up.
- **A key record with any problem is never used.** Not only a bad public key: a malformed key id or pairing id, a direction that is neither, a validity that is not a `dateTime`, an `until` not after its `from`, or a key the record does not have (a store's own column that came along, such as a revocation date) each make the whole record unusable. A receiver lists the problem when it loads its keys, by the record's position, and a request that names such a key is answered exactly as a request naming no key is (§3 step 5: one verify against the decoy, `bad_signature`).
- **A key record is read once.** What a receiver checks is what it uses: it takes a plain copy of the record's fields, checks that copy, and imports the public key from it, so a record can never show one key to the check and another to the import.
- **One key per id, pairing and direction.** Two records with the same id, pairing and direction are a problem of the **later** one: the earlier is the key, and the later is never used. **This holds even when the earlier record has a problem of its own**: then neither is used (it fails closed; a later record never takes the place of an earlier one). The same id under another pairing or the other direction is another key.
- **Key ids:** `^[A-Za-z0-9._-]{1,64}$` (it matches the whole string). A key has a validity: `from`, and `until` once it is being retired. A key is valid from `from` **itself** and until just before `until`: `from <= now < until`, so a request at the very second of `from` is inside and one at the very second of `until` is outside. A `from` or an `until` that is not a `dateTime` (§6) counts as retired: it fails closed.
- **Rotation, in v0, sends nothing on the wire.** The side rotating makes a new pair under a new key id. The owner enters the new public key on the board, and on the site's own settings for the board's key. Both keys of the direction are valid until the old key's `until`: every 90 days, with a 7-day overlap.
- **After a breach:** the owner pairs again. Recovery is never automatic.

## 2. A request

Every request is an HTTPS **`POST`** with a JSON body, at most **256 KiB**. No other method is a request: a signed `GET` is refused. **The method is compared without regard to the case of the letters A to Z**: a receiver whose HTTP library reports `post` reads it as `POST`, and `get` in any case is refused. The signed string always carries the method in capitals, `POST`, whatever case it arrived in.

- **Paths:** `^/[A-Za-z0-9._~/-]{0,511}$` (it matches the whole string): a `/`, then at most 511 of letters, digits and `. _ ~ / -`, so at most **512 characters** in all, with no query string, no fragment, no space and no percent-escape. A path that fails this in any way is refused with one code (§3 step 2).
- **Redirects** are never followed.

These headers are required. HTTP header names are not case-sensitive; this page writes them in lowercase, and a receiver reads them whatever their case (`Wire-Key`, `WIRE-KEY` and `wire-key` are one header). Case is folded for the letters A to Z only, as HTTP does: a name written with another character that some systems fold to a letter (the Kelvin sign for `K`) is a different name, and so is not a wire header. **A header whose value is empty is absent, and so is a header that is there twice**: under two spellings, as a list of more than one value, **or as one value that holds a comma**. An HTTP library may hand a header sent twice over as its values joined with `, `; no wire header's own value ever holds a comma, so a comma always means twice. A receiver never picks one of two values, and decides which headers are there before it looks at any key: a required header sent twice is missing (step 2 of §3), so a `wire-key` sent twice is `bad_request` whether or not the key is held. **`wire-retry` is not a required header, so a `wire-retry` that is there twice is simply not there**, and what follows is what follows for any request without one: never `bad_retry_key`, which is for a retry key that is present and malformed. If the sender signed with that retry value, the signed string no longer matches (the receiver signs an empty retry line) and the request is `bad_signature`. If the sender signed with no retry key, the signature verifies, and the request is a read with no retry key, which passes, or a write, which is `missing_retry_key`. The reference check takes the headers as a plain object, each name to a string or to a list of strings; an adapter makes that from whatever its HTTP library gives (a Fetch `Headers`, a `Map`).

| Header | Value |
|---|---|
| `wire-version` | `v0` |
| `wire-key` | the signing key's id |
| `wire-time` | Unix time in whole seconds, decimal, at most 12 digits |
| `wire-nonce` | a one-use number: 16 random bytes, base64url without padding (`^[A-Za-z0-9_-]{22}$` (it matches the whole string)). A receiver **compares it as a string and never decodes it**: any string of that shape is a number, and two spellings that would decode to the same bytes are two numbers |
| `wire-body` | SHA-256 of the exact body bytes, base64url without padding |
| `wire-retry` | the retry key, `^[A-Za-z0-9][A-Za-z0-9_-]{15,63}$` (it matches the whole string): 16 to 64 characters starting with a letter or a digit, so **every retry key is also an id** (§6). **Required on a write.** A read may carry one; when present it is signed and checked like any other |
| `wire-signature` | Ed25519 signature of the signed string: 64 bytes in base64url **without padding**, in its one spelling, `^[A-Za-z0-9_-]{85}[AQgw]$` (it matches the whole string) |

**The signed string** is these eleven fields joined with `\n` (LF), with no trailing newline, UTF-8:

```
wire
v0
<direction: operation | event>
POST
<path, exactly as requested>
<wire-time>
<wire-nonce>
<wire-body>
<wire-key>
<wire-retry, or the empty string when there is none>
<pairing id>
```

## 3. Checking a request (the receiver, at one pairing), in this order

**Rate-limit first.** The receiving route limits requests (per source and per pairing) **before** any of these checks: step 4 hashes up to 256 KiB and step 5 runs a signature verify for anyone who sends a request.

1. `wire-version` is `v0`. Otherwise `bad_version`: a **missing** `wire-version` (or an empty one) is `bad_version` too, not `bad_request`.
2. The method is `POST` (in any case of its letters: §2); `wire-key`, `wire-time`, `wire-nonce`, `wire-body` and `wire-signature` are **present** (an empty value, or a header there twice, is absent: §2); and the path matches its pattern (§2). Otherwise `bad_request`: one code for a missing header and for a path that fails in any way (a space, 513 characters, a query, a fragment). Their shapes are checked later: `wire-time`, `wire-retry` and `wire-nonce` each with its own code, and `wire-key` and `wire-signature` inside step 5, where a `wire-key` that has no key id's shape is simply a key that is not held (`bad_signature`).
3. `wire-time` is 1–12 digits (`bad_time`; 13 digits are `bad_time`, never read as a time), and **at most** 300 seconds from the receiver's clock either way. Exactly 300 is inside. Older is `stale`, ahead is `future`.
4. The body is at most 256 KiB (`body_too_large`), and its SHA-256 equals `wire-body` (`body_mismatch`).
5. **The key and the signature, as one check.** All of these must hold, and **any failure is the same answer: `bad_signature`, status 401**:
   - the receiver holds a key of that id **for this pairing and this direction** (an unpaired site, an unknown id, another pairing's key and a key of the other direction are all simply not held);
   - its validity holds at the receiver's clock (`from <= now < until`; a `from` or `until` that is not a `dateTime` fails);
   - its record had **no problem at all when the keys were loaded** (§1): a key whose public key is malformed, off the curve or of small order, or whose record is wrong in any other way, is never used;
   - `wire-signature` is in its one spelling (§2: no padding, no spare bits, 86 characters);
   - the signature verifies against the signed string, with **the receiver's own pairing id** as the last line.

   **The same work is done whatever the cause.** Look the key up among the keys already loaded (§1: **no key is checked or imported here**, so the first request that names a held key costs what any other does), then run **exactly one** Ed25519 verify: against the live key's public key, or, when no usable live key matches, against a fixed decoy public key. Only then combine the conditions, the signature's spelling among them, **with no early return in between**. A signature that verifies against the decoy is still refused. Without this, a held key costs a verify and an unknown one does not, and the difference in time lists the live key ids.

   Nothing about the key is checked before steps 3 and 4, so whether a request is stale, early or carries the wrong body is answered the same whatever key id it names: a stranger learns nothing about which keys exist, which direction or pairing they belong to, or when they retire.

   **The cause is for the receiver's own log only.** The check answers a refusal and a code, nothing else; which condition failed goes to a log callback outside the value a route answers from, and is never in the answer, its status or its timing. `wire-key` is a stranger's text until the signature verifies (it can hold a newline): the log gets it only when it has a key id's shape, otherwise nothing. A logger that fails, at once or later (a rejected promise), changes nothing about the answer.
6. A write without `wire-retry` is `missing_retry_key`. A `wire-retry` that is present and malformed is `bad_retry_key`, **on a read too**: a retry key present is always signed and always checked.
7. `wire-nonce` is well formed (`bad_nonce`) and not already used for this pairing and key (`replayed`). Record it, and keep used numbers **at least 601 seconds**: twice the window and a second. (A request stamped 300 seconds ahead is still inside the window 600 seconds later, to the second; a number forgotten at 600 would let it in twice.)

The one-use number is checked last, so a request that fails any other check never uses one up.

**When two things are wrong, the earlier step answers.** A request of another version with no signature is `bad_version`; one with no signature that is also stale is `bad_request`; a stale one whose body changed is `stale`; a changed body under a key that is not held is `body_mismatch`; a write with no retry key and a bad signature is `bad_signature`; a write with a missing or malformed retry key and a one-use number already used is `missing_retry_key` or `bad_retry_key`. §7 has a vector for each pair of neighbouring steps.

## 4. Errors and retrying

An error answer is a 4xx or 5xx with exactly this body: `{"error":{"code":"<code>"}}`. It carries no sentence, and nothing from the request comes back. `bad_signature` is always status **401**, whatever its cause (§3 step 5).

- **Request checks:** `bad_version`, `bad_request`, `bad_time`, `stale`, `future`, `body_too_large`, `body_mismatch`, `bad_signature`, `missing_retry_key`, `bad_retry_key`, `bad_nonce`, `replayed`
- **What it asked:** `unknown_operation`, `bad_input`, `not_found`, `conflict`, `rate_limited`, `unavailable`, `internal`, `unknown_event`, `bad_event`

**Try again later** (a fresh `wire-time` and `wire-nonce`, the same retry key or event id): `rate_limited`, `unavailable`, `internal`, and no answer at all (a timeout or a dropped connection). **Every other code is never retried** as it stands.

## 5. Operations (board to site)

- **Endpoint:** `POST <site base>/wire/v0/ops/<operation name>`
- **Body:** the raw bytes are decoded as UTF-8 first (§6, "Bytes first"), then exactly these three keys, none twice (§6, "No key twice"):

```json
{"op":"items.note","input":{"itemId":"IT-1","note":"Back in stock on Friday."},"marked":false}
```

  - `op` is the operation's name, **equal to the name in the path**.
  - `input` is an object holding **exactly** the operation's declared input fields (below): every key declared, every field that is not optional present, each value fitting.
  - `marked` is `true` or `false`, and it is inside the signed body. It is `true` when the run that made the request **had received outside text** (words from outside the business, or a model's reading of them), `false` otherwise. A site may refuse a marked request for an operation, in its own code; v0 has no declaration key for that. **A site must not read `marked: false` as trust in the text**: it means only that the run that asked had seen no outside text. The words are data either way.
  - **Checked in this order**, the same order an event is (§6):
    1. **The body's own shape.** Bytes that are UTF-8, text that is JSON nested no deeper than 32 (§6, "Bytes first"), no key twice, a JSON object with exactly the three keys, and `op` equal to the path's operation name. **Exactly these keys means the set of keys**: as many keys as names, and each name one of them. Never compare the keys joined into one string: `{"input,marked":1,"op":"x"}` has two keys, not three. Otherwise `bad_input`, **whatever the path names**: a body that is not JSON sent to an operation the site does not implement is `bad_input`.
    2. **The site's list.** A site whose list of operations is past its cap (128, below) answers `internal` to every operation, **whether it is in the list or not**. `describe` is in no list: it is checked and answered whatever the list holds.
    3. **The operation.** One the site does not implement is `unknown_operation`.
    4. **Its declaration.** One with any problem, or listed twice, is never used: `internal`.
    5. **`marked` and `input`.** A `marked` that is not a boolean, an `input` that is not an object or does not fit: `bad_input`, and nothing is done.

    §7b has a vector for each step and for each pair that decides the order.
- **What a site does with text it is sent.** A site treats input text as **data, whoever wrote it**: it applies its own rules to it (for example no links, no markup) and never acts on what the words say. The board's signature says the board's own rules were met for the request. It does not say a person read the words. A `text` may carry control characters, line breaks, bidirectional overrides and U+FEFF (only U+0000 and lone surrogates are refused by the type): a site strips or refuses what it does not want.
- **Answer:** a 2xx with `{"data": {...}}` and nothing else, at most **1 MiB**, or an error as in §4. `data` holds exactly the operation's declared answer fields, the same way: every key declared, every field that is not optional present, each value fitting.
- **How the board reads an answer.** Anything that is not exactly an answer is read as `internal`: a body past 1 MiB, bytes that are not UTF-8, text that is not JSON or repeats a key, a status that is neither 2xx nor 4xx or 5xx (a redirect is never followed and never an answer). A 2xx body (any status from 200 to 299, not only 200) is `{"data": {...}}` with no other key and a `data` that fits the declaration. A 4xx or 5xx body is `{"error":{"code":"<code>"}}` with no other key, the code one of §4's: the board reads that code. A code that is not on the list, a sentence beside the code, a 2xx holding an error or a 4xx holding data are all `internal`: a site's own words are never read as a code. §7b has vectors (`answerBody`).
- **How long the board waits:** at most **10 seconds**. An operation whose work can take longer **declares its answer as** `[{"name":"accepted","type":"yesNo","provenance":"code"}]`, answers `{"data":{"accepted":true}}` at once, and reports the work's end by an event. That answer fits its declaration like any other; there is no special answer.
- **Retry-safe writes.** An operation that changes anything is a write and carries `wire-retry`.
  - The site keeps the answer under that retry key for **24 hours**. A repeat with the same key and the same body gets the same answer and acts nothing a second time.
  - The same retry key with a **different body** is `conflict`, and nothing is done.
- **Answers are not signed in v0.** The board trusts an answer because it came over TLS from the paired host, in reply to its own signed request for that pairing.

### `describe`

Every site implements `describe`: a read whose body is `{"op":"describe","input":{},"marked":false}`. It answers as every operation does, `{"data": <the describe>}`, where the describe is:

```json
{"wire":"v0",
 "operations":[{"name":"items.get","write":false,
   "input":[{"name":"itemId","type":"id","prefix":"IT-"}],
   "answer":[{"name":"price","type":"number","min":0,"provenance":"code"},
             {"name":"tags","type":"list","of":{"type":"choice","of":["new","sale"]},"maxItems":5,"provenance":"inside"},
             {"name":"title","type":"text","maxLength":200,"provenance":"outside"},
             {"name":"note","type":"text","maxLength":2000,"provenance":"modelFromOutside","optional":true}],
   "freeText":true},
  {"name":"catalogue.items","write":false,
   "input":[{"name":"suppliers","type":"list","of":{"type":"id"},"maxItems":10,"optional":true}],
   "answer":[{"name":"items","type":"list","maxItems":50,"of":[
               {"name":"id","type":"id","prefix":"IT-","provenance":"code"},
               {"name":"title","type":"text","maxLength":200,"provenance":"outside"},
               {"name":"supplier","type":"id","provenance":"inside"},
               {"name":"price","type":"number","min":0,"provenance":"outside"}]}],
   "freeText":true},
  {"name":"items.note","write":true,
   "input":[{"name":"itemId","type":"id","prefix":"IT-"},{"name":"note","type":"text","maxLength":2000}],
   "answer":[{"name":"saved","type":"yesNo","provenance":"code"}],
   "freeText":false}],
 "events":[{"kind":"shop.feed.loaded","sender":"system","fields":[{"name":"items","type":"list","of":{"type":"id"}},{"name":"at","type":"dateTime"}]}]}
```

- **A `describe` has `wire`, `operations` and `events`, all three and nothing else, and `wire` is exactly `"v0"`** (a describe with no `wire`, or with another value, is refused). An operation has `name`, `write`, `input`, `answer` and `freeText`, all five and nothing else; an event has `kind`, `sender` and `fields`, all three and nothing else. A missing key refuses the describe as an extra one does. It lists **at most 128 operations and 128 events**, each operation name **once** and each event kind **once**; a repeat refuses it. **These caps hold where the lists are used, too**: a site whose list of operations is longer than 128 answers `internal` to every operation in it, and a board whose list of event declarations is longer than 128 answers `internal` to every event; nothing in such a list is used, the first entry included.
- **Operation names** match `^[a-z][a-zA-Z0-9_.]{0,63}$` (it matches the whole string). `describe` is the contract's own: a describe that **lists** an operation named `describe` is refused.
- **`input`** is what the operation takes, declared in **the wire's own typed fields** (§6): a list of **at most 32** field declarations, each a scalar with its type's own narrowing, a `text` with its `maxLength`, a list of one scalar, or a list of one-level records, each name once. No `provenance` (the board sends an input; what a site does with its text is above). **Never a JSON Schema**: one type system for inputs, events and answers, so a declaration says exactly what the site takes and nothing in it is open-ended. An operation that takes nothing declares `"input": []`. A site that wants a JSON Schema for its own validator may generate one from the fields; `describe` never carries one, and a JSON Schema given as `input` is refused.
- **`answer`** is a list of **at most 64** field declarations, typed, named and narrowed exactly as the others are (§6): the same name rule, each name **once**, `text` with its `maxLength`, and each with its `provenance`.
- **`provenance`** says where an answer field's value came from:
  - `code`: the site's own code worked it out;
  - `inside`: a person inside the business wrote it;
  - `outside`: a person outside wrote it;
  - `modelFromOutside`: a model wrote it from outside text.
- **Declare the least trusted provenance any value of the field can have.** If a field is sometimes the owner's words and sometimes a supplier's, it is `outside`. The owner approving exact words does **not** change provenance: a product note a model drafted from a supplier's page stays `modelFromOutside` after the owner approves it.
- A `text` field is never `code`.
- **Provenance belongs on each answer field, except:** a list of **one scalar item** states it on the list, never on the item (`of` has no `provenance` and no `name`; a list item that has either is refused). **A list of records in an answer** (§6) states **no** `provenance` of its own; a list of records that has one is refused. Instead **each of its record fields states its own `provenance`**, and it applies to that field's value **in every row**. For `catalogue.items` above, every row's `id` is `code`, its `title` and `price` are `outside`, and its `supplier` is `inside`.
- **`freeText`** must be `true` when any answer field, **or any record field of a list of records**, is `outside`, `modelFromOutside` or `text`. Such an answer is outside text: it goes to the board's reader and marks the run that receives it.
- An answer to `catalogue.items` above:

```json
{"data":{"items":[{"id":"IT-1","title":"Linen shirt","supplier":"sup-a","price":48},
                  {"id":"IT-2","title":"Straw hat","supplier":"sup-b","price":19.5}]}}
```
- The board compares `describe` with what its blueprint expects, when pairing and at each health check. A malformed `describe` is a mismatch, never a crash: **checking one never fails on what it holds** (a name that is an object, 20,000 entries where 64 are allowed), lists a bounded number of problems, and never repeats the site's text in them: a thing is named **by its position** ("operation 3", "field 2"), never by its name, because a name is the site's choice even when it is well formed.

## 6. Events (site to board), and typed fields

- **Endpoint:** `POST` to the URL the board gives at pairing (no query string).
- **Body:** exactly these four keys:

```json
{"event":"shop.feed.loaded","id":"ev-0001","at":"2098-12-31T23:59:30Z","fields":{"items":["IT-1","IT-2"],"at":"2098-12-31T23:59:00Z"}}
```

  - `event` is a kind the board declared, lowercase dotted names with the contributor first: `<contributor>.<name>` or deeper, two to four parts (`shop.feed.loaded`). **Every kind matches `^[a-z][a-z0-9_]{0,39}(\.[a-z][a-z0-9_]{0,39}){1,3}$`** (it matches the whole string): each part a lowercase letter, then up to 39 of `a-z`, `0-9` and `_`. A board holds every kind it declares to this same pattern. A declaration with any other kind is refused.
  - `id` is the site's one id for this event, `^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$` (it matches the whole string).
  - `at` is a UTC moment (a `dateTime`, below).
  - `fields` holds the event's declared fields: at most 32.
- **Success:** `{"data":{"recorded":true}}`. The same answer comes back for an event id the board already has: it is recorded once.

### The types

The same types declare an operation's input, an event's fields and an operation's answer.

- `number`: a finite number, within the declared `min` and `max` (each, if declared, a finite number, `min` at most `max`). **Numbers are IEEE 754 doubles**, read as JSON parsers read them: an integer past 2^53 is the nearest double (`9007199254740993` is read as `9007199254740992`, and fits), and a number too large for a double (an integer of 401 digits) is not finite and fits no number. Send an exact large value as an `id`.
- `choice`: one of the declared `of` list. A choice declares 1 to 100 options, each matching the id grammar (so an option is never a sentence), none twice.
- `id`: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$` (it matches the whole string), narrowed by `prefix` if declared: every value **starts with** the prefix, which is 1 to 40 characters matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$` (it matches the whole string). **There is no `pattern` in v0**: a declaration never carries a regular expression, so nothing a site declares is ever run as one (a written pattern such as `^(a+)+$` can backtrack for ever). A declaration with `pattern` is refused.
- `date`: `YYYY-MM-DD`, a real day **in the years 0001 to 9999**; `0000-01-01` and rolled-over dates such as `2099-02-30` are refused.
- `dateTime`: a UTC moment, `YYYY-MM-DDTHH:MM:SSZ` or, with milliseconds, `YYYY-MM-DDTHH:MM:SS.mmmZ`: **a fraction is exactly three digits or not there**. **A real moment** means: a real calendar day in the years 0001 to 9999 (no month 13, no 30 February), an hour from 00 to 23, a minute and a second from 00 to 59 (**no second 60**: there is no leap second, and `24:00` is not an hour), and the capital letters `T` and `Z` exactly (never an offset such as `+00:00`, never lowercase).
- `yesNo`: true or false.
- `text`: free text, **in an input and in an answer only, never in an event** (top level or in a record; never a list's item). A JSON string, never `null`, of **1 to `maxLength` Unicode code points**: **the empty string is not a text** (`maxLength` starts at 1, and leaving an optional field out is how nothing is said). `maxLength` is **required**, a whole number from 1 to 20,000: no text is unbounded, and the body's size cap bounds its bytes. The string is valid Unicode: **no lone surrogate** and **no U+0000**. Count code points, not UTF-16 units: a character outside the basic plane is one.
- `list`: an array of at most `maxItems` items (default and limit 100: a list that declares no `maxItems` takes 100 items and refuses 101; a declared `maxItems` is a whole number from 1 to 100, and any other `maxItems` is refused and lets **nothing** fit: never no limit). A list with no `of` is refused and nothing fits it. Its `of` is **either**:
  - **one scalar item declaration**, such as `{"type":"id"}`: each item fits it; never a list of lists, never text; **or**
  - **a record**: a JSON array of **1 to 32 field declarations**, such as `[{"name":"day","type":"date"},{"name":"clicks","type":"number","min":0}]`. Each item (a **row**) is a JSON object.

**Field names**, top level and in a record alike: `^[a-z][a-zA-Z0-9]{0,63}$` (it matches the whole string): a lowercase letter, then letters and digits; so never `__proto__` or any name with `_`, `-` or a space. Each name **once** among its siblings (an operation's input fields, an event's fields, an operation's answer fields, a record's fields). A name declared twice is refused.

**Optional.** Any named field (top level or in a record; in an input, an event or an answer) may declare `"optional": true`. Then **its key may be absent**, and nothing else changes: **`null` still fits nothing**, a value that is present must fit, and there are no defaults. `optional` is `true` or it is not there: `"optional": false`, or any other value, is refused (absent means required). A list's item is never optional.

**Records.** Each record field has a `name` and a `type` from the scalar types above (in an input or an answer also `text`), with the same keys and rules. A `choice` in a record is a scalar like any other. A record is **one level deep**: a record field is never of type `list`, and never itself an array. In an answer (§5) a record field states its own `provenance`. In an event or an input, a record field never has `provenance`; in an event it is never `text`.

**An object fits its fields** (a row, an operation's `input`, an answer's `data`, an event's `fields`) when **every key is the name of a declared field**, **every declared field that is not optional is present** (as the object's own key), and **every value present fits its field**. Check the keys by name, never by counting them. A row that is not an object, a missing field, an extra field or an ill-typed value refuses the **whole list**, and so the whole event (`bad_event`), input (`bad_input`) or answer. Example, an event field `days` declared as a list of the record above: `"days":[{"day":"2098-12-30","clicks":12}]`.

**Each type has one closed list of keys.** A declaration carries `type`, the keys its place allows (`name` and `optional` for a named field; `provenance` on an answer's field, §5), and only these:

| Type | Its own keys |
|---|---|
| `number` | `min`, `max` (each a finite number, `min` at most `max`) |
| `choice` | `of` (1 to 100 ids, none twice) |
| `id` | `prefix` (1 to 40 characters of an id) |
| `date`, `dateTime`, `yesNo` | none |
| `text` | `maxLength` (required; a whole number, 1 to 20,000) |
| `list` | `of` (one scalar item, or a record), `maxItems` (a whole number, 1 to 100) |

**Any other key is refused, never ignored**: a narrowing on a type it does not belong to (a `list` with `prefix`, `min` or `max`; a `text` with `of`; an `id` with `min` or `maxLength`; any scalar, list item or record field with `maxItems`), a JSON Schema keyword (`enum`, `minimum`, `pattern`), or a misspelling (`Prefix`). A list's item carries `type` and its own keys only. Every number a declaration carries is bounded as the table says.

**A declaration is checked whole, once, and then never changes.** One with any problem is never used: nothing fits it. One found sound stays exactly as it was checked (the reference implementation takes its own copy and freezes that), so a later change to it cannot take effect unchecked. **Whether a declaration has a problem and whether it is used are one decision**: a declaration is used exactly when the checks above find nothing wrong with it, so a `describe` that is well formed is one whose every operation the site answers and whose every answer the board reads. There is no size limit beyond the caps on this page: the largest declaration they allow (an operation of 32 input and 64 answer fields, each a list of 32 record fields, each a choice of 100 options) is checked and used like any other. A checker may stop reading a declaration once it holds more than that one does; by then it is past a cap, and is refused.

Free text is never an event field. **Provenance is never on an event's or an input's field** (top level or in a record): an event's trust is its sender strength, and an input is the board's. A declaration with `provenance` there is refused.

- **Bytes first.** A receiver decodes a body's raw bytes as **UTF-8** before it parses anything: bytes that are not valid UTF-8, and a byte-order mark at the start, refuse the body whole (an event with `bad_event`, an operation with `bad_input`, an answer as `internal`). **A body nests at most 32 deep**, counting every object and every list from the body's own object as the first; a body nested deeper is refused the same way. A receiver decides this **before or while it parses, without recursion**: a body of a hundred thousand `[` inside the size cap must be refused, never crash the parser. Only the decoded text is parsed, and only that same text is scanned for repeated keys: a body is never parsed by one path and checked by another.
- **No key twice (I-JSON, RFC 7493).** A body, operation, event or answer, that repeats a key in **any** object (its own keys, `input`, `fields`, or a row) is refused whole: an event with `bad_event`, an operation with `bad_input`, and the board refuses such an answer as it refuses a malformed one. Most JSON parsers keep the last of two equal keys silently, so a receiver checks for repeats itself (keys compared after unescaping, so `"c"` and `"c"` are the same key).
- **Refusals, in this order.**
  1. **The body's own shape.** Bytes that are UTF-8, JSON nested no deeper than 32, no key twice, a JSON object with exactly the four keys (as a set, as in §5) and a string `event`. Otherwise `bad_event`.
  2. **The board's list.** A board whose list of event declarations is past its cap (128, §5) answers `internal` to every event, **whether its kind is in the list or not**.
  3. **The kind.** One the board did not declare is `unknown_event`, **whatever else is wrong with the body** (a malformed `id` included).
  4. **The board's own declaration.** One with any problem (anything §5–§6 refuses, such as a record field named twice), or a kind declared twice, is never used, and the event is answered `internal` (the board's fault; the site tries again later, as §4 says).
  5. **`id` and `at`**, then **no undeclared field**, then **the declared fields**: any unknown, missing or ill-typed field refuses the whole event with `bad_event`.

  The board checks against its own declarations, never against anything the site sends.
- **Which field a refusal names.** The reference implementation gives a `field` with a `bad_event` only when a **declared** field is missing or does not fit (the last part of step 5), and it names **the first such field in the order the board declared them**, whatever order the body gives them in. A fault anywhere else names no field: the body's shape, `id`, `at`, and above all a key the board did not declare, which is the sender's text and is never given back, even when a declared field is at fault as well.
- **Sender strength.** Each declared event states how strongly its sender is verified: `verified`, `platform`, `carrier`, `typed`, or `system` for an event no person caused (a scheduled load finished). The board takes it from the declaration, never from the body.
- **Content that is not a field** (a photo, a document, a message's words) never rides on an event. The event carries its id, and the board reads it through an operation whose answer is declared `outside`.
- **Retries.** A site that gets no answer, or a retry-later code, sends again later with the same `id` and a fresh time and number.

## 7. Test vectors

**TEST KEYS ONLY. Never pair with these.** The private keys are Ed25519 keys made from the 32-byte `seeds` (RFC 8032 secret keys). `keys` holds the key records as the receiver holds them, each with its pairing. Seven of them have a problem a receiver lists when it loads them, and are never used (§1): `board-op-odd` (an `until` that is not a `dateTime`), `board-op-small` (a small-order point, with no seed), `bad id!` (a malformed id), `board-op-pair` (a malformed pairing id), `board-op-extra` (a key the record does not have), the second record under `board-op-1` (the earlier one is the key), and the second record under `board-op-extra` (whose first record has a problem: neither is used). `board-op-now` is valid from the receiver's clock exactly. Every vector's receiver is at the pairing named in the vector. `now` is the receiver's clock (2099-01-01T00:00:00Z), except where a vector gives its own `now`.

Load `keys` first (§1), then, for each vector, verify the request (its `method`, `path`, `headers` and `body`) at its `pairing` with `keys`, its `now`, its `write` flag, and the one-use numbers in `usedBefore` as already used. The answer must be `expect`: `ok`, or that error code.

There are 69 vectors.

They are fixed for v0: the SHA-256 of the `vectors` array serialised as compact JSON (no spaces, keys in the order given) is `84a50405f20e24a4cb74721b941043c031b567a1e52a5e8d01b88518f4d0ab2d`.

- **Fourteen must pass:** the method given as `post`; a read whose `wire-retry` holds a comma, signed with no retry key; and these twelve: a read; a write with its retry key; an event; an event with the new key in the rotation overlap; 299 seconds old; exactly 300 seconds ahead; exactly 300 seconds old; a read that carries a retry key; a path of 512 characters; a key whose `from` is the receiver's clock exactly; header names in another case; and a one-use number that would decode to the bytes of a used one (it is another string, so another number).
- **The other 55 must be refused.** Among them:
  - `bad_signature` for everything in §3 step 5: signed for the staging pairing and received at production, the staging pairing's own key received at production, a key used for the other direction, a key the receiver does not hold, a key id that has no key id's shape, keys before or after their validity or with an `until` that is not a `dateTime`, a stored small-order key with the signature that verifies against it for any request, **four requests signed correctly by a key whose record has a problem** (a malformed id, a malformed pairing id at a receiver of that same id, a key the record does not have, the later of two records under one id, and the later of two under an id whose earlier record has a problem), a signature with padding, and a signature spelt with spare bits;
  - a key the receiver does not hold on a request 301 seconds old, which is `stale`: the time is answered before anything about the key;
  - `bad_request` for a signed `GET` and a signed `get`, a header there twice in two spellings, a `wire-key` whose value holds a comma (once for a held key and once for a key that is not held: the same answer), and a path with a space, of 513 characters, with a query, or with a fragment; `bad_version` for a request with no `wire-version` and for a `wire-version` whose value holds a comma; `bad_time` for a time of 13 digits; a read with a malformed retry key and a retry key starting with a hyphen (`bad_retry_key`); a write whose `wire-retry` is empty (`missing_retry_key`);
  - a write whose `wire-retry` holds a comma: signed with that value it is `bad_signature`, signed with no retry key it is `missing_retry_key` (§2);
  - seven requests with two faults, one for each pair of neighbouring steps of §3, each answered by the earlier step;
  - `body_too_large` has no vector (its body would be over 256 KiB): test it yourself, below. The key whose `until` is the receiver's clock exactly is the vector "the old key after the overlap ends".

To check a signer, rebuild each passing vector's headers from its seed, pairing, path, body, time, nonce and retry key: every byte must match (Ed25519 signatures are deterministic).

The same file also holds **`fieldVectors`** (§7b). They involve no signing.

### What an implementer must test itself

The vectors check answers. These are parts of the contract that no list of answers can show; an implementation that passes every vector can still have each of them wrong.

- **One verify per request, and the decoy** (§3 step 5). Count calls to your signature check: exactly one for a request that reaches step 5, whatever the cause (no key, a retired key, an unusable key, a bad signature, a good one), and none for a request refused earlier. Then time the first request that names a held key against requests that name no key, in a fresh process: the two must not be told apart.
- **The cause never reaches the caller.** Assert that the value your check returns for a refusal holds a code and nothing else, for every cause; that the log callback is what receives the cause; and that a callback that throws, or whose promise rejects, leaves the answer unchanged.
- **One-use numbers: kept 601 seconds, per pairing and key** (§3 step 7). With a clock you control: a number used at time 0 is refused at 600 seconds and accepted again only after 601; the same number under another key, or at another pairing, is a different number and is accepted.
- **Rate limiting before any check** (§3). Send more requests than the limit with bad signatures: the ones past the limit are answered `rate_limited` and your body hash and signature check are not called for them.
- **Retry keys and `conflict`** (§5). Send a write twice with one retry key and one body: the second gets the first's answer and the work is done once. Send it again with another body: `conflict`, and nothing is done. After 24 hours the key may be forgotten.
- **The size caps.** A request body of 256 KiB and one byte is `body_too_large`, decided before the body is hashed. An answer of 1 MiB and one byte is read as `internal`, whatever it holds.
- **Header names fold ASCII case only** (§2). Send `wire-key` spelt with the Kelvin sign in place of `K`, and the method spelt with a long s: neither is read as the real one. (A vector would hide the difference: the two characters look alike.)
- **Nesting, without recursion** (§6). A body of 100,000 `[` is refused, and your process is still standing.

```json
{
 "wire": "v0",
 "note": "TEST KEYS ONLY. Never pair with these.",
 "now": 4070908800,
 "pairing": "site-prod",
 "seeds": {
  "board-op-1": "0101010101010101010101010101010101010101010101010101010101010101",
  "site-ev-1": "0202020202020202020202020202020202020202020202020202020202020202",
  "site-ev-2": "0303030303030303030303030303030303030303030303030303030303030303",
  "board-op-stg": "0404040404040404040404040404040404040404040404040404040404040404",
  "board-op-next": "0505050505050505050505050505050505050505050505050505050505050505",
  "board-op-odd": "0606060606060606060606060606060606060606060606060606060606060606",
  "board-op-badid": "0707070707070707070707070707070707070707070707070707070707070707",
  "board-op-pair": "0808080808080808080808080808080808080808080808080808080808080808",
  "board-op-extra": "0909090909090909090909090909090909090909090909090909090909090909",
  "board-op-dup": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
  "board-op-now": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
  "board-op-dup2": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
 },
 "keys": [
  {
   "id": "board-op-1",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "site-ev-1",
   "pairing": "site-prod",
   "direction": "event",
   "publicKey": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
   "from": "2098-10-01T00:00:00Z",
   "until": "2099-01-02T00:00:00Z"
  },
  {
   "id": "site-ev-2",
   "pairing": "site-prod",
   "direction": "event",
   "publicKey": "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E",
   "from": "2098-12-26T00:00:00Z"
  },
  {
   "id": "board-op-stg",
   "pairing": "site-staging",
   "direction": "operation",
   "publicKey": "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "board-op-next",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "bnoc3Smwt4_ROvTFWY_v9O8qlxZuPKby5Pv8zYBQW_E",
   "from": "2099-02-01T00:00:00Z"
  },
  {
   "id": "board-op-odd",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "iodf_x6zhFFXes1a_uQFRWVo3XyJ4JCGOgVXvHr0nxc",
   "from": "2098-12-01T00:00:00Z",
   "until": "not a date"
  },
  {
   "id": "board-op-small",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "bad id!",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "board-op-pair",
   "pairing": "site prod",
   "direction": "operation",
   "publicKey": "E5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8o",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "board-op-extra",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg",
   "from": "2098-12-01T00:00:00Z",
   "revokedAt": "2098-12-15T00:00:00Z"
  },
  {
   "id": "board-op-1",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "Q6cucUQBdi32a2jCbfvfJoKq7J8kdOykYT5CSg-6_Tw",
   "from": "2098-12-01T00:00:00Z"
  },
  {
   "id": "board-op-now",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "Zr5-Myx6RTMyvZ0Kf32wVfXF7xoGraZtmLOftoEMRzo",
   "from": "2099-01-01T00:00:00Z"
  },
  {
   "id": "board-op-extra",
   "pairing": "site-prod",
   "direction": "operation",
   "publicKey": "C1E62bSSQBXKCQLtB5BE06xdvsIwbwaUjBDajrbjny0",
   "from": "2098-12-01T00:00:00Z"
  }
 ],
 "errorBody": "{\"error\":{\"code\":\"replayed\"}}",
 "vectors": [
  {
   "name": "a read operation",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a write operation with its retry key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "retry-0001-abcdefgh",
    "wire-signature": "ukyJyD4QMqgiVSeX-ynbffY6N0C0xfrgMULZ3g7atcGGa8h8PxhaQnzo2oY4PUymbVqOf88plBF04yRV6Y3kDg"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "an event",
   "pairing": "site-prod",
   "direction": "event",
   "method": "POST",
   "path": "/hooks/site",
   "headers": {
    "wire-version": "v0",
    "wire-key": "site-ev-1",
    "wire-time": "4070908800",
    "wire-nonce": "BBBBBBBBBBBBBBBBBBBBBB",
    "wire-body": "qQ1aMhiU3TNBedphlu_NwnTViatmb3x8ExqhQnFp_Lc",
    "wire-signature": "9h7oK1k-SjVSWvvG3wIlQZjL6B05bXxOHve3mkZhgQ0f1sGUa35N2w_AnT809fd8ukcEl0U0vORwPV53QLPeCA"
   },
   "body": "{\"event\":\"site.item_sold_out\",\"id\":\"ev-0001\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"itemId\":\"IT-1\",\"left\":0}}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "an event signed with the new key during the rotation overlap",
   "pairing": "site-prod",
   "direction": "event",
   "method": "POST",
   "path": "/hooks/site",
   "headers": {
    "wire-version": "v0",
    "wire-key": "site-ev-2",
    "wire-time": "4070908800",
    "wire-nonce": "CCCCCCCCCCCCCCCCCCCCCC",
    "wire-body": "qQ1aMhiU3TNBedphlu_NwnTViatmb3x8ExqhQnFp_Lc",
    "wire-signature": "YwLY299jiclZIOHBAM6bPSNdZa2mlLta35GXVsoR_E8lobyqNzSM-NUPVyXJLR4FntNOdESMyyJofW8gO8dtAw"
   },
   "body": "{\"event\":\"site.item_sold_out\",\"id\":\"ev-0001\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"itemId\":\"IT-1\",\"left\":0}}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a request 299 seconds old",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908501",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "nApR18J24Od3gXtuHE3W4tGUqFXmlyn-aqGfKslNVJXVp2X4nD-IBgCmeYTGTGmrq84o_C-3mRv7JLC8IqTSAA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a request exactly 300 seconds ahead: the window's edge is inside",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070909100",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "zBau0AVQBwMOCH6E_ZNj4yisy7Z5bZn0AHd_lkILLMgoHGvj4hidAgdxxzkEBBwq6YRvGeXyP5MxUUwXiDlEBA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a request exactly 300 seconds old: the window's edge is inside",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908500",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "6GQfCPm3mrWccHpYBe6Y4dMJDTrz1m2AiRc4qjC-O8L-08p6PMNtqzuiLvU017hc9QFPA368ffqfCfxuxzy4Ag"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a read that carries a retry key: it is signed and well formed, and the read passes",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-retry": "retry-0001-abcdefgh",
    "wire-signature": "bkeRb_5iudbIP88EJv6IghZdNU1qVYAirhAM66KdY5Mq4ZFK-y8erT2wQ6x7KG3eCWuhJVYT3TN88qddJTezAQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a path of 512 characters: the longest a path is",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "EUPP4CitGcwE0uSNgbX43lWi5X4Yp4r54TJ9GyrLAr9QqPv9GTmoOOtel0IhoBZMoEj-vvrSNqhDcaMSY1_jCQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a key whose validity starts at the receiver's clock exactly: from is inside",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-now",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "vBI02u8s9dTgfCFSZvh1_ysj-zWvmS_ti4mft8yBkfrWwU88zbNHs0-zoUjmfs6hXE-qvWvROnT5DP3tTynzCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "header names in another case: they are read whatever their case",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "WIRE-VERSION": "v0",
    "Wire-Key": "board-op-1",
    "WIRE-TIME": "4070908800",
    "Wire-Nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "WIRE-BODY": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "Wire-Signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "the method given in lowercase: post is POST, and the signed string says POST",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "post",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a read whose wire-retry holds a comma, signed with no retry key: the header is absent, and a read needs none",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg",
    "wire-retry": "retry-0001-abcdefgh, retry-0001-abcdefgh"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "a one-use number is compared as a string: one that would decode to the bytes of a used one is another number",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAB",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "xEJfI6043QC1PohxvqraT5RkJM0kZZqgJvVnlNl-ukY3NJmNa85vJCOgT6RSZS1hpQr106nea5UFwKh7e8vPBA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [
    "AAAAAAAAAAAAAAAAAAAAAA"
   ],
   "now": 4070908800,
   "expect": "ok"
  },
  {
   "name": "replayed: the same one-use number again",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [
    "AAAAAAAAAAAAAAAAAAAAAA"
   ],
   "now": 4070908800,
   "expect": "replayed"
  },
  {
   "name": "stale: 301 seconds old",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908499",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "bK9NEaRvT6wqTSBKQd-37t_U8XvBkxbaGHVu3g0u1woOOaRoRFj39plSIrCuE03xnoS4UFzF_ZDnMarZX6jBDQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "stale"
  },
  {
   "name": "future: 301 seconds ahead",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070909101",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "um65G1Tlem6JIh6AQvTM9mAvwDDk0BLAedntfcJVCEpemzyzPLkQ0FUJ7MoZL06CFMwB87aJqHenpjOm6ifICg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "future"
  },
  {
   "name": "the body changed after signing",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-2\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "body_mismatch"
  },
  {
   "name": "the path changed after signing",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.delete",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "signed by a key that is not the one named",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "KnwgvY7NA00ZgpOqyRVneCilZbXBPlTJndUc1FckFdYSQh5wT5kwBcu0yl5h03bF-ZAJcULXwd0Ajciu5gZwBQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "an operation key used for an event",
   "pairing": "site-prod",
   "direction": "event",
   "method": "POST",
   "path": "/hooks/site",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "qQ1aMhiU3TNBedphlu_NwnTViatmb3x8ExqhQnFp_Lc",
    "wire-signature": "Xl0KZ_W5SVI6GWHcKmIM44Vw3T9FBDb9TlpGzF1YjnZkmDduBrl18RluzAkZ9HtIcBTpEosKD4OYkJzfB99OBg"
   },
   "body": "{\"event\":\"site.item_sold_out\",\"id\":\"ev-0001\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"itemId\":\"IT-1\",\"left\":0}}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "an event replayed to the board as an operation",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/hooks/site",
   "headers": {
    "wire-version": "v0",
    "wire-key": "site-ev-1",
    "wire-time": "4070908800",
    "wire-nonce": "BBBBBBBBBBBBBBBBBBBBBB",
    "wire-body": "qQ1aMhiU3TNBedphlu_NwnTViatmb3x8ExqhQnFp_Lc",
    "wire-signature": "9h7oK1k-SjVSWvvG3wIlQZjL6B05bXxOHve3mkZhgQ0f1sGUa35N2w_AnT809fd8ukcEl0U0vORwPV53QLPeCA"
   },
   "body": "{\"event\":\"site.item_sold_out\",\"id\":\"ev-0001\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"itemId\":\"IT-1\",\"left\":0}}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a key the receiver does not hold",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-9",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "the old key after the overlap ends",
   "pairing": "site-prod",
   "direction": "event",
   "method": "POST",
   "path": "/hooks/site",
   "headers": {
    "wire-version": "v0",
    "wire-key": "site-ev-1",
    "wire-time": "4070995200",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "qQ1aMhiU3TNBedphlu_NwnTViatmb3x8ExqhQnFp_Lc",
    "wire-signature": "dQJuC3AtdW_iPR-PPdjCaTicjSXGPqH40l3WrAhViuLZibYXhwGwFkqoLKOqdvSGrFfSDfXMNiki7rZd2yqcAA"
   },
   "body": "{\"event\":\"site.item_sold_out\",\"id\":\"ev-0001\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"itemId\":\"IT-1\",\"left\":0}}",
   "write": false,
   "usedBefore": [],
   "now": 4070995200,
   "expect": "bad_signature"
  },
  {
   "name": "a write with no retry key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-signature": "Y3EgCdKsmSTp2VXBjTAI0etXo4933L6uE-1t9DVJ9eTXd4PkuzCFLifImz0njsjwFMazzkQtAGrCiXTyurEIAw"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "missing_retry_key"
  },
  {
   "name": "a retry key changed after signing",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "retry-0002-abcdefgh",
    "wire-signature": "ukyJyD4QMqgiVSeX-ynbffY6N0C0xfrgMULZ3g7atcGGa8h8PxhaQnzo2oY4PUymbVqOf88plBF04yRV6Y3kDg"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "another version",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v1",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_version"
  },
  {
   "name": "no signature",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "signed for the staging pairing, received at production with the same key id",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "9HmdSYGJ04KlzkqNSjfS01c4TfztxoQMtN8LqzYCA9KnFon6_kPHCg3a3AjKuRMq0g0wvjF3AFPhe-vxdctHAA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "the staging pairing's own key, received at production",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-stg",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "Vdrivdt3XMZJEuwkxTF--LsYNXrEvyfES_OXaMYoysPIYv7rI4aJ7DPXR2l9GPBBQmDFQfp67y4lLNQbqloDCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a path with a query string",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get?as=owner",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "dXyY5KUDmyuV4KFLyuN-YxGNb54F5dBpVqvBGDiThmIXOus58eHY05TYyd4AMYRW6gMVvTpyomwipP6IfYZhAg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a key before its validity starts",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-next",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "v2Pjj3TjSNXCv7yi1qz90CqvxLvWWrCv5TiSdGBw5rQfbnpxnd1fYKnNFOXnusWdEHkLXu6W-oD_5O4oZwDHCw"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a key whose until is not a dateTime",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-odd",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "b0u4wdVkYBYahQi74wsKyQgShYIh6YDLh3aKxArSHc4Eq0HiXj7u4Cf74PeV9rOghv9nwYDARASlVO_GrhajCA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a time that is not whole seconds",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800.5",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_time"
  },
  {
   "name": "a retry key of the wrong shape",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "short",
    "wire-signature": "dTbv1gysXxxQvBwpOoz5-179huQQ8MY6xBApTksnspVrMxjcWunN5l63d34QhGdw83fp5nVVV7g6S5W5tmsSAw"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_retry_key"
  },
  {
   "name": "a one-use number that is not 16 bytes",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "short",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "AJuIIKuG5l_IE-bkaERUxQrA8eoNOIHyL55kJil8a4ZbrIW3-jtR1ww3P5zB3_L9lIQuKf1SfhS-xbqxXXOmAQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_nonce"
  },
  {
   "name": "a key the receiver does not hold, 301 seconds old: the time is answered first, as for a held key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-9",
    "wire-time": "4070908499",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "bK9NEaRvT6wqTSBKQd-37t_U8XvBkxbaGHVu3g0u1woOOaRoRFj39plSIrCuE03xnoS4UFzF_ZDnMarZX6jBDQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "stale"
  },
  {
   "name": "a stored key that is a small-order point, with a signature that verifies against it for any request: the key is never used",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-small",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a signature with base64 padding",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg=="
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a signature spelt with spare bits in its last character",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCh"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a signed GET: the method is POST only",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "GET",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "PjrKsILltf9kyZLSk7EMoVaB1gnVAiNpNrT-VgQ7Xf_R6QnY3qBIhKNdgxUztHkiFz9hivlBygAbvP7zFnlBDA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a read with a retry key of the wrong shape: a retry key present is always checked",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-retry": "short",
    "wire-signature": "pqxBY9UDmEp_mOs003bqpioR94uvYnObLBr4e5xz0u8pnD1fAzjMjps8pqyiW0R9JaDy8tRn7a873mxC4gyIDQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_retry_key"
  },
  {
   "name": "a retry key that starts with a hyphen: a retry key is also an id",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "-etry-0001-abcdefgh",
    "wire-signature": "VImGZC8IzRdQG72UZGXAkJxGOyh3tl6sqVeewGZZpEkDLYWTMSrE1WWxH-_cFY_Li-gQ4yfCVvCa478CXrzXCA"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_retry_key"
  },
  {
   "name": "a key id that has no key id's shape: answered as any key that is not held",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board op 1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a stored key whose id is malformed, named and signed correctly: a key record with a problem is never used",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "bad id!",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "nhSmv-gqlyP0LsDLI2DK2cipRd2FLBhsmhmG1XrxDS2YGk3eclyK1B-w-HTJeIau9qNpqAN584_FFPhb61GrDg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a stored key whose pairing id is malformed, at a receiver of that same id",
   "pairing": "site prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-pair",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "0KwUi-rMwWfIte5W28Tiyg4h4tQp51NE94l-AkQTQItjJ44w8X3OMusSQqKJGPZIhbsJW1F7Gii29nMgelGtBQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a stored key whose record has a key it does not have (a store's own column)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-extra",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "JoL7PW1JgLuE5aO_FhiQhsu5wtjhlQ5kEZoRrMWaKDW5GWjUgPVMaGgApv8fezpKA4nfWBP9t4-T4qQ1AHqNDg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "signed by the later of two keys entered under one id: the earlier one is the key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "CvC_-_xC6hFvbMMIAsPCmcUF65G3pTN1X-cTcnK5Su0nOhF66nCxEMvrpVR1eMgurGL6tE1s0gjdKfgB3GjmAA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a path with a space",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "ipFa_HWoezxKDcIrCnyZRrR0jglYEwMnVL5ZpUg3j89SIVe5YItUM3IrH4GM0WOfb0o_wqilnBRciSHNYUEfCw"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a path of 513 characters",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "3ZkGzB8gmu_aLFrxAMJ6qgHwC-CwQoFxwN1PLDdX8rTIPpMXoZoIuag6mh31U22i758VEz63QYcfZd9-Qy9uCw"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a path with a fragment",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get#top",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "mj2wA-NJR-C42Wc_LHUw9QIG36ERQjpMC7sBu-DLR63e8hM6R6WIs2LdSIKpHXYxPkn32Jhp3ZVQGnmswzBJBg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "no wire-version header: a missing version is a bad version",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_version"
  },
  {
   "name": "a time of 13 digits",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800000",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "QckHuNs7RhZq-JtzmaFp1Tl77o8mnhRghTUojepcVROYQ3SygxkLAqC9-asE9Kq5aSgyanbfM00DUvR5WuwLAA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_time"
  },
  {
   "name": "signed by a later record under an id whose earlier record has a problem: the later one is still not the key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-extra",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "kd7L3SyzXx9GV4h1Hg5ygu68IjKUlYnb37kC01drUYdKFZYAhvL-mOZy-2sKa6ICCzCbYNCUtzU2x9wqrZatAQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a header there twice, in two spellings: it is absent",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg",
    "Wire-Key": "board-op-1"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a wire-key sent twice and joined with a comma, as an HTTP library does: it is absent",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1, board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "the same for a key the receiver does not hold: the answer does not depend on the key",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-9, board-op-9",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a signed get, in lowercase: no method but POST is a request, in any case",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "get",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "PjrKsILltf9kyZLSk7EMoVaB1gnVAiNpNrT-VgQ7Xf_R6QnY3qBIhKNdgxUztHkiFz9hivlBygAbvP7zFnlBDA"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "a write whose wire-retry holds a comma, signed with that value: the header is absent, so the signature does not verify",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "retry-0001-abcdefgh, retry-0001-abcdefgh",
    "wire-signature": "gSkUjlW-Zc4K7h80rLcdfALOeKla2nf_NJdVC2Bb3KN0tw-kgEcQMi4wxqjWSRVBR4rAJxkPxn-OQaKvP5UeBA"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a write whose wire-retry holds a comma, signed with no retry key: the header is absent, and a write needs one",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-signature": "Y3EgCdKsmSTp2VXBjTAI0etXo4933L6uE-1t9DVJ9eTXd4PkuzCFLifImz0njsjwFMazzkQtAGrCiXTyurEIAw",
    "wire-retry": "retry-0001-abcdefgh, retry-0001-abcdefgh"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "missing_retry_key"
  },
  {
   "name": "a wire-version sent twice and joined with a comma: it is absent, and a missing version is a bad version",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0, v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_version"
  },
  {
   "name": "another version and no signature: the version is answered first (steps 1 and 2)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v1",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_version"
  },
  {
   "name": "no signature and 301 seconds old: the missing header is answered first (steps 2 and 3)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908499",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_request"
  },
  {
   "name": "301 seconds old and the body changed: the time is answered first (steps 3 and 4)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908499",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "bK9NEaRvT6wqTSBKQd-37t_U8XvBkxbaGHVu3g0u1woOOaRoRFj39plSIrCuE03xnoS4UFzF_ZDnMarZX6jBDQ"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-2\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "stale"
  },
  {
   "name": "the body changed and a key the receiver does not hold: the body is answered first (steps 4 and 5)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.get",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-9",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "7UGoX-W3H1Bpg_47NnFcKgERzULw8xFj-YH9b5vhP5k",
    "wire-signature": "o-5GplB7yvJJY5InWFAI3Z5OyGhaeCLlGeOMoUGWFsY7bPBcGHHTXpXxUWkxgKWPUTZwv-Vqxg8WfPwWz_PVCg"
   },
   "body": "{\"op\":\"items.get\",\"input\":{\"itemId\":\"IT-2\"},\"marked\":false}",
   "write": false,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "body_mismatch"
  },
  {
   "name": "a write with no retry key, signed by a key that is not the one named: the signature is answered first (steps 5 and 6)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-signature": "9xf8SR1jn2bf-zfmWd9ilR177P4-ORxLGFiTgzVI9jJ9b7C72bDxpQtFI9L8WEOoEnWhfBKhxKgFduc1D36IBw"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "bad_signature"
  },
  {
   "name": "a write with a malformed retry key and a one-use number already used: the retry key is answered first (steps 6 and 7)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-retry": "short",
    "wire-signature": "dTbv1gysXxxQvBwpOoz5-179huQQ8MY6xBApTksnspVrMxjcWunN5l63d34QhGdw83fp5nVVV7g6S5W5tmsSAw"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [
    "AAAAAAAAAAAAAAAAAAAAAA"
   ],
   "now": 4070908800,
   "expect": "bad_retry_key"
  },
  {
   "name": "a write with no retry key and a one-use number already used: the retry key is answered first (steps 6 and 7)",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-signature": "Y3EgCdKsmSTp2VXBjTAI0etXo4933L6uE-1t9DVJ9eTXd4PkuzCFLifImz0njsjwFMazzkQtAGrCiXTyurEIAw"
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [
    "AAAAAAAAAAAAAAAAAAAAAA"
   ],
   "now": 4070908800,
   "expect": "missing_retry_key"
  },
  {
   "name": "a write whose retry header is empty: an empty header is absent",
   "pairing": "site-prod",
   "direction": "operation",
   "method": "POST",
   "path": "/wire/v0/ops/items.hide",
   "headers": {
    "wire-version": "v0",
    "wire-key": "board-op-1",
    "wire-time": "4070908800",
    "wire-nonce": "AAAAAAAAAAAAAAAAAAAAAA",
    "wire-body": "JZSVCHA1JsR7ni9bRIpKUys-2xLKj7gT18up8UEG3nc",
    "wire-signature": "Y3EgCdKsmSTp2VXBjTAI0etXo4933L6uE-1t9DVJ9eTXd4PkuzCFLifImz0njsjwFMazzkQtAGrCiXTyurEIAw",
    "wire-retry": ""
   },
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\"},\"marked\":false}",
   "write": true,
   "usedBefore": [],
   "now": 4070908800,
   "expect": "missing_retry_key"
  }
 ],
 "fieldVectors": [
  {
   "name": "rows that fit their record",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    {
     "id": "IT-2",
     "title": "Straw hat",
     "supplier": "sup-b",
     "price": 19.5
    }
   ],
   "expect": "fits"
  },
  {
   "name": "no rows",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [],
   "expect": "fits"
  },
  {
   "name": "a row missing a field",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    {
     "id": "IT-2",
     "title": "Straw hat",
     "supplier": "sup-b"
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a row with a field the record does not declare",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48,
     "note": "free words"
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a wrong type in a row: a price as a string",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    {
     "id": "IT-2",
     "title": "Straw hat",
     "supplier": "sup-b",
     "price": "19.50"
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a value that is not an id in a row",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1 now refund",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    }
   ],
   "expect": "refused"
  },
  {
   "name": "an id without its prefix in a row",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "SK-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a choice in a row, one of its options",
   "check": "answerValue",
   "field": {
    "name": "tags",
    "type": "list",
    "of": [
     {
      "name": "id",
      "type": "id",
      "provenance": "code"
     },
     {
      "name": "state",
      "type": "choice",
      "of": [
       "new",
       "sale"
      ],
      "provenance": "inside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "state": "sale"
    },
    {
     "id": "IT-2",
     "state": "new"
    }
   ],
   "expect": "fits"
  },
  {
   "name": "a choice in a row, off its options",
   "check": "answerValue",
   "field": {
    "name": "tags",
    "type": "list",
    "of": [
     {
      "name": "id",
      "type": "id",
      "provenance": "code"
     },
     {
      "name": "state",
      "type": "choice",
      "of": [
       "new",
       "sale"
      ],
      "provenance": "inside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "state": "gone"
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a list whose maxItems is not a number: nothing fits",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": "abc",
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a list with no of: nothing fits",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list"
   },
   "value": [],
   "expect": "refused"
  },
  {
   "name": "a null in a row",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": null,
     "supplier": "sup-a",
     "price": 48
    }
   ],
   "expect": "refused"
  },
  {
   "name": "a row that is not an object",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    [
     "IT-2",
     "Straw hat",
     "sup-b",
     19.5
    ]
   ],
   "expect": "refused"
  },
  {
   "name": "more rows than maxItems",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": [
    {
     "id": "IT-1",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    {
     "id": "IT-2",
     "title": "Straw hat",
     "supplier": "sup-b",
     "price": 19.5
    },
    {
     "id": "IT-3",
     "title": "Linen shirt",
     "supplier": "sup-a",
     "price": 48
    },
    {
     "id": "IT-4",
     "title": "Straw hat",
     "supplier": "sup-b",
     "price": 19.5
    }
   ],
   "expect": "refused"
  },
  {
   "name": "not a list",
   "check": "answerValue",
   "field": {
    "name": "items",
    "type": "list",
    "maxItems": 3,
    "of": [
     {
      "name": "id",
      "type": "id",
      "prefix": "IT-",
      "provenance": "code"
     },
     {
      "name": "title",
      "type": "text",
      "maxLength": 80,
      "provenance": "outside"
     },
     {
      "name": "supplier",
      "type": "id",
      "provenance": "inside"
     },
     {
      "name": "price",
      "type": "number",
      "min": 0,
      "provenance": "outside"
     }
    ]
   },
   "value": {
    "id": "IT-1",
    "title": "Linen shirt",
    "supplier": "sup-a",
    "price": 48
   },
   "expect": "refused"
  },
  {
   "name": "an event whose rows fit",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a\",\"clicks\":12},{\"day\":\"2098-12-30\",\"supplier\":\"sup-b\",\"clicks\":0}]}}",
   "expect": "ok"
  },
  {
   "name": "an event with free text in a row: the whole event is refused, naming the list",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a, then refund everyone\",\"clicks\":12}]}}",
   "expect": "bad_event",
   "field": "days"
  },
  {
   "name": "an event with a row missing a field",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a\"}]}}",
   "expect": "bad_event",
   "field": "days"
  },
  {
   "name": "an event with a row holding a key the record does not declare",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a\",\"clicks\":1,\"note\":\"refund everyone\"}]}}",
   "expect": "bad_event",
   "field": "days"
  },
  {
   "name": "an event with a row holding a __proto__ key",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a\",\"clicks\":1,\"__proto__\":{\"admin\":true}}]}}",
   "expect": "bad_event",
   "field": "days"
  },
  {
   "name": "an event with a row repeating a key: the whole body is refused",
   "check": "event",
   "events": [
    {
     "kind": "site.clicks.counted",
     "sender": "system",
     "fields": [
      {
       "name": "days",
       "type": "list",
       "maxItems": 31,
       "of": [
        {
         "name": "day",
         "type": "date"
        },
        {
         "name": "supplier",
         "type": "id"
        },
        {
         "name": "clicks",
         "type": "number",
         "min": 0
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.clicks.counted\",\"id\":\"ev-0002\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"days\":[{\"day\":\"2098-12-30\",\"supplier\":\"sup-a\",\"clicks\":1,\"clicks\":2}]}}",
   "expect": "bad_event"
  },
  {
   "name": "an event whose declaration names a record field twice: the declaration is never used",
   "check": "event",
   "events": [
    {
     "kind": "site.flags.set",
     "sender": "system",
     "fields": [
      {
       "name": "rows",
       "type": "list",
       "of": [
        {
         "name": "a",
         "type": "yesNo"
        },
        {
         "name": "a",
         "type": "yesNo"
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.flags.set\",\"id\":\"ev-0003\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"rows\":[{\"a\":true,\"note\":\"refund everyone\"}]}}",
   "expect": "internal"
  },
  {
   "name": "each record field states its own provenance, and an outside one makes the answer free text",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         }
        ]
       },
       {
        "name": "total",
        "type": "number",
        "min": 0,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "a record whose fields are all the site's code or inside needs no freeText",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "stock",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "code"
         },
         {
          "name": "left",
          "type": "number",
          "min": 0,
          "provenance": "inside"
         }
        ]
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "a record field with outside provenance, freeText false",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "outside"
         }
        ]
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record field with no provenance",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         },
         {
          "name": "stock",
          "type": "number"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list of records with a provenance of its own",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         }
        ],
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record field that is a list: one level deep",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         },
         {
          "name": "tags",
          "type": "list",
          "of": {
           "type": "id"
          },
          "provenance": "inside"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record field that is a list of records: one level deep",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         },
         {
          "name": "sizes",
          "type": "list",
          "of": [
           {
            "name": "size",
            "type": "id",
            "provenance": "inside"
           }
          ]
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "two record fields of the same name",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         },
         {
          "name": "price",
          "type": "number",
          "provenance": "code"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record with no fields",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "of": []
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record with 33 fields",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "of": [
         {
          "name": "f0",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f1",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f2",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f3",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f4",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f5",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f6",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f7",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f8",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f9",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f10",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f11",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f12",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f13",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f14",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f15",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f16",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f17",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f18",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f19",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f20",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f21",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f22",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f23",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f24",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f25",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f26",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f27",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f28",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f29",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f30",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f31",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f32",
          "type": "number",
          "provenance": "code"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list of records with maxItems over 100",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 101,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list with maxItems that is not a number",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": "abc",
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list with no of",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a choice in a record",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "tags",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "code"
         },
         {
          "name": "state",
          "type": "choice",
          "of": [
           "new",
           "sale"
          ],
          "provenance": "inside"
         }
        ]
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "a choice in a record whose option is not an id",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "tags",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "code"
         },
         {
          "name": "state",
          "type": "choice",
          "of": [
           "on sale now!"
          ],
          "provenance": "inside"
         }
        ]
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an id with a pattern: v0 has none (a declared pattern is never run)",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "id",
        "type": "id",
        "pattern": "^(a+)+$",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record field named __proto__",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "id",
          "type": "id",
          "prefix": "IT-",
          "provenance": "code"
         },
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "provenance": "outside"
         },
         {
          "name": "supplier",
          "type": "id",
          "provenance": "inside"
         },
         {
          "name": "price",
          "type": "number",
          "min": 0,
          "provenance": "outside"
         },
         {
          "name": "__proto__",
          "type": "number",
          "provenance": "code"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a field name that is not a lowercase-first word",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "Total price",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "two answer fields of the same name",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "total",
        "type": "number",
        "provenance": "code"
       },
       {
        "name": "total",
        "type": "yesNo",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list item with a provenance of its own",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id",
         "provenance": "outside"
        },
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event's field carrying provenance",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.stock.left",
      "sender": "system",
      "fields": [
       {
        "name": "left",
        "type": "number",
        "provenance": "code"
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event's record field carrying provenance",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.clicks.counted",
      "sender": "system",
      "fields": [
       {
        "name": "days",
        "type": "list",
        "of": [
         {
          "name": "day",
          "type": "date",
          "provenance": "code"
         }
        ]
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a text field in an event's record",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.clicks.counted",
      "sender": "system",
      "fields": [
       {
        "name": "days",
        "type": "list",
        "of": [
         {
          "name": "note",
          "type": "text"
         }
        ]
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a list with a pattern",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id"
        },
        "pattern": "^IT-",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list with a prefix",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id"
        },
        "prefix": "IT-",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list with min",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ns",
        "type": "list",
        "of": {
         "type": "number"
        },
        "min": 0,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list with max",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ns",
        "type": "list",
        "of": {
         "type": "number"
        },
        "max": 9,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text with a pattern",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "pattern": "^[a-z]+$",
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text with a prefix",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "prefix": "IT-",
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text with min",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "min": 1,
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text with max",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "max": 80,
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text with of",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "of": [
         "a",
         "b"
        ],
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text in a record with maxItems",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "rows",
        "type": "list",
        "of": [
         {
          "name": "title",
          "type": "text",
          "maxLength": 80,
          "maxItems": 3,
          "provenance": "outside"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a number with a prefix",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "prefix": "IT-",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an id with min",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "id",
        "type": "id",
        "min": 1,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a date with max",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "day",
        "type": "date",
        "max": 9,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an id with of",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "id",
        "type": "id",
        "of": [
         "a",
         "b"
        ],
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a number with maxItems",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "maxItems": 3,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list item with maxItems",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id",
         "maxItems": 3
        },
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record field with maxItems",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "rows",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "maxItems": 3,
          "provenance": "code"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input of typed fields: an id with its prefix, a list of records with maxItems, a yes or no",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "prefix": "IT-"
       },
       {
        "name": "sizes",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "size",
          "type": "choice",
          "of": [
           "s",
           "m",
           "l"
          ]
         },
         {
          "name": "count",
          "type": "number",
          "min": 1,
          "max": 9
         }
        ]
       },
       {
        "name": "hide",
        "type": "yesNo"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an input with no fields: the operation takes {}",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an input given as a closed JSON Schema",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "itemId": {
         "type": "string"
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with an array and no items",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "ids": {
         "type": "array",
         "maxItems": 5
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with prefixItems",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "pair": {
         "type": "array",
         "prefixItems": [
          {
           "type": "string"
          },
          {}
         ],
         "maxItems": 2
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with $ref",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "item": {
         "$ref": "#/$defs/item"
        }
       },
       "$defs": {
        "item": {}
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with $dynamicRef",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "item": {
         "$dynamicRef": "#item"
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with an empty allOf",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "item": {
         "allOf": []
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input narrowing by maxLength, enum and minimum",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "note": {
         "type": "string",
         "maxLength": 40
        },
        "size": {
         "enum": [
          "s",
          "m"
         ]
        },
        "count": {
         "type": "number",
         "minimum": 1
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a JSON Schema input with pattern and patternProperties",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": {
       "type": "object",
       "properties": {
        "sku": {
         "type": "string",
         "pattern": "^(a+)+$"
        }
       },
       "patternProperties": {
        "^x-": {
         "type": "string"
        }
       },
       "additionalProperties": false
      },
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with maxLength",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "maxLength": 40
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with enum",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "size",
        "type": "id",
        "enum": [
         "s",
         "m"
        ]
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with Prefix (a misspelt key is refused, never ignored)",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "Prefix": "IT-"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with minimum",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "count",
        "type": "number",
        "minimum": 1
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with a pattern",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "pattern": "^IT-"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input text with no maxLength: no text is unbounded",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "note",
        "type": "text"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input field with provenance",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "provenance": "code"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input list with maxItems over 100",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 101
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input naming a field twice",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id"
       },
       {
        "name": "itemId",
        "type": "yesNo"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input with 33 fields",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "f0",
        "type": "yesNo"
       },
       {
        "name": "f1",
        "type": "yesNo"
       },
       {
        "name": "f2",
        "type": "yesNo"
       },
       {
        "name": "f3",
        "type": "yesNo"
       },
       {
        "name": "f4",
        "type": "yesNo"
       },
       {
        "name": "f5",
        "type": "yesNo"
       },
       {
        "name": "f6",
        "type": "yesNo"
       },
       {
        "name": "f7",
        "type": "yesNo"
       },
       {
        "name": "f8",
        "type": "yesNo"
       },
       {
        "name": "f9",
        "type": "yesNo"
       },
       {
        "name": "f10",
        "type": "yesNo"
       },
       {
        "name": "f11",
        "type": "yesNo"
       },
       {
        "name": "f12",
        "type": "yesNo"
       },
       {
        "name": "f13",
        "type": "yesNo"
       },
       {
        "name": "f14",
        "type": "yesNo"
       },
       {
        "name": "f15",
        "type": "yesNo"
       },
       {
        "name": "f16",
        "type": "yesNo"
       },
       {
        "name": "f17",
        "type": "yesNo"
       },
       {
        "name": "f18",
        "type": "yesNo"
       },
       {
        "name": "f19",
        "type": "yesNo"
       },
       {
        "name": "f20",
        "type": "yesNo"
       },
       {
        "name": "f21",
        "type": "yesNo"
       },
       {
        "name": "f22",
        "type": "yesNo"
       },
       {
        "name": "f23",
        "type": "yesNo"
       },
       {
        "name": "f24",
        "type": "yesNo"
       },
       {
        "name": "f25",
        "type": "yesNo"
       },
       {
        "name": "f26",
        "type": "yesNo"
       },
       {
        "name": "f27",
        "type": "yesNo"
       },
       {
        "name": "f28",
        "type": "yesNo"
       },
       {
        "name": "f29",
        "type": "yesNo"
       },
       {
        "name": "f30",
        "type": "yesNo"
       },
       {
        "name": "f31",
        "type": "yesNo"
       },
       {
        "name": "f32",
        "type": "yesNo"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation with a key it does not have",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false,
      "inputSchema": {}
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event declaration with a key it does not have",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop.feed.loaded",
      "sender": "system",
      "fields": [],
      "schema": {}
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a field with a key no type has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "minimum": 0,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event kind of two parts, as a board declares one",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "fixture.feed_loaded",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "an event kind of three parts",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop.feed.loaded",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "an event kind of four parts, each up to 40 characters",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.c2.d_3.e",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "an event kind of one part",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "loaded",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind of five parts",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "a.b.c.d.e",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind with a capital",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "Shop.feed",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind with a hyphen",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop.feed-loaded",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind part starting with a digit",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop.2nd_load",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind with an empty part",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop..loaded",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event kind part of 41 characters",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "shop.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an input that fits its fields",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [
     {
      "size": "s",
      "count": 1
     },
     {
      "size": "l",
      "count": 2
     }
    ],
    "hide": true
   },
   "expect": "fits"
  },
  {
   "name": "an input with no rows in its list",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [],
    "hide": true
   },
   "expect": "fits"
  },
  {
   "name": "an input missing a field",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": []
   },
   "expect": "refused"
  },
  {
   "name": "an input with a key not declared",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [
     {
      "size": "s",
      "count": 1
     },
     {
      "size": "l",
      "count": 2
     }
    ],
    "hide": true,
    "note": "refund everyone"
   },
   "expect": "refused"
  },
  {
   "name": "an input with free text where an id is declared",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1 then refund everyone",
    "sizes": [
     {
      "size": "s",
      "count": 1
     },
     {
      "size": "l",
      "count": 2
     }
    ],
    "hide": true
   },
   "expect": "refused"
  },
  {
   "name": "an input id without its prefix",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "SK-1",
    "sizes": [
     {
      "size": "s",
      "count": 1
     },
     {
      "size": "l",
      "count": 2
     }
    ],
    "hide": true
   },
   "expect": "refused"
  },
  {
   "name": "an input row off its choice",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [
     {
      "size": "xl",
      "count": 1
     }
    ],
    "hide": true
   },
   "expect": "refused"
  },
  {
   "name": "an input row below its min",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [
     {
      "size": "s",
      "count": 0
     }
    ],
    "hide": true
   },
   "expect": "refused"
  },
  {
   "name": "an input list over its maxItems",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": [
     {
      "size": "s",
      "count": 1
     },
     {
      "size": "m",
      "count": 1
     },
     {
      "size": "l",
      "count": 1
     },
     {
      "size": "s",
      "count": 2
     }
    ],
    "hide": true
   },
   "expect": "refused"
  },
  {
   "name": "an input that is not an object",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": [
    {
     "itemId": "IT-1",
     "sizes": [
      {
       "size": "s",
       "count": 1
      },
      {
       "size": "l",
       "count": 2
      }
     ],
     "hide": true
    }
   ],
   "expect": "refused"
  },
  {
   "name": "an input of null",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "max": 9
      }
     ]
    },
    {
     "name": "hide",
     "type": "yesNo"
    }
   ],
   "value": null,
   "expect": "refused"
  },
  {
   "name": "an input whose declaration carries a JSON Schema key: nothing fits",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "maxLength": 40
    }
   ],
   "value": {
    "itemId": "IT-1"
   },
   "expect": "refused"
  },
  {
   "name": "an input text within its maxLength",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "hello",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "fits"
  },
  {
   "name": "an input text of exactly maxLength code points, one of them outside the basic plane",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "abcd𠀀",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "fits"
  },
  {
   "name": "an input text one over its maxLength, counted in code points",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "abcde𠀀",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an input text given as null",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": null,
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an input text holding a lone surrogate",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "ab\ud800c",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an input text holding U+0000",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "ab\u0000c",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an input text given as a number",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": 5,
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an optional input field left out",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "sizes": []
   },
   "expect": "fits"
  },
  {
   "name": "a row's optional field left out",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "hello",
    "sizes": [
     {
      "size": "s"
     }
    ]
   },
   "expect": "fits"
  },
  {
   "name": "a row's optional field given as null",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "hello",
    "sizes": [
     {
      "size": "s",
      "count": null
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an optional field present with a value that does not fit",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "hello",
    "sizes": [
     {
      "size": "s",
      "count": 0
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a required input field left out beside an optional one",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "note": "hello",
    "sizes": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer text within its maxLength",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "maxLength": 5,
    "provenance": "outside"
   },
   "value": "hello",
   "expect": "fits"
  },
  {
   "name": "an answer text of exactly maxLength code points, one of them outside the basic plane",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "maxLength": 5,
    "provenance": "outside"
   },
   "value": "abcd𠀀",
   "expect": "fits"
  },
  {
   "name": "an answer text one over its maxLength",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "maxLength": 5,
    "provenance": "outside"
   },
   "value": "abcde𠀀",
   "expect": "refused"
  },
  {
   "name": "an answer text holding a lone surrogate",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "maxLength": 5,
    "provenance": "outside"
   },
   "value": "ab\udc00c",
   "expect": "refused"
  },
  {
   "name": "an answer text whose declaration states no maxLength: nothing fits",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "provenance": "outside"
   },
   "value": "hello",
   "expect": "refused"
  },
  {
   "name": "an answer that fits, every field present",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "title": "hello",
    "rows": [
     {
      "id": "IT-1",
      "note": "fine"
     }
    ]
   },
   "expect": "fits"
  },
  {
   "name": "an answer with its optional field left out",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "rows": []
   },
   "expect": "fits"
  },
  {
   "name": "an answer whose optional field is null",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "title": null,
    "rows": [
     {
      "id": "IT-1",
      "note": "fine"
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an answer whose row leaves out its optional field",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "title": "hello",
    "rows": [
     {
      "id": "IT-1"
     }
    ]
   },
   "expect": "fits"
  },
  {
   "name": "an answer missing a required field",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "title": "hello",
    "rows": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer with a key not declared",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "title": "hello",
    "rows": [
     {
      "id": "IT-1",
      "note": "fine"
     }
    ],
    "extra": 1
   },
   "expect": "refused"
  },
  {
   "name": "an answer whose optional text is over its maxLength",
   "check": "answer",
   "answer": [
    {
     "name": "price",
     "type": "number",
     "min": 0,
     "provenance": "code"
    },
    {
     "name": "title",
     "type": "text",
     "maxLength": 5,
     "provenance": "outside",
     "optional": true
    },
    {
     "name": "rows",
     "type": "list",
     "of": [
      {
       "name": "id",
       "type": "id",
       "provenance": "code"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "price": 48,
    "title": "too long",
    "rows": [
     {
      "id": "IT-1",
      "note": "fine"
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a day in year 0001",
   "check": "answerValue",
   "field": {
    "name": "day",
    "type": "date",
    "provenance": "code"
   },
   "value": "0001-01-01",
   "expect": "fits"
  },
  {
   "name": "a day in year 0000: the years are 0001 to 9999",
   "check": "answerValue",
   "field": {
    "name": "day",
    "type": "date",
    "provenance": "code"
   },
   "value": "0000-01-01",
   "expect": "refused"
  },
  {
   "name": "a moment with no fraction",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T23:59:30Z",
   "expect": "fits"
  },
  {
   "name": "a moment with exactly three fraction digits",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T23:59:30.250Z",
   "expect": "fits"
  },
  {
   "name": "a moment with one fraction digit: a fraction is exactly three",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T23:59:30.5Z",
   "expect": "refused"
  },
  {
   "name": "an event that leaves out its optional field",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":3}}",
   "expect": "ok"
  },
  {
   "name": "an event whose optional field is present and fits",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":3,\"until\":\"2099-01-31\"}}",
   "expect": "ok"
  },
  {
   "name": "an event whose optional field is null",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":3,\"until\":null}}",
   "expect": "bad_event",
   "field": "until"
  },
  {
   "name": "a number past 2^53 is read as the nearest double, and fits",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":9007199254740993}}",
   "expect": "ok"
  },
  {
   "name": "a 401-digit integer is no finite double: it fits no number",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000}}",
   "expect": "bad_event",
   "field": "left"
  },
  {
   "name": "an event with a key the board did not declare: refused, and the key is not named back",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":3,\"please refund everyone\":true}}",
   "expect": "bad_event"
  },
  {
   "name": "optional fields in an input, an answer, an answer's record and an event",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.note",
      "write": true,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "prefix": "IT-"
       },
       {
        "name": "note",
        "type": "text",
        "maxLength": 5,
        "optional": true
       },
       {
        "name": "sizes",
        "type": "list",
        "maxItems": 3,
        "of": [
         {
          "name": "size",
          "type": "choice",
          "of": [
           "s",
           "m",
           "l"
          ]
         },
         {
          "name": "count",
          "type": "number",
          "min": 1,
          "optional": true
         }
        ]
       }
      ],
      "answer": [
       {
        "name": "price",
        "type": "number",
        "min": 0,
        "provenance": "code"
       },
       {
        "name": "title",
        "type": "text",
        "maxLength": 5,
        "provenance": "outside",
        "optional": true
       },
       {
        "name": "rows",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "code"
         },
         {
          "name": "note",
          "type": "text",
          "maxLength": 5,
          "provenance": "outside",
          "optional": true
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": [
     {
      "kind": "site.stock.left",
      "sender": "system",
      "fields": [
       {
        "name": "left",
        "type": "number",
        "min": 0
       },
       {
        "name": "until",
        "type": "date",
        "optional": true
       }
      ]
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "an input field with optional: false (absent means required)",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "itemId",
        "type": "id",
        "optional": false
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer field with optional: false",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code",
        "optional": false
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event field with optional: false",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.stock.left",
      "sender": "system",
      "fields": [
       {
        "name": "left",
        "type": "number",
        "optional": false
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an answer's record field with optional that is not true",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "rows",
        "type": "list",
        "of": [
         {
          "name": "id",
          "type": "id",
          "provenance": "code",
          "optional": "yes"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list's item with optional",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id",
         "optional": true
        }
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input text with maxLength at the most, 20,000",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "note",
        "type": "text",
        "maxLength": 20000
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an input text with maxLength 0",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "note",
        "type": "text",
        "maxLength": 0
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input text with maxLength 20,001",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "note",
        "type": "text",
        "maxLength": 20001
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an input text with a maxLength that is not a whole number",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "note",
        "type": "text",
        "maxLength": 1.5
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a list of text in an input: a list's item is never text",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "notes",
        "type": "list",
        "of": {
         "type": "text",
         "maxLength": 5
        }
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer text with no maxLength",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer text with maxLength 20,001",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 20001,
        "provenance": "outside"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an answer's record text with no maxLength",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "rows",
        "type": "list",
        "of": [
         {
          "name": "note",
          "type": "text",
          "provenance": "outside"
         }
        ]
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event text, even with a maxLength: an event never carries text",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.stock.left",
      "sender": "system",
      "fields": [
       {
        "name": "note",
        "type": "text",
        "maxLength": 5
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an operation listed twice",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op1",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event kind declared twice",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "128 operations and 128 events: the most a describe lists",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op0",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op1",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op2",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op3",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op4",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op5",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op6",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op7",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op8",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op9",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op10",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op11",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op12",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op13",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op14",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op15",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op16",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op17",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op18",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op19",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op20",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op21",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op22",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op23",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op24",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op25",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op26",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op27",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op28",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op29",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op30",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op31",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op32",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op33",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op34",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op35",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op36",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op37",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op38",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op39",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op40",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op41",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op42",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op43",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op44",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op45",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op46",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op47",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op48",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op49",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op50",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op51",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op52",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op53",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op54",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op55",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op56",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op57",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op58",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op59",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op60",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op61",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op62",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op63",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op64",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op65",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op66",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op67",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op68",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op69",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op70",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op71",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op72",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op73",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op74",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op75",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op76",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op77",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op78",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op79",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op80",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op81",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op82",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op83",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op84",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op85",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op86",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op87",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op88",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op89",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op90",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op91",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op92",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op93",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op94",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op95",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op96",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op97",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op98",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op99",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op100",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op101",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op102",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op103",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op104",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op105",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op106",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op107",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op108",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op109",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op110",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op111",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op112",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op113",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op114",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op115",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op116",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op117",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op118",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op119",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op120",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op121",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op122",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op123",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op124",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op125",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op126",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op127",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": [
     {
      "kind": "site.e0",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e2",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e3",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e4",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e5",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e6",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e7",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e8",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e9",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e10",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e11",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e12",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e13",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e14",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e15",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e16",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e17",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e18",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e19",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e20",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e21",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e22",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e23",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e24",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e25",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e26",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e27",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e28",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e29",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e30",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e31",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e32",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e33",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e34",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e35",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e36",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e37",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e38",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e39",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e40",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e41",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e42",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e43",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e44",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e45",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e46",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e47",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e48",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e49",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e50",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e51",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e52",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e53",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e54",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e55",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e56",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e57",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e58",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e59",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e60",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e61",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e62",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e63",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e64",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e65",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e66",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e67",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e68",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e69",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e70",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e71",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e72",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e73",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e74",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e75",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e76",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e77",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e78",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e79",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e80",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e81",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e82",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e83",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e84",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e85",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e86",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e87",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e88",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e89",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e90",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e91",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e92",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e93",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e94",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e95",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e96",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e97",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e98",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e99",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e100",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e101",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e102",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e103",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e104",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e105",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e106",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e107",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e108",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e109",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e110",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e111",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e112",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e113",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e114",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e115",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e116",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e117",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e118",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e119",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e120",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e121",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e122",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e123",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e124",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e125",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e126",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e127",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "129 operations",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op0",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op1",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op2",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op3",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op4",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op5",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op6",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op7",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op8",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op9",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op10",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op11",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op12",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op13",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op14",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op15",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op16",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op17",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op18",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op19",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op20",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op21",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op22",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op23",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op24",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op25",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op26",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op27",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op28",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op29",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op30",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op31",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op32",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op33",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op34",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op35",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op36",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op37",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op38",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op39",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op40",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op41",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op42",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op43",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op44",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op45",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op46",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op47",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op48",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op49",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op50",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op51",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op52",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op53",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op54",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op55",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op56",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op57",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op58",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op59",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op60",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op61",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op62",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op63",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op64",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op65",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op66",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op67",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op68",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op69",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op70",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op71",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op72",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op73",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op74",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op75",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op76",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op77",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op78",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op79",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op80",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op81",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op82",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op83",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op84",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op85",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op86",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op87",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op88",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op89",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op90",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op91",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op92",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op93",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op94",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op95",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op96",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op97",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op98",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op99",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op100",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op101",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op102",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op103",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op104",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op105",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op106",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op107",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op108",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op109",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op110",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op111",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op112",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op113",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op114",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op115",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op116",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op117",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op118",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op119",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op120",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op121",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op122",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op123",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op124",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op125",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op126",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op127",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     },
     {
      "name": "op128",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "129 events",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e0",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e2",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e3",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e4",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e5",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e6",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e7",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e8",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e9",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e10",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e11",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e12",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e13",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e14",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e15",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e16",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e17",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e18",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e19",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e20",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e21",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e22",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e23",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e24",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e25",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e26",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e27",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e28",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e29",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e30",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e31",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e32",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e33",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e34",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e35",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e36",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e37",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e38",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e39",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e40",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e41",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e42",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e43",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e44",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e45",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e46",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e47",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e48",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e49",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e50",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e51",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e52",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e53",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e54",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e55",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e56",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e57",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e58",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e59",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e60",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e61",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e62",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e63",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e64",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e65",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e66",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e67",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e68",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e69",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e70",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e71",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e72",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e73",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e74",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e75",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e76",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e77",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e78",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e79",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e80",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e81",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e82",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e83",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e84",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e85",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e86",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e87",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e88",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e89",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e90",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e91",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e92",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e93",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e94",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e95",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e96",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e97",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e98",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e99",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e100",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e101",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e102",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e103",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e104",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e105",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e106",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e107",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e108",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e109",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e110",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e111",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e112",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e113",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e114",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e115",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e116",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e117",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e118",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e119",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e120",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e121",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e122",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e123",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e124",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e125",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e126",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e127",
      "sender": "system",
      "fields": []
     },
     {
      "kind": "site.e128",
      "sender": "system",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an answer of 64 fields: the most an answer has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "f0",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f1",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f2",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f3",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f4",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f5",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f6",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f7",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f8",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f9",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f10",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f11",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f12",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f13",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f14",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f15",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f16",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f17",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f18",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f19",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f20",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f21",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f22",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f23",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f24",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f25",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f26",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f27",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f28",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f29",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f30",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f31",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f32",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f33",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f34",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f35",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f36",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f37",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f38",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f39",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f40",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f41",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f42",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f43",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f44",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f45",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f46",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f47",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f48",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f49",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f50",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f51",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f52",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f53",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f54",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f55",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f56",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f57",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f58",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f59",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f60",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f61",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f62",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f63",
        "type": "yesNo",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an answer of 65 fields",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "f0",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f1",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f2",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f3",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f4",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f5",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f6",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f7",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f8",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f9",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f10",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f11",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f12",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f13",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f14",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f15",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f16",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f17",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f18",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f19",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f20",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f21",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f22",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f23",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f24",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f25",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f26",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f27",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f28",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f29",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f30",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f31",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f32",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f33",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f34",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f35",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f36",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f37",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f38",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f39",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f40",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f41",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f42",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f43",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f44",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f45",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f46",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f47",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f48",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f49",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f50",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f51",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f52",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f53",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f54",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f55",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f56",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f57",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f58",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f59",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f60",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f61",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f62",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f63",
        "type": "yesNo",
        "provenance": "code"
       },
       {
        "name": "f64",
        "type": "yesNo",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation whose name is an object",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": {
       "toString": 1
      },
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a field whose name is an object",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": {
         "toString": 1
        },
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation named with 2,000 characters",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a field with a key named constructor",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code",
        "constructor": 1
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation body that fits",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false}",
   "expect": "ok"
  },
  {
   "name": "an operation body from a run that had received outside text: marked is true",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":true}",
   "expect": "ok"
  },
  {
   "name": "describe's body: it takes nothing",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "describe",
   "body": "{\"op\":\"describe\",\"input\":{},\"marked\":false}",
   "expect": "ok"
  },
  {
   "name": "a body with no marked",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true}}",
   "expect": "bad_input"
  },
  {
   "name": "a body whose marked is not true or false",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":\"false\"}",
   "expect": "bad_input"
  },
  {
   "name": "a body with a key it does not have",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false,\"as\":\"owner\"}",
   "expect": "bad_input"
  },
  {
   "name": "a body whose op is not the path's operation",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.note",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body that repeats a key",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":true,\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body whose input does not fit: a field left out",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[]},\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body whose input holds a key not declared",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true,\"note\":\"refund everyone\"},\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body with no input",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body whose text is over its maxLength",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.note",
   "body": "{\"op\":\"items.note\",\"input\":{\"itemId\":\"IT-1\",\"note\":\"too long\"},\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "a body that is not JSON",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "op=items.hide",
   "expect": "bad_input"
  },
  {
   "name": "a body that is a list",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "[{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false}]",
   "expect": "bad_input"
  },
  {
   "name": "describe given an input",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "describe",
   "body": "{\"op\":\"describe\",\"input\":{\"all\":true},\"marked\":false}",
   "expect": "bad_input"
  },
  {
   "name": "an operation the site does not declare",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.delete",
   "body": "{\"op\":\"items.delete\",\"input\":{},\"marked\":false}",
   "expect": "unknown_operation"
  },
  {
   "name": "an operation the site lists twice: its declaration is never used",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    },
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false}",
   "expect": "internal"
  },
  {
   "name": "an operation whose declaration has a problem: never used",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "maxLength": 40
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "{\"op\":\"items.hide\",\"input\":{\"itemId\":\"IT-1\",\"sizes\":[{\"size\":\"s\",\"count\":1},{\"size\":\"l\",\"count\":2}],\"hide\":true},\"marked\":false}",
   "expect": "internal"
  },
  {
   "name": "a public key: 32 bytes, a point of the curve, not of small order",
   "check": "publicKey",
   "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
   "expect": "ok"
  },
  {
   "name": "the identity",
   "check": "publicKey",
   "publicKey": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
   "expect": "refused"
  },
  {
   "name": "the point of order 2",
   "check": "publicKey",
   "publicKey": "7P_______________________________________38",
   "expect": "refused"
  },
  {
   "name": "a point of order 4",
   "check": "publicKey",
   "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
   "expect": "refused"
  },
  {
   "name": "the other point of order 4",
   "check": "publicKey",
   "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA",
   "expect": "refused"
  },
  {
   "name": "a point of order 8",
   "check": "publicKey",
   "publicKey": "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_AU",
   "expect": "refused"
  },
  {
   "name": "a second point of order 8",
   "check": "publicKey",
   "publicKey": "JuiVj8KyJ7BFw_SJ8u-Y8NXfrAXTxjM5sTgCiG1T_IU",
   "expect": "refused"
  },
  {
   "name": "a third point of order 8",
   "check": "publicKey",
   "publicKey": "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o",
   "expect": "refused"
  },
  {
   "name": "a fourth point of order 8",
   "check": "publicKey",
   "publicKey": "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA_o",
   "expect": "refused"
  },
  {
   "name": "32 bytes that are no point of the curve",
   "check": "publicKey",
   "publicKey": "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
   "expect": "refused"
  },
  {
   "name": "a y that is not below the field's prime",
   "check": "publicKey",
   "publicKey": "7f_______________________________________38",
   "expect": "refused"
  },
  {
   "name": "the identity with its sign bit set: not its one encoding",
   "check": "publicKey",
   "publicKey": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIA",
   "expect": "refused"
  },
  {
   "name": "31 bytes",
   "check": "publicKey",
   "publicKey": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
   "expect": "refused"
  },
  {
   "name": "a key with base64 padding",
   "check": "publicKey",
   "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
   "expect": "refused"
  },
  {
   "name": "a key spelt with spare bits in its last character",
   "check": "publicKey",
   "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1x",
   "expect": "refused"
  },
  {
   "name": "a key in standard base64, not base64url",
   "check": "publicKey",
   "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1+",
   "expect": "refused"
  },
  {
   "name": "a key record: its id, pairing, direction, public key and validity",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z"
   },
   "expect": "ok"
  },
  {
   "name": "a key record that is being retired: until after from",
   "check": "key",
   "key": {
    "id": "site-ev-1",
    "pairing": "site-prod",
    "direction": "event",
    "publicKey": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
    "from": "2098-10-01T00:00:00Z",
    "until": "2099-01-02T00:00:00Z"
   },
   "expect": "ok"
  },
  {
   "name": "a key id with a space",
   "check": "key",
   "key": {
    "id": "board op 1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z"
   },
   "expect": "refused"
  },
  {
   "name": "a pairing id of 65 characters",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z"
   },
   "expect": "refused"
  },
  {
   "name": "a direction that is neither",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "both",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z"
   },
   "expect": "refused"
  },
  {
   "name": "a small-order public key",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "from": "2098-12-01T00:00:00Z"
   },
   "expect": "refused"
  },
  {
   "name": "a from that is a day, not a moment",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01"
   },
   "expect": "refused"
  },
  {
   "name": "no from",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
   },
   "expect": "refused"
  },
  {
   "name": "an until that is not a moment",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z",
    "until": "not a date"
   },
   "expect": "refused"
  },
  {
   "name": "an until that is not after from",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z",
    "until": "2098-12-01T00:00:00Z"
   },
   "expect": "refused"
  },
  {
   "name": "a key record with a key it does not have",
   "check": "key",
   "key": {
    "id": "board-op-1",
    "pairing": "site-prod",
    "direction": "operation",
    "publicKey": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
    "from": "2098-12-01T00:00:00Z",
    "privateKey": "AAAA"
   },
   "expect": "refused"
  },
  {
   "name": "a choice of 100 options: the most a choice has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "state",
        "type": "choice",
        "of": [
         "o0",
         "o1",
         "o2",
         "o3",
         "o4",
         "o5",
         "o6",
         "o7",
         "o8",
         "o9",
         "o10",
         "o11",
         "o12",
         "o13",
         "o14",
         "o15",
         "o16",
         "o17",
         "o18",
         "o19",
         "o20",
         "o21",
         "o22",
         "o23",
         "o24",
         "o25",
         "o26",
         "o27",
         "o28",
         "o29",
         "o30",
         "o31",
         "o32",
         "o33",
         "o34",
         "o35",
         "o36",
         "o37",
         "o38",
         "o39",
         "o40",
         "o41",
         "o42",
         "o43",
         "o44",
         "o45",
         "o46",
         "o47",
         "o48",
         "o49",
         "o50",
         "o51",
         "o52",
         "o53",
         "o54",
         "o55",
         "o56",
         "o57",
         "o58",
         "o59",
         "o60",
         "o61",
         "o62",
         "o63",
         "o64",
         "o65",
         "o66",
         "o67",
         "o68",
         "o69",
         "o70",
         "o71",
         "o72",
         "o73",
         "o74",
         "o75",
         "o76",
         "o77",
         "o78",
         "o79",
         "o80",
         "o81",
         "o82",
         "o83",
         "o84",
         "o85",
         "o86",
         "o87",
         "o88",
         "o89",
         "o90",
         "o91",
         "o92",
         "o93",
         "o94",
         "o95",
         "o96",
         "o97",
         "o98",
         "o99"
        ],
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "a choice of 101 options",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "state",
        "type": "choice",
        "of": [
         "o0",
         "o1",
         "o2",
         "o3",
         "o4",
         "o5",
         "o6",
         "o7",
         "o8",
         "o9",
         "o10",
         "o11",
         "o12",
         "o13",
         "o14",
         "o15",
         "o16",
         "o17",
         "o18",
         "o19",
         "o20",
         "o21",
         "o22",
         "o23",
         "o24",
         "o25",
         "o26",
         "o27",
         "o28",
         "o29",
         "o30",
         "o31",
         "o32",
         "o33",
         "o34",
         "o35",
         "o36",
         "o37",
         "o38",
         "o39",
         "o40",
         "o41",
         "o42",
         "o43",
         "o44",
         "o45",
         "o46",
         "o47",
         "o48",
         "o49",
         "o50",
         "o51",
         "o52",
         "o53",
         "o54",
         "o55",
         "o56",
         "o57",
         "o58",
         "o59",
         "o60",
         "o61",
         "o62",
         "o63",
         "o64",
         "o65",
         "o66",
         "o67",
         "o68",
         "o69",
         "o70",
         "o71",
         "o72",
         "o73",
         "o74",
         "o75",
         "o76",
         "o77",
         "o78",
         "o79",
         "o80",
         "o81",
         "o82",
         "o83",
         "o84",
         "o85",
         "o86",
         "o87",
         "o88",
         "o89",
         "o90",
         "o91",
         "o92",
         "o93",
         "o94",
         "o95",
         "o96",
         "o97",
         "o98",
         "o99",
         "o100"
        ],
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a record of 32 fields: the most a record has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "items",
        "type": "list",
        "of": [
         {
          "name": "f0",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f1",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f2",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f3",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f4",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f5",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f6",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f7",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f8",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f9",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f10",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f11",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f12",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f13",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f14",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f15",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f16",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f17",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f18",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f19",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f20",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f21",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f22",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f23",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f24",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f25",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f26",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f27",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f28",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f29",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f30",
          "type": "number",
          "provenance": "code"
         },
         {
          "name": "f31",
          "type": "number",
          "provenance": "code"
         }
        ]
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an input of 32 fields: the most an input has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "items.get",
      "write": false,
      "input": [
       {
        "name": "f0",
        "type": "yesNo"
       },
       {
        "name": "f1",
        "type": "yesNo"
       },
       {
        "name": "f2",
        "type": "yesNo"
       },
       {
        "name": "f3",
        "type": "yesNo"
       },
       {
        "name": "f4",
        "type": "yesNo"
       },
       {
        "name": "f5",
        "type": "yesNo"
       },
       {
        "name": "f6",
        "type": "yesNo"
       },
       {
        "name": "f7",
        "type": "yesNo"
       },
       {
        "name": "f8",
        "type": "yesNo"
       },
       {
        "name": "f9",
        "type": "yesNo"
       },
       {
        "name": "f10",
        "type": "yesNo"
       },
       {
        "name": "f11",
        "type": "yesNo"
       },
       {
        "name": "f12",
        "type": "yesNo"
       },
       {
        "name": "f13",
        "type": "yesNo"
       },
       {
        "name": "f14",
        "type": "yesNo"
       },
       {
        "name": "f15",
        "type": "yesNo"
       },
       {
        "name": "f16",
        "type": "yesNo"
       },
       {
        "name": "f17",
        "type": "yesNo"
       },
       {
        "name": "f18",
        "type": "yesNo"
       },
       {
        "name": "f19",
        "type": "yesNo"
       },
       {
        "name": "f20",
        "type": "yesNo"
       },
       {
        "name": "f21",
        "type": "yesNo"
       },
       {
        "name": "f22",
        "type": "yesNo"
       },
       {
        "name": "f23",
        "type": "yesNo"
       },
       {
        "name": "f24",
        "type": "yesNo"
       },
       {
        "name": "f25",
        "type": "yesNo"
       },
       {
        "name": "f26",
        "type": "yesNo"
       },
       {
        "name": "f27",
        "type": "yesNo"
       },
       {
        "name": "f28",
        "type": "yesNo"
       },
       {
        "name": "f29",
        "type": "yesNo"
       },
       {
        "name": "f30",
        "type": "yesNo"
       },
       {
        "name": "f31",
        "type": "yesNo"
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "provenance": "code"
       }
      ],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an event of 32 fields: the most an event has",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": [
       {
        "name": "f0",
        "type": "yesNo"
       },
       {
        "name": "f1",
        "type": "yesNo"
       },
       {
        "name": "f2",
        "type": "yesNo"
       },
       {
        "name": "f3",
        "type": "yesNo"
       },
       {
        "name": "f4",
        "type": "yesNo"
       },
       {
        "name": "f5",
        "type": "yesNo"
       },
       {
        "name": "f6",
        "type": "yesNo"
       },
       {
        "name": "f7",
        "type": "yesNo"
       },
       {
        "name": "f8",
        "type": "yesNo"
       },
       {
        "name": "f9",
        "type": "yesNo"
       },
       {
        "name": "f10",
        "type": "yesNo"
       },
       {
        "name": "f11",
        "type": "yesNo"
       },
       {
        "name": "f12",
        "type": "yesNo"
       },
       {
        "name": "f13",
        "type": "yesNo"
       },
       {
        "name": "f14",
        "type": "yesNo"
       },
       {
        "name": "f15",
        "type": "yesNo"
       },
       {
        "name": "f16",
        "type": "yesNo"
       },
       {
        "name": "f17",
        "type": "yesNo"
       },
       {
        "name": "f18",
        "type": "yesNo"
       },
       {
        "name": "f19",
        "type": "yesNo"
       },
       {
        "name": "f20",
        "type": "yesNo"
       },
       {
        "name": "f21",
        "type": "yesNo"
       },
       {
        "name": "f22",
        "type": "yesNo"
       },
       {
        "name": "f23",
        "type": "yesNo"
       },
       {
        "name": "f24",
        "type": "yesNo"
       },
       {
        "name": "f25",
        "type": "yesNo"
       },
       {
        "name": "f26",
        "type": "yesNo"
       },
       {
        "name": "f27",
        "type": "yesNo"
       },
       {
        "name": "f28",
        "type": "yesNo"
       },
       {
        "name": "f29",
        "type": "yesNo"
       },
       {
        "name": "f30",
        "type": "yesNo"
       },
       {
        "name": "f31",
        "type": "yesNo"
       }
      ]
     }
    ]
   },
   "expect": "ok"
  },
  {
   "name": "an event of 33 fields",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e1",
      "sender": "system",
      "fields": [
       {
        "name": "f0",
        "type": "yesNo"
       },
       {
        "name": "f1",
        "type": "yesNo"
       },
       {
        "name": "f2",
        "type": "yesNo"
       },
       {
        "name": "f3",
        "type": "yesNo"
       },
       {
        "name": "f4",
        "type": "yesNo"
       },
       {
        "name": "f5",
        "type": "yesNo"
       },
       {
        "name": "f6",
        "type": "yesNo"
       },
       {
        "name": "f7",
        "type": "yesNo"
       },
       {
        "name": "f8",
        "type": "yesNo"
       },
       {
        "name": "f9",
        "type": "yesNo"
       },
       {
        "name": "f10",
        "type": "yesNo"
       },
       {
        "name": "f11",
        "type": "yesNo"
       },
       {
        "name": "f12",
        "type": "yesNo"
       },
       {
        "name": "f13",
        "type": "yesNo"
       },
       {
        "name": "f14",
        "type": "yesNo"
       },
       {
        "name": "f15",
        "type": "yesNo"
       },
       {
        "name": "f16",
        "type": "yesNo"
       },
       {
        "name": "f17",
        "type": "yesNo"
       },
       {
        "name": "f18",
        "type": "yesNo"
       },
       {
        "name": "f19",
        "type": "yesNo"
       },
       {
        "name": "f20",
        "type": "yesNo"
       },
       {
        "name": "f21",
        "type": "yesNo"
       },
       {
        "name": "f22",
        "type": "yesNo"
       },
       {
        "name": "f23",
        "type": "yesNo"
       },
       {
        "name": "f24",
        "type": "yesNo"
       },
       {
        "name": "f25",
        "type": "yesNo"
       },
       {
        "name": "f26",
        "type": "yesNo"
       },
       {
        "name": "f27",
        "type": "yesNo"
       },
       {
        "name": "f28",
        "type": "yesNo"
       },
       {
        "name": "f29",
        "type": "yesNo"
       },
       {
        "name": "f30",
        "type": "yesNo"
       },
       {
        "name": "f31",
        "type": "yesNo"
       },
       {
        "name": "f32",
        "type": "yesNo"
       }
      ]
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a list of 100 items at the most, declared",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "ids",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 100,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an operation in a list of 128: the most a describe lists",
   "check": "operationBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "op1",
   "body": "{\"op\":\"op1\",\"input\":{},\"marked\":false}",
   "expect": "ok"
  },
  {
   "name": "an operation in a list of 129: none of the list is used",
   "check": "operationBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op128",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "op1",
   "body": "{\"op\":\"op1\",\"input\":{},\"marked\":false}",
   "expect": "internal"
  },
  {
   "name": "an answer for an operation in a list of 129: none of the list is used",
   "check": "answerBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op128",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "op1",
   "status": 200,
   "body": "{\"data\":{}}",
   "expect": "internal"
  },
  {
   "name": "an event of a kind in a list of 128: the most a describe lists",
   "check": "event",
   "events": [
    {
     "kind": "site.e0",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e1",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e2",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e3",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e4",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e5",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e6",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e7",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e8",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e9",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e10",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e11",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e12",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e13",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e14",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e15",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e16",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e17",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e18",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e19",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e20",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e21",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e22",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e23",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e24",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e25",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e26",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e27",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e28",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e29",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e30",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e31",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e32",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e33",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e34",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e35",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e36",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e37",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e38",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e39",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e40",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e41",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e42",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e43",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e44",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e45",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e46",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e47",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e48",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e49",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e50",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e51",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e52",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e53",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e54",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e55",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e56",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e57",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e58",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e59",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e60",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e61",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e62",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e63",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e64",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e65",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e66",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e67",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e68",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e69",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e70",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e71",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e72",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e73",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e74",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e75",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e76",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e77",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e78",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e79",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e80",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e81",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e82",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e83",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e84",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e85",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e86",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e87",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e88",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e89",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e90",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e91",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e92",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e93",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e94",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e95",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e96",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e97",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e98",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e99",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e100",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e101",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e102",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e103",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e104",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e105",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e106",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e107",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e108",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e109",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e110",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e111",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e112",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e113",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e114",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e115",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e116",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e117",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e118",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e119",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e120",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e121",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e122",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e123",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e124",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e125",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e126",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e127",
     "sender": "system",
     "fields": []
    }
   ],
   "body": "{\"event\":\"site.e1\",\"id\":\"ev-0005\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{}}",
   "expect": "ok"
  },
  {
   "name": "an event of a kind in a list of 129: none of the list is used",
   "check": "event",
   "events": [
    {
     "kind": "site.e0",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e1",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e2",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e3",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e4",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e5",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e6",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e7",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e8",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e9",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e10",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e11",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e12",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e13",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e14",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e15",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e16",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e17",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e18",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e19",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e20",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e21",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e22",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e23",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e24",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e25",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e26",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e27",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e28",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e29",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e30",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e31",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e32",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e33",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e34",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e35",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e36",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e37",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e38",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e39",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e40",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e41",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e42",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e43",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e44",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e45",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e46",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e47",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e48",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e49",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e50",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e51",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e52",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e53",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e54",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e55",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e56",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e57",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e58",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e59",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e60",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e61",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e62",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e63",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e64",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e65",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e66",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e67",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e68",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e69",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e70",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e71",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e72",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e73",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e74",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e75",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e76",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e77",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e78",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e79",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e80",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e81",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e82",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e83",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e84",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e85",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e86",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e87",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e88",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e89",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e90",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e91",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e92",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e93",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e94",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e95",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e96",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e97",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e98",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e99",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e100",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e101",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e102",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e103",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e104",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e105",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e106",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e107",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e108",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e109",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e110",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e111",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e112",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e113",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e114",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e115",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e116",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e117",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e118",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e119",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e120",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e121",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e122",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e123",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e124",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e125",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e126",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e127",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e128",
     "sender": "system",
     "fields": []
    }
   ],
   "body": "{\"event\":\"site.e1\",\"id\":\"ev-0005\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{}}",
   "expect": "internal"
  },
  {
   "name": "an operation that is not in a list of 129: the list is answered before the operation",
   "check": "operationBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op128",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.delete",
   "body": "{\"op\":\"items.delete\",\"input\":{},\"marked\":false}",
   "expect": "internal"
  },
  {
   "name": "a body that is not JSON, at a site whose list is 129: the body is answered first",
   "check": "operationBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op128",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "op1",
   "body": "op=op1",
   "expect": "bad_input"
  },
  {
   "name": "describe at a site whose list is 129: describe is in no list",
   "check": "operationBody",
   "operations": [
    {
     "name": "op0",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op1",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op2",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op3",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op4",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op5",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op6",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op7",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op8",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op9",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op10",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op11",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op12",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op13",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op14",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op15",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op16",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op17",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op18",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op19",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op20",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op21",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op22",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op23",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op24",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op25",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op26",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op27",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op28",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op29",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op30",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op31",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op32",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op33",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op34",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op35",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op36",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op37",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op38",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op39",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op40",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op41",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op42",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op43",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op44",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op45",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op46",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op47",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op48",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op49",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op50",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op51",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op52",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op53",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op54",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op55",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op56",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op57",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op58",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op59",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op60",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op61",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op62",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op63",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op64",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op65",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op66",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op67",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op68",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op69",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op70",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op71",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op72",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op73",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op74",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op75",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op76",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op77",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op78",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op79",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op80",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op81",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op82",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op83",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op84",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op85",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op86",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op87",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op88",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op89",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op90",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op91",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op92",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op93",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op94",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op95",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op96",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op97",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op98",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op99",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op100",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op101",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op102",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op103",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op104",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op105",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op106",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op107",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op108",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op109",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op110",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op111",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op112",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op113",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op114",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op115",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op116",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op117",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op118",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op119",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op120",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op121",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op122",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op123",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op124",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op125",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op126",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op127",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    },
    {
     "name": "op128",
     "write": false,
     "input": [],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "describe",
   "body": "{\"op\":\"describe\",\"input\":{},\"marked\":false}",
   "expect": "ok"
  },
  {
   "name": "an event of a kind that is not in a list of 129: the list is answered before the kind",
   "check": "event",
   "events": [
    {
     "kind": "site.e0",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e1",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e2",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e3",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e4",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e5",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e6",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e7",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e8",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e9",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e10",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e11",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e12",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e13",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e14",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e15",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e16",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e17",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e18",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e19",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e20",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e21",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e22",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e23",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e24",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e25",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e26",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e27",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e28",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e29",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e30",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e31",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e32",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e33",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e34",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e35",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e36",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e37",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e38",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e39",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e40",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e41",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e42",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e43",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e44",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e45",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e46",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e47",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e48",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e49",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e50",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e51",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e52",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e53",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e54",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e55",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e56",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e57",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e58",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e59",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e60",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e61",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e62",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e63",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e64",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e65",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e66",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e67",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e68",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e69",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e70",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e71",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e72",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e73",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e74",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e75",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e76",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e77",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e78",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e79",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e80",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e81",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e82",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e83",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e84",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e85",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e86",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e87",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e88",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e89",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e90",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e91",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e92",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e93",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e94",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e95",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e96",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e97",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e98",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e99",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e100",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e101",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e102",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e103",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e104",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e105",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e106",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e107",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e108",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e109",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e110",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e111",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e112",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e113",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e114",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e115",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e116",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e117",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e118",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e119",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e120",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e121",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e122",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e123",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e124",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e125",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e126",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e127",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e128",
     "sender": "system",
     "fields": []
    }
   ],
   "body": "{\"event\":\"site.other\",\"id\":\"ev-0005\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{}}",
   "expect": "internal"
  },
  {
   "name": "an event body that is not JSON, at a board whose list is 129: the body is answered first",
   "check": "event",
   "events": [
    {
     "kind": "site.e0",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e1",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e2",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e3",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e4",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e5",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e6",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e7",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e8",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e9",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e10",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e11",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e12",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e13",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e14",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e15",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e16",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e17",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e18",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e19",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e20",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e21",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e22",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e23",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e24",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e25",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e26",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e27",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e28",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e29",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e30",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e31",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e32",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e33",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e34",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e35",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e36",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e37",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e38",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e39",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e40",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e41",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e42",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e43",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e44",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e45",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e46",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e47",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e48",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e49",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e50",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e51",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e52",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e53",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e54",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e55",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e56",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e57",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e58",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e59",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e60",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e61",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e62",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e63",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e64",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e65",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e66",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e67",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e68",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e69",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e70",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e71",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e72",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e73",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e74",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e75",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e76",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e77",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e78",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e79",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e80",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e81",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e82",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e83",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e84",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e85",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e86",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e87",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e88",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e89",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e90",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e91",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e92",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e93",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e94",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e95",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e96",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e97",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e98",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e99",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e100",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e101",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e102",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e103",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e104",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e105",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e106",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e107",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e108",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e109",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e110",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e111",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e112",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e113",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e114",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e115",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e116",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e117",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e118",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e119",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e120",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e121",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e122",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e123",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e124",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e125",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e126",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e127",
     "sender": "system",
     "fields": []
    },
    {
     "kind": "site.e128",
     "sender": "system",
     "fields": []
    }
   ],
   "body": "event=site.e1",
   "expect": "bad_event"
  },
  {
   "name": "a body of two keys, one of them named with a comma: not the three keys, whatever the path names",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.delete",
   "body": "{\"input,marked\":1,\"op\":\"items.delete\"}",
   "expect": "bad_input"
  },
  {
   "name": "an event body of three keys, one of them named with a comma: not the four keys, whatever its kind",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"at\":\"2098-12-31T23:59:30Z\",\"event\":\"site.other\",\"fields,id\":1}",
   "expect": "bad_event"
  },
  {
   "name": "an answer whose one key is named with a comma",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data,x\":{\"price\":48}}",
   "expect": "internal"
  },
  {
   "name": "two fields at fault, given in the other order: the first declared is named",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"until\":\"not a day\",\"left\":\"three\"}}",
   "expect": "bad_event",
   "field": "left"
  },
  {
   "name": "a required field left out and an optional one at fault: the first declared is named",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"until\":\"not a day\"}}",
   "expect": "bad_event",
   "field": "left"
  },
  {
   "name": "only the second declared field at fault: it is named",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":3,\"until\":\"not a day\"}}",
   "expect": "bad_event",
   "field": "until"
  },
  {
   "name": "an undeclared key and a declared field at fault: no field is named",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.stock.left\",\"id\":\"ev-0004\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"left\":\"three\",\"stock\":1}}",
   "expect": "bad_event"
  },
  {
   "name": "an operation named describe: the name is the contract's own",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "describe",
      "write": false,
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a describe with no wire",
   "check": "describe",
   "describe": {
    "operations": [],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a describe of another wire version",
   "check": "describe",
   "describe": {
    "wire": "v1",
    "operations": [],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a text whose provenance is code: text is never the site's code's own",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "title",
        "type": "text",
        "maxLength": 80,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event whose sender is not one of the strengths",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e1",
      "sender": "anyone",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "a number whose min is above its max",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "min": 2,
        "max": 1,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a number whose min equals its max",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "n",
        "type": "number",
        "min": 2,
        "max": 2,
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an id prefix of 40 characters: the longest a prefix is",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "id",
        "type": "id",
        "prefix": "pppppppppppppppppppppppppppppppppppppppp",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "ok"
  },
  {
   "name": "an id prefix of 41 characters",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "id",
        "type": "id",
        "prefix": "ppppppppppppppppppppppppppppppppppppppppp",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a choice with no of",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "catalogue.items",
      "write": false,
      "input": [
       {
        "name": "suppliers",
        "type": "list",
        "of": {
         "type": "id"
        },
        "maxItems": 10
       }
      ],
      "answer": [
       {
        "name": "state",
        "type": "choice",
        "provenance": "code"
       }
      ],
      "freeText": true
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation whose write is not true or false",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "write": "no",
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a moment at second 60: there is no leap second",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T23:59:60Z",
   "expect": "refused"
  },
  {
   "name": "a moment in month 13",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-13-01T00:00:00Z",
   "expect": "refused"
  },
  {
   "name": "a moment on 30 February",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-02-30T00:00:00Z",
   "expect": "refused"
  },
  {
   "name": "a moment at 24:00",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T24:00:00Z",
   "expect": "refused"
  },
  {
   "name": "a moment with an offset where Z belongs",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31T23:59:30+00:00",
   "expect": "refused"
  },
  {
   "name": "a moment written in lowercase",
   "check": "answerValue",
   "field": {
    "name": "at",
    "type": "dateTime",
    "provenance": "code"
   },
   "value": "2098-12-31t23:59:30z",
   "expect": "refused"
  },
  {
   "name": "a list with no maxItems holding 100 items",
   "check": "answerValue",
   "field": {
    "name": "ids",
    "type": "list",
    "of": {
     "type": "id"
    },
    "provenance": "code"
   },
   "value": [
    "IT-0",
    "IT-1",
    "IT-2",
    "IT-3",
    "IT-4",
    "IT-5",
    "IT-6",
    "IT-7",
    "IT-8",
    "IT-9",
    "IT-10",
    "IT-11",
    "IT-12",
    "IT-13",
    "IT-14",
    "IT-15",
    "IT-16",
    "IT-17",
    "IT-18",
    "IT-19",
    "IT-20",
    "IT-21",
    "IT-22",
    "IT-23",
    "IT-24",
    "IT-25",
    "IT-26",
    "IT-27",
    "IT-28",
    "IT-29",
    "IT-30",
    "IT-31",
    "IT-32",
    "IT-33",
    "IT-34",
    "IT-35",
    "IT-36",
    "IT-37",
    "IT-38",
    "IT-39",
    "IT-40",
    "IT-41",
    "IT-42",
    "IT-43",
    "IT-44",
    "IT-45",
    "IT-46",
    "IT-47",
    "IT-48",
    "IT-49",
    "IT-50",
    "IT-51",
    "IT-52",
    "IT-53",
    "IT-54",
    "IT-55",
    "IT-56",
    "IT-57",
    "IT-58",
    "IT-59",
    "IT-60",
    "IT-61",
    "IT-62",
    "IT-63",
    "IT-64",
    "IT-65",
    "IT-66",
    "IT-67",
    "IT-68",
    "IT-69",
    "IT-70",
    "IT-71",
    "IT-72",
    "IT-73",
    "IT-74",
    "IT-75",
    "IT-76",
    "IT-77",
    "IT-78",
    "IT-79",
    "IT-80",
    "IT-81",
    "IT-82",
    "IT-83",
    "IT-84",
    "IT-85",
    "IT-86",
    "IT-87",
    "IT-88",
    "IT-89",
    "IT-90",
    "IT-91",
    "IT-92",
    "IT-93",
    "IT-94",
    "IT-95",
    "IT-96",
    "IT-97",
    "IT-98",
    "IT-99"
   ],
   "expect": "fits"
  },
  {
   "name": "a list with no maxItems holding 101 items",
   "check": "answerValue",
   "field": {
    "name": "ids",
    "type": "list",
    "of": {
     "type": "id"
    },
    "provenance": "code"
   },
   "value": [
    "IT-0",
    "IT-1",
    "IT-2",
    "IT-3",
    "IT-4",
    "IT-5",
    "IT-6",
    "IT-7",
    "IT-8",
    "IT-9",
    "IT-10",
    "IT-11",
    "IT-12",
    "IT-13",
    "IT-14",
    "IT-15",
    "IT-16",
    "IT-17",
    "IT-18",
    "IT-19",
    "IT-20",
    "IT-21",
    "IT-22",
    "IT-23",
    "IT-24",
    "IT-25",
    "IT-26",
    "IT-27",
    "IT-28",
    "IT-29",
    "IT-30",
    "IT-31",
    "IT-32",
    "IT-33",
    "IT-34",
    "IT-35",
    "IT-36",
    "IT-37",
    "IT-38",
    "IT-39",
    "IT-40",
    "IT-41",
    "IT-42",
    "IT-43",
    "IT-44",
    "IT-45",
    "IT-46",
    "IT-47",
    "IT-48",
    "IT-49",
    "IT-50",
    "IT-51",
    "IT-52",
    "IT-53",
    "IT-54",
    "IT-55",
    "IT-56",
    "IT-57",
    "IT-58",
    "IT-59",
    "IT-60",
    "IT-61",
    "IT-62",
    "IT-63",
    "IT-64",
    "IT-65",
    "IT-66",
    "IT-67",
    "IT-68",
    "IT-69",
    "IT-70",
    "IT-71",
    "IT-72",
    "IT-73",
    "IT-74",
    "IT-75",
    "IT-76",
    "IT-77",
    "IT-78",
    "IT-79",
    "IT-80",
    "IT-81",
    "IT-82",
    "IT-83",
    "IT-84",
    "IT-85",
    "IT-86",
    "IT-87",
    "IT-88",
    "IT-89",
    "IT-90",
    "IT-91",
    "IT-92",
    "IT-93",
    "IT-94",
    "IT-95",
    "IT-96",
    "IT-97",
    "IT-98",
    "IT-99",
    "IT-100"
   ],
   "expect": "refused"
  },
  {
   "name": "a 2xx answer that is not 200",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 201,
   "body": "{\"data\":{\"price\":48}}",
   "expect": "ok"
  },
  {
   "name": "a 5xx refusal by its code",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 503,
   "body": "{\"error\":{\"code\":\"unavailable\"}}",
   "expect": "unavailable"
  },
  {
   "name": "a 5xx answer holding data",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 500,
   "body": "{\"data\":{\"price\":48}}",
   "expect": "internal"
  },
  {
   "name": "a body nested 32 deep: the deepest a body is",
   "check": "body",
   "body": "{\"a\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}",
   "expect": "ok"
  },
  {
   "name": "a body nested 33 deep",
   "check": "body",
   "body": "{\"a\":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}",
   "expect": "refused"
  },
  {
   "name": "a body of 33 nested objects",
   "check": "body",
   "body": "{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":1}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}",
   "expect": "refused"
  },
  {
   "name": "brackets inside a string are not nesting",
   "check": "body",
   "body": "{\"a\":\"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\"}",
   "expect": "ok"
  },
  {
   "name": "any body that repeats a key, whatever it is for",
   "check": "body",
   "body": "{\"a\":1,\"a\":2}",
   "expect": "refused"
  },
  {
   "name": "any body that is not JSON, whatever it is for",
   "check": "body",
   "body": "a=1",
   "expect": "refused"
  },
  {
   "name": "an input text that is empty",
   "check": "input",
   "input": [
    {
     "name": "itemId",
     "type": "id",
     "prefix": "IT-"
    },
    {
     "name": "note",
     "type": "text",
     "maxLength": 5,
     "optional": true
    },
    {
     "name": "sizes",
     "type": "list",
     "maxItems": 3,
     "of": [
      {
       "name": "size",
       "type": "choice",
       "of": [
        "s",
        "m",
        "l"
       ]
      },
      {
       "name": "count",
       "type": "number",
       "min": 1,
       "optional": true
      }
     ]
    }
   ],
   "value": {
    "itemId": "IT-1",
    "note": "",
    "sizes": [
     {
      "size": "s",
      "count": 1
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an answer text that is empty",
   "check": "answerValue",
   "field": {
    "name": "title",
    "type": "text",
    "maxLength": 5,
    "provenance": "outside"
   },
   "value": "",
   "expect": "refused"
  },
  {
   "name": "a describe with no operations",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "a describe with no events",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation with no write",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "input": [],
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation with no freeText",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "write": false,
      "input": [],
      "answer": []
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation with no input",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "write": false,
      "answer": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an operation with no answer",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [
     {
      "name": "op1",
      "write": false,
      "input": [],
      "freeText": false
     }
    ],
    "events": []
   },
   "expect": "refused"
  },
  {
   "name": "an event with no sender",
   "check": "describe",
   "describe": {
    "wire": "v0",
    "operations": [],
    "events": [
     {
      "kind": "site.e1",
      "fields": []
     }
    ]
   },
   "expect": "refused"
  },
  {
   "name": "an event of a kind the board did not declare, with a malformed id: the kind is answered first",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.other\",\"id\":\"not an id!\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{}}",
   "expect": "unknown_event"
  },
  {
   "name": "an event whose declaration has a problem, with a malformed id: the declaration is answered first",
   "check": "event",
   "events": [
    {
     "kind": "site.flags.set",
     "sender": "system",
     "fields": [
      {
       "name": "rows",
       "type": "list",
       "of": [
        {
         "name": "a",
         "type": "yesNo"
        },
        {
         "name": "a",
         "type": "yesNo"
        }
       ]
      }
     ]
    }
   ],
   "body": "{\"event\":\"site.flags.set\",\"id\":\"not an id!\",\"at\":\"2098-12-31T23:59:30Z\",\"fields\":{\"rows\":[]}}",
   "expect": "internal"
  },
  {
   "name": "an event body that starts with a byte-order mark",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "bodyHex": "efbbbf7b226576656e74223a22736974652e73746f636b2e6c656674222c226964223a2265762d30303034222c226174223a22323039382d31322d33315432333a35393a33305a222c226669656c6473223a7b226c656674223a337d7d",
   "expect": "bad_event"
  },
  {
   "name": "an event body whose bytes are not UTF-8",
   "check": "event",
   "events": [
    {
     "kind": "site.stock.left",
     "sender": "system",
     "fields": [
      {
       "name": "left",
       "type": "number",
       "min": 0
      },
      {
       "name": "until",
       "type": "date",
       "optional": true
      }
     ]
    }
   ],
   "bodyHex": "7b226576656e74223a22736974652e73746f636b2e6c656674222c226964223a2265762d303030ff222c226174223a22323039382d31322d33315432333a35393a33305a222c226669656c6473223a7b226c656674223a337d7d",
   "expect": "bad_event"
  },
  {
   "name": "an operation the site does not declare, with a body that is not JSON: the body is answered first",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.delete",
   "body": "op=items.delete",
   "expect": "bad_input"
  },
  {
   "name": "an operation whose declaration has a problem, with a body that is not JSON: the body is answered first",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "maxLength": 40
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "body": "op=items.hide",
   "expect": "bad_input"
  },
  {
   "name": "an operation body that starts with a byte-order mark",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "bodyHex": "efbbbf7b226f70223a226974656d732e68696465222c22696e707574223a7b226974656d4964223a2249542d31222c2273697a6573223a5b7b2273697a65223a2273222c22636f756e74223a317d2c7b2273697a65223a226c222c22636f756e74223a327d5d2c2268696465223a747275657d2c226d61726b6564223a66616c73657d",
   "expect": "bad_input"
  },
  {
   "name": "an operation body whose bytes are not UTF-8",
   "check": "operationBody",
   "operations": [
    {
     "name": "items.hide",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id",
       "prefix": "IT-"
      },
      {
       "name": "sizes",
       "type": "list",
       "maxItems": 3,
       "of": [
        {
         "name": "size",
         "type": "choice",
         "of": [
          "s",
          "m",
          "l"
         ]
        },
        {
         "name": "count",
         "type": "number",
         "min": 1,
         "max": 9
        }
       ]
      },
      {
       "name": "hide",
       "type": "yesNo"
      }
     ],
     "answer": [
      {
       "name": "hidden",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    },
    {
     "name": "items.note",
     "write": true,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      },
      {
       "name": "note",
       "type": "text",
       "maxLength": 5
      }
     ],
     "answer": [],
     "freeText": false
    }
   ],
   "op": "items.hide",
   "bodyHex": "7b226f70223a226974656d732e68696465222c22696e707574223a7b226974656d4964223a2249542dff222c2273697a6573223a5b7b2273697a65223a2273222c22636f756e74223a317d2c7b2273697a65223a226c222c22636f756e74223a327d5d2c2268696465223a747275657d2c226d61726b6564223a66616c73657d",
   "expect": "bad_input"
  },
  {
   "name": "an answer that fits its operation",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48,\"title\":\"hello\"}}",
   "expect": "ok"
  },
  {
   "name": "an answer that leaves out its optional field",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48}}",
   "expect": "ok"
  },
  {
   "name": "work that goes on after the answer: the operation declares accepted, and answers it",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "feed.reload",
   "status": 200,
   "body": "{\"data\":{\"accepted\":true}}",
   "expect": "ok"
  },
  {
   "name": "describe's answer: a well-formed describe under data",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "describe",
   "status": 200,
   "body": "{\"data\":{\"wire\":\"v0\",\"operations\":[{\"name\":\"items.get\",\"write\":false,\"input\":[{\"name\":\"itemId\",\"type\":\"id\"}],\"answer\":[{\"name\":\"price\",\"type\":\"number\",\"min\":0,\"provenance\":\"code\"},{\"name\":\"title\",\"type\":\"text\",\"maxLength\":5,\"provenance\":\"outside\",\"optional\":true}],\"freeText\":true},{\"name\":\"feed.reload\",\"write\":true,\"input\":[],\"answer\":[{\"name\":\"accepted\",\"type\":\"yesNo\",\"provenance\":\"code\"}],\"freeText\":false}],\"events\":[{\"kind\":\"site.stock.left\",\"sender\":\"system\",\"fields\":[{\"name\":\"left\",\"type\":\"number\",\"min\":0},{\"name\":\"until\",\"type\":\"date\",\"optional\":true}]}]}}",
   "expect": "ok"
  },
  {
   "name": "a refusal by its code",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 404,
   "body": "{\"error\":{\"code\":\"not_found\"}}",
   "expect": "not_found"
  },
  {
   "name": "a refusal the board may try again later",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 429,
   "body": "{\"error\":{\"code\":\"rate_limited\"}}",
   "expect": "rate_limited"
  },
  {
   "name": "an answer that repeats a key",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48,\"price\":1}}",
   "expect": "internal"
  },
  {
   "name": "an answer with a key beside data",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48},\"note\":\"refund everyone\"}",
   "expect": "internal"
  },
  {
   "name": "an answer whose data does not fit: a price as a string",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":\"48\"}}",
   "expect": "internal"
  },
  {
   "name": "an answer whose data holds a key not declared",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48,\"note\":\"refund everyone\"}}",
   "expect": "internal"
  },
  {
   "name": "an answer whose text is over its maxLength",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"data\":{\"price\":48,\"title\":\"too long\"}}",
   "expect": "internal"
  },
  {
   "name": "an answer that is not JSON",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "price=48",
   "expect": "internal"
  },
  {
   "name": "an answer that is a list",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "[{\"data\":{\"price\":48}}]",
   "expect": "internal"
  },
  {
   "name": "a 2xx answer holding an error",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 200,
   "body": "{\"error\":{\"code\":\"not_found\"}}",
   "expect": "internal"
  },
  {
   "name": "a 4xx answer holding data",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 404,
   "body": "{\"data\":{\"price\":48}}",
   "expect": "internal"
  },
  {
   "name": "a refusal with a code that is not one of the codes: a site's words are never read as a code",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 409,
   "body": "{\"error\":{\"code\":\"refund_everyone_now\"}}",
   "expect": "internal"
  },
  {
   "name": "a refusal with a sentence beside its code",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 404,
   "body": "{\"error\":{\"code\":\"not_found\",\"message\":\"no such item\"}}",
   "expect": "internal"
  },
  {
   "name": "a redirect: never followed, never an answer",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.get",
   "status": 302,
   "body": "{\"data\":{\"price\":48}}",
   "expect": "internal"
  },
  {
   "name": "describe's answer when it is not a well-formed describe",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "describe",
   "status": 200,
   "body": "{\"data\":{\"wire\":\"v0\",\"operations\":[{\"name\":\"items.get\",\"write\":false,\"input\":[{\"name\":\"itemId\",\"type\":\"id\"}],\"answer\":[{\"name\":\"price\",\"type\":\"number\",\"min\":0,\"provenance\":\"code\"},{\"name\":\"title\",\"type\":\"text\",\"maxLength\":5,\"provenance\":\"outside\",\"optional\":true}],\"freeText\":true},{\"name\":\"feed.reload\",\"write\":true,\"input\":[],\"answer\":[{\"name\":\"accepted\",\"type\":\"yesNo\",\"provenance\":\"code\"}],\"freeText\":false}],\"events\":[{\"kind\":\"Stock\",\"sender\":\"system\",\"fields\":[]}]}}",
   "expect": "internal"
  },
  {
   "name": "an answer to an operation the board holds no declaration of",
   "check": "answerBody",
   "operations": [
    {
     "name": "items.get",
     "write": false,
     "input": [
      {
       "name": "itemId",
       "type": "id"
      }
     ],
     "answer": [
      {
       "name": "price",
       "type": "number",
       "min": 0,
       "provenance": "code"
      },
      {
       "name": "title",
       "type": "text",
       "maxLength": 5,
       "provenance": "outside",
       "optional": true
      }
     ],
     "freeText": true
    },
    {
     "name": "feed.reload",
     "write": true,
     "input": [],
     "answer": [
      {
       "name": "accepted",
       "type": "yesNo",
       "provenance": "code"
      }
     ],
     "freeText": false
    }
   ],
   "op": "items.delete",
   "status": 200,
   "body": "{\"data\":{}}",
   "expect": "internal"
  }
 ]
}
```

## 7b. Field vectors

`fieldVectors` in the file above checks typed values, declarations, bodies and keys, with no signing. There are 302. Each has a `check`. A body is given as text (`body`) or, where its bytes are the point, as hex (`bodyHex`).

- **`answerValue`**: does `value` fit the answer field `field` (§5, §6)? `expect` is `fits` or `refused`. A field whose declaration has any problem fits nothing. (9 fit, 25 are refused. Among them: a row missing a field, an extra field, a wrong type in a row, a value that is not an id, an id without its prefix, a choice off its options, a `null`, a row that is not an object, more rows than `maxItems`, a `maxItems` that is not a number, a list with no `of`; a text within its `maxLength`, at exactly `maxLength` code points with one outside the basic plane, one over, with a lone surrogate, empty, and against a declaration with no `maxLength`; a day in year 0001 and in year 0000; a moment with no fraction, with three fraction digits, and with one; a moment at second 60, in month 13, on 30 February, at 24:00, with an offset, and in lowercase; and a list that declares no `maxItems` holding 100 items (fits) and 101.)
- **`event`**: what the board answers the event `body`, checked against the declarations in `events` (§6). `expect` is `ok`, `bad_event`, `unknown_event` or `internal`; when the reference implementation names the field at fault, `field` gives it (always a declared top-level field). (5 ok; 16 `bad_event`; 1 `unknown_event`; 4 `internal`. Among them: a row with an undeclared key, a row with a `__proto__` key, a row repeating a key; an optional field left out, present, and `null`; `9007199254740993`, which fits as a double; an integer of 401 digits, which does not; an undeclared top-level key, refused with no `field`; a declaration naming a record field twice, which is never used; an undeclared kind with a malformed `id` (`unknown_event`) and an unsound declaration with a malformed `id` (`internal`), for the order; bodies that start with a byte-order mark or are not UTF-8; an event of a kind in a list of 128 declarations (ok) and of 129 (`internal`), a kind that is not in a list of 129 (`internal`: the list is answered before the kind) and a body that is not JSON at such a board (`bad_event`: the body is answered first); and, for which field is named: two fields at fault given in the other order, a required field left out with an optional one at fault, only the second declared field at fault, an undeclared key beside a field at fault (no `field`); and a body of three keys, one of them named with a comma, which is not the four keys.)
- **`describe`**: is `describe` well formed (§5, §6)? `expect` is `ok` (no problem at all) or `refused` (any problem). (19 ok, 105 refused. Among them:
  - provenance: an outside record field with `freeText` false, a record field with none, a list of records or a list item with its own, an event or input field carrying one;
  - shape: a record field that is a list, a name declared twice, a record with no or 33 fields, a bad `maxItems`, a list with no `of`, a choice option that is not an id, a field named `__proto__` or not matching the name rule;
  - keys: each narrowing on a type it does not belong to, `pattern` anywhere, `maxLength`, `enum`, `minimum` and `Prefix` on an input field, and an operation, an event declaration and a field each with a key they do not have;
  - inputs: typed inputs that pass (fields, and none), and every JSON Schema given as an input refused (a closed one; one with an array and no `items`, with `prefixItems`, `$ref`, `$dynamicRef`, an empty `allOf`, `maxLength`/`enum`/`minimum`, or `pattern`/`patternProperties`);
  - text: with no `maxLength`, with 0, 20,001 and a fraction, at 20,000 (ok), as a list's item, in an answer with none or 20,001, in an answer's record with none, and in an event;
  - optional: in an input, an answer, an answer's record and an event together (ok), `optional: false` in each place, a value that is not `true`, and on a list's item;
  - event kinds of two, three and four parts (ok), and of one or five parts, with a capital, a hyphen, a part starting with a digit, an empty part, or a part of 41 characters;
  - required keys: a describe with no `operations` or no `events`, an operation with no `write`, `freeText`, `input` or `answer`, an event with no `sender`;
  - once and no more: an operation listed twice, a kind declared twice;
  - what a describe must say: no `wire`, another `wire`, an operation named `describe`, a `write` that is not a boolean, an event whose `sender` is not one of the strengths;
  - bounds: a text whose provenance is `code`, a number whose `min` is above its `max` (and one whose `min` equals it, ok), an id prefix of 40 characters (ok) and of 41, a choice with no `of`;
  - each cap, at it (ok) and one over: 128 operations and 128 events, and 129 of either; an answer of 64 fields, and of 65; a record, an input and an event of 32 fields, and of 33; a choice of 100 options, and of 101; a list of 100 items at the most, and of 101. The largest declaration the caps allow together (§6) has no vector: it would be megabytes. A checker shows the same thing by building one: it has no problem and is used;
  - never a failure of the check itself: an operation or a field whose name is an object, an operation named with 2,000 characters, a key named `constructor`.)
- **`input`**: does `value` fit an operation whose input is declared as `input` (§5)? `expect` is `fits` or `refused` (the site answers `bad_input`). Input fields whose declaration has any problem take nothing. (6 fit, 19 are refused. Among them: a missing field, an undeclared key, free text where an id is declared, an id without its prefix, a row off its choice or below its `min`, a list over its `maxItems`, a value that is not an object, `null`; a text within its `maxLength`, at exactly `maxLength` code points with one outside the basic plane, one over, `null`, with a lone surrogate, with U+0000, empty, and a number where text is declared; an optional field left out, a row's optional field left out and `null`, an optional field present that does not fit, and a required field left out.)
- **`answer`**: does `value` fit an answer whose fields are declared as `answer` (§5)? `expect` is `fits` or `refused`. (3 fit, 4 are refused: every field present, an optional field left out, a row's optional field left out; an optional field that is `null`, a required field missing, an undeclared key, an optional text over its `maxLength`.)
- **`operationBody`**: what a site that declares `operations` answers the `body` sent to the operation `op` (the path's name, §5). `expect` is `ok`, `bad_input`, `unknown_operation` or `internal`. (5 ok: a body that fits, one with `marked` true, `describe`'s, an operation in a list of 128, and `describe` at a site whose list is 129. 18 `bad_input`: no `marked`, a `marked` that is not a boolean, an extra key, an `op` that is not the path's, a repeated key, an input missing a field, an input with an undeclared key, no `input`, a text over its `maxLength`, a body that is not JSON, a body that is a list, `describe` given an input, a body that starts with a byte-order mark, one that is not UTF-8, and three that fix the order: a body that is not JSON sent to an operation the site does not declare, to one whose declaration has a problem, and to a site whose list is 129 (the body is answered first each time); and a body of two keys, one of them named with a comma, which is not the three keys. 1 `unknown_operation`. 4 `internal`: an operation listed twice, one whose declaration has a problem, an operation in a list of 129, and one that is not in a list of 129 (the list is answered before the operation).)
- **`answerBody`**: what the board reads the answer `body` with HTTP `status` as, for the operation `op` of a site that declares `operations` (§5). `expect` is `ok` or the code the board reads. (5 ok: an answer that fits, the same under status 201, one that leaves out its optional field, `{"data":{"accepted":true}}` for an operation that declares `accepted`, and `describe`'s. 3 by their code: `not_found`, `rate_limited`, and `unavailable` under a 5xx. 17 `internal`: an answer whose one key is named with a comma, a 5xx holding data, an operation in a list of 129, a repeated key, a key beside `data`, data that does not fit, an undeclared key, a text over its `maxLength`, a body that is not JSON, a list, a 2xx holding an error, a 4xx holding data, a code that is not one of the codes, a sentence beside the code, a redirect, a `describe` that is not well formed, and an operation the board holds no declaration of. The 1 MiB cap has no vector: its body would be a megabyte.)
- **`publicKey`**: may `publicKey` be entered (§1)? `expect` is `ok` or `refused`. (1 ok. 15 refused: the eight small-order points, 32 bytes that are no point of the curve, a `y` not below the field's prime, the identity with its sign bit set, 31 bytes, a key with padding, a key spelt with spare bits, and a key in standard base64.)
- **`key`**: may the whole key record `key` be entered (§1)? `expect` is `ok` or `refused`. (2 ok, one of them being retired. 9 refused: a key id with a space, a pairing id of 65 characters, a direction that is neither, a small-order public key, a `from` that is a day, no `from`, an `until` that is not a moment, an `until` not after `from`, and a key the record does not have.)
- **`body`**: is `body` a body a receiver parses at all (§6: decoded, nested no deeper than 32, no key twice)? `expect` is `ok` or `refused`. (2 ok: nested exactly 32 deep, and a string full of brackets, which are not nesting. 4 refused: nested 33 deep in lists, 33 deep in objects, a repeated key, and text that is not JSON.)

A verifier passes when every field vector gets its `expect` (and, for an `event` vector that gives one, its `field`).

## 8. What v0 rests on, and what is not in it

- **Trust in answers.** Answers are trusted through TLS to the paired host plus the signed request, whose pairing id is signed. Answers carry no signature of their own in v0.
- **Who builds what.** The receiving side stores the keys per pairing, checks each key when it is entered and loads them ahead of any request (§1), rate-limits, and then checks the request (§3) and the body: the site an operation's (§5), the board an event's against its own declarations (§6) and an operation's answer (§5).
- **Ids are opaque data.** An id is letters, digits and `. _ : -`, and a list of ids can spell words. A receiver shows an id to an agent **as an id**, never as prose, and never acts on what a run of ids seems to say.
- **What a change bumps.** The `wire-version` token (`v0`) covers the headers and the signed string: a change to either is a new token. From the first release on, a change to the declaration grammar that makes a `describe` pass which was refused before (a new type, a new key, a wider bound) is also a new token, rolled out **board first**: the board accepts the new token before any site sends it. A change that only refuses more is announced on this page under the same token while v0 is unstable.
- **Not in v0:**
  - how the site stores its private key;
  - pagination and batching;
  - key rotation over the wire (it is the owner's);
  - signed answers;
  - provenance stated per field on an input's text;
  - default values for a field that is left out;
  - a declaration key by which an operation refuses marked requests;
  - JSON Schema anywhere in a declaration.
- **Undo is an ordinary write.** A site that offers undo declares an operation for it whose input takes the original write's retry key (a retry key is an id, §2) as an `id` field. It restores only if the row still holds what that write left; otherwise it answers `conflict`, and nothing is done.
- **An event caused by a board write should say so** (advice, not a rule of v0). When a site emits an event because of a write the board asked for, it should carry that write's retry key in a declared `id` field of the event. The board can then tie the event to its cause, instead of reading it as new activity from outside. This needs no new type and no change to the body: a retry key is already an id.

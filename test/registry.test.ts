import { describe, expect, it } from "vitest";
import {
  createRegistry, describeProblems, RegistryProblems, WIRE_DESCRIBE_MAX_EVENTS, WIRE_DESCRIBE_MAX_OPERATIONS,
  type WireAnswerField, type WireEventDecl, type WireInputField, type WireOperation,
} from "../src/index.js";

const yes = (name: string): WireAnswerField => ({ name, type: "yesNo", provenance: "code" });
/** An operation with whatever is given changed; a wrong shape on purpose is cast by the caller. */
const op = (name: string, over: Record<string, unknown> = {}): WireOperation =>
  ({ name, write: false, input: [], answer: [yes("done")], run: async () => ({ done: true }), ...over }) as WireOperation;
const event = (kind: string, over: Record<string, unknown> = {}): WireEventDecl =>
  ({ kind, sender: "system", fields: [{ name: "count", type: "number", min: 0 }], ...over }) as WireEventDecl;
const many = <T>(n: number, make: (i: number) => T): T[] => Array.from({ length: n }, (_, i) => make(i));
const refused = (ops: readonly WireOperation[], events: readonly WireEventDecl[] = []) => () => createRegistry(ops, events);

const INPUT: WireInputField[] = [
  { name: "thingId", type: "id", prefix: "T-" },
  { name: "note", type: "text", maxLength: 5, optional: true },
  { name: "sizes", type: "list", maxItems: 2, optional: true, of: [{ name: "size", type: "choice", of: ["s", "m"] }, { name: "count", type: "number", min: 1, optional: true }] },
];

describe("a registry's describe", () => {
  it("is generated from typed inputs, answers and events, and is a well-formed describe", () => {
    const r = createRegistry(
      [op("things.note", { write: true, input: INPUT }), op("things.count")],
      [event("site.things.counted"), event("site.loaded", { fields: [{ name: "at", type: "dateTime", optional: true }] })],
    );
    expect(describeProblems(r.describe)).toEqual([]);
    expect(r.describe).toEqual({
      wire: "v0",
      operations: [
        { name: "things.note", write: true, input: INPUT, answer: [yes("done")], freeText: false },
        { name: "things.count", write: false, input: [], answer: [yes("done")], freeText: false },
      ],
      events: [
        { kind: "site.things.counted", sender: "system", fields: [{ name: "count", type: "number", min: 0 }] },
        { kind: "site.loaded", sender: "system", fields: [{ name: "at", type: "dateTime", optional: true }] },
      ],
    });
  });

  it("works out freeText, including from a record's fields", () => {
    const r = createRegistry([
      op("rows.code", { answer: [{ name: "rows", type: "list", of: [{ name: "day", type: "date", provenance: "code" }] }] }),
      op("rows.outside", { answer: [{ name: "rows", type: "list", of: [{ name: "day", type: "date", provenance: "code" }, { name: "note", type: "text", maxLength: 200, provenance: "inside" }] }] }),
      op("title.outside", { answer: [{ name: "title", type: "id", provenance: "outside" }] }),
    ], []);
    expect(r.describe.operations.map((o) => o.freeText)).toEqual([false, true, true]);
  });

  it("is fixed once made: the caller's later changes are never read", () => {
    const answer = [{ name: "changed", type: "yesNo" as const, provenance: "code" as const }];
    const input = [{ name: "thingId", type: "id" as const }];
    const ops: WireOperation[] = [{ name: "things.hide", write: true, input, answer, run: async () => ({ changed: true }) }];
    const events = [{ kind: "site.things.hidden", sender: "system" as const, fields: [{ name: "count", type: "number" as const, min: 0 }] }];
    const r = createRegistry(ops, events);
    // The caller changes everything it handed over.
    (answer[0] as { type: string }).type = "id";
    (input[0] as { type: string }).type = "number";
    (events[0]!.fields[0] as { min: number }).min = -100;
    (ops[0] as { name: string }).name = "other";
    const hide = r.operation("things.hide")!;
    expect(hide).toBeDefined();
    expect(r.operation("other")).toBeUndefined();
    expect(r.answerFits(hide, { changed: true })).toBe(true);
    expect(r.answerFits(hide, { changed: "an-id" })).toBe(false);
    expect(r.inputFits(hide, { thingId: "T-1" })).toBe(true);
    expect(r.inputFits(hide, { thingId: 5 })).toBe(false);
    expect(() => r.eventBody("site.things.hidden", "ev-1", "2098-12-31T23:59:30Z", { count: -1 })).toThrow(/bad_event/);
    expect(r.describe.operations[0]).toEqual({ name: "things.hide", write: true, input: [{ name: "thingId", type: "id" }], answer: [{ name: "changed", type: "yesNo", provenance: "code" }], freeText: false });
    expect(Object.isFrozen(r.describe)).toBe(true);
    expect(Object.isFrozen(r.describe.operations[0]!.answer[0])).toBe(true);
    expect(Object.isFrozen(r.describe.operations[0]!.input[0])).toBe(true);
  });
});

describe("a registry is refused when it is made", () => {
  it("with an input that is a JSON Schema, or any input declaration the contract refuses", () => {
    for (const input of [
      { type: "object", properties: { thingId: { type: "string" } }, required: ["thingId"] },
      { type: "object" },
      [{ name: "thingId", type: "id", pattern: "^T-" }],
      [{ name: "thingId", type: "string" }],
      [{ name: "note", type: "text" }],
      [{ name: "note", type: "text", maxLength: 0 }],
      [{ name: "note", type: "text", maxLength: 20_001 }],
      [{ name: "thingId", type: "id", provenance: "code" }],
      [{ name: "thingId", type: "id", optional: false }],
      [{ name: "thingId", type: "id" }, { name: "thingId", type: "id" }],
      [{ name: "thing_id", type: "id" }],
      undefined,
    ]) expect(refused([op("things.get", { input })]), JSON.stringify(input)).toThrow(RegistryProblems);
  });

  it("with an answer the contract refuses", () => {
    for (const answer of [
      [{ name: "title", type: "text", maxLength: 200, provenance: "code" }],
      [{ name: "title", type: "text", provenance: "outside" }],
      [{ name: "title", type: "id" }],
      [{ name: "done", type: "yesNo", provenance: "code", optional: false }],
      [yes("done"), yes("done")],
    ]) expect(refused([op("things.get", { answer })]), JSON.stringify(answer)).toThrow(RegistryProblems);
  });

  it("with an operation named describe, named off the pattern, given twice, or with no function", () => {
    expect(refused([op("describe")])).toThrow(RegistryProblems);
    expect(refused([op("Things.get")])).toThrow(RegistryProblems);
    expect(refused([op("things.get"), op("things.get")])).toThrow(RegistryProblems);
    expect(refused([op("things.get", { run: "not a function" })])).toThrow(RegistryProblems);
    expect(refused([op("things.get", { write: "yes" })])).toThrow(RegistryProblems);
  });

  it("with an event kind off the contract's pattern, or declared twice", () => {
    for (const kind of ["site.loaded", "site.things.loaded", "site.things.rows.loaded", "site_a.things_2.loaded"]) {
      expect(createRegistry([], [event(kind)]).describe.events[0]!.kind).toBe(kind);
    }
    for (const kind of ["loaded", "a.b.c.d.e", "Site.loaded", "site.things-loaded", "site.2things", "site..loaded", `site.${"a".repeat(41)}`, "Bad Kind", ""]) {
      expect(refused([], [event(kind)]), kind).toThrow(RegistryProblems);
    }
    expect(refused([], [event("site.loaded"), event("site.loaded")])).toThrow(RegistryProblems);
    expect(refused([], [event("site.loaded", { sender: "anyone" })])).toThrow(RegistryProblems);
    expect(refused([], [event("site.loaded", { fields: [{ name: "note", type: "text", maxLength: 5 }] })])).toThrow(RegistryProblems);
  });

  it("past a cap, and not at it", () => {
    const ops = (n: number) => many(n, (i) => op(`things.op${i}`));
    const events = (n: number) => many(n, (i) => event(`site.kind${i}`));
    expect(WIRE_DESCRIBE_MAX_OPERATIONS).toBe(128);
    expect(WIRE_DESCRIBE_MAX_EVENTS).toBe(128);
    expect(createRegistry(ops(128), events(128)).describe.operations).toHaveLength(128);
    expect(refused(ops(129))).toThrow(RegistryProblems);
    expect(refused([], events(129))).toThrow(RegistryProblems);

    const answer = (n: number) => many(n, (i) => yes(`f${i}`));
    expect(createRegistry([op("things.get", { answer: answer(64) })], []).describe.operations[0]!.answer).toHaveLength(64);
    expect(refused([op("things.get", { answer: answer(65) })])).toThrow(RegistryProblems);

    const fields = (n: number) => many(n, (i) => ({ name: `f${i}`, type: "yesNo" }));
    expect(createRegistry([op("things.get", { input: fields(32) })], [event("site.loaded", { fields: fields(32) })]).describe.operations[0]!.input).toHaveLength(32);
    expect(refused([op("things.get", { input: fields(33) })])).toThrow(RegistryProblems);
    expect(refused([], [event("site.loaded", { fields: fields(33) })])).toThrow(RegistryProblems);

    const rows = (n: number) => [{ name: "rows", type: "list", of: fields(n) }];
    expect(createRegistry([op("things.get", { input: rows(32) })], []).describe.operations).toHaveLength(1);
    expect(refused([op("things.get", { input: rows(33) })])).toThrow(RegistryProblems);
    expect(refused([op("things.get", { answer: [{ name: "rows", type: "list", of: many(33, (i) => yes(`f${i}`)) }] })])).toThrow(RegistryProblems);
  });

  it("names a thing by its position, never by its name", () => {
    let problems: readonly string[] = [];
    try {
      createRegistry([op("things.get"), op("things.get")], []);
    } catch (err) {
      problems = (err as RegistryProblems).problems;
    }
    expect(problems.length).toBeGreaterThan(0);
    expect(problems.join("\n")).not.toContain("things.get");
    expect(problems.join("\n")).toContain("operation 2");
  });
});

describe("a registry's checks", () => {
  const r = createRegistry([op("things.note", { write: true, input: INPUT })], [event("site.things.counted")]);
  const body = (input: unknown, marked: unknown = false, name = "things.note") => JSON.stringify({ op: name, input, marked });

  it("checks an operation's body as the contract does, and hands back the input and marked", () => {
    expect(r.checkBody(body({ thingId: "T-1" }), "things.note")).toEqual({ ok: true, op: "things.note", input: { thingId: "T-1" }, marked: false });
    expect(r.checkBody(Buffer.from(body({ thingId: "T-1", note: "hello", sizes: [{ size: "s" }, { size: "m", count: 2 }] }, true)), "things.note"))
      .toEqual({ ok: true, op: "things.note", input: { thingId: "T-1", note: "hello", sizes: [{ size: "s" }, { size: "m", count: 2 }] }, marked: true });
    expect(r.checkBody('{"op":"describe","input":{},"marked":false}', "describe")).toEqual({ ok: true, op: "describe", input: {}, marked: false });
  });

  it("refuses a body that is not exactly op, input and marked, or an input that does not fit", () => {
    for (const text of [
      '{"op":"things.note","input":{"thingId":"T-1"}}',
      '{"op":"things.note","input":{"thingId":"T-1"},"marked":"no"}',
      '{"op":"things.note","input":{"thingId":"T-1"},"marked":false,"extra":1}',
      '{"op":"things.other","input":{"thingId":"T-1"},"marked":false}',
      '{"op":"things.note","op":"things.note","input":{"thingId":"T-1"},"marked":false}',
      body({}),
      body({ thingId: "X-1" }),
      body({ thingId: "T-1", other: 1 }),
      body({ thingId: "T-1", note: "" }),
      body({ thingId: "T-1", note: "sixsix" }),
      body({ thingId: "T-1", note: null }),
      body({ thingId: "T-1", sizes: [{ size: "s" }, { size: "s" }, { size: "s" }] }),
      body({ thingId: "T-1", sizes: [{ size: "xl" }] }),
      body({ thingId: "T-1", sizes: [{ count: 1 }] }),
      "not json",
      `﻿${body({ thingId: "T-1" })}`,
    ]) expect(r.checkBody(text, "things.note"), text).toEqual({ ok: false, code: "bad_input" });
    expect(r.checkBody('{"op":"describe","input":{"a":1},"marked":false}', "describe")).toEqual({ ok: false, code: "bad_input" });
  });

  it("answers the body's own shape first, then an operation it does not offer as unknown_operation", () => {
    expect(r.checkBody("not json", "things.other")).toEqual({ ok: false, code: "bad_input" });
    expect(r.checkBody(body({}, false, "things.other"), "things.other")).toEqual({ ok: false, code: "unknown_operation" });
    expect(r.checkBody(body({}, false, "__proto__"), "__proto__")).toEqual({ ok: false, code: "unknown_operation" });
  });

  it("checks an answer: every field that is not optional present, each fitting, nothing else", () => {
    const get = createRegistry([op("things.get", { answer: [yes("done"), { name: "title", type: "text", maxLength: 5, provenance: "outside", optional: true }] })], []);
    const o = get.operation("things.get")!;
    expect(get.answerFits(o, { done: true })).toBe(true);
    expect(get.answerFits(o, { done: true, title: "hello" })).toBe(true);
    for (const data of [{}, { title: "hello" }, { done: true, title: "sixsix" }, { done: true, title: "" }, { done: true, title: null }, { done: true, other: 1 }, null, [true]]) {
      expect(get.answerFits(o, data), JSON.stringify(data)).toBe(false);
    }
  });

  it("checks an outgoing event as the board will", () => {
    expect(r.eventBody("site.things.counted", "ev-1", "2098-12-31T23:59:30Z", { count: 2 })).toBe(
      '{"event":"site.things.counted","id":"ev-1","at":"2098-12-31T23:59:30Z","fields":{"count":2}}',
    );
    expect(() => r.eventBody("site.other", "ev-1", "2098-12-31T23:59:30Z", {})).toThrow(/unknown_event/);
    expect(() => r.eventBody("site.things.counted", "ev-1", "2098-12-31T23:59:30Z", { count: -1 })).toThrow(/bad_event at field count/);
    expect(() => r.eventBody("site.things.counted", "ev 1", "2098-12-31T23:59:30Z", { count: 1 })).toThrow(/bad_event/);
    expect(() => r.eventBody("site.things.counted", "ev-1", "2098-12-31T23:59:30.5Z", { count: 1 })).toThrow(/bad_event/);
  });
});

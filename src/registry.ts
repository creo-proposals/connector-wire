/**
 * A site's registry: the operations and events it offers. `describe` is generated from it, so it cannot drift from what the handler
 * does, and the same declarations check every body, every input, every answer and every outgoing event. Everything is declared in the
 * wire's own typed fields (contract sections 5 and 6): an operation's input as its answer and an event's fields are, never a JSON
 * Schema. A registry whose `describe` has any problem is refused when it is made, never used: a name or kind off its pattern or given
 * twice, a list past a cap (128 operations, 128 events, 64 top-level answer fields, 32 fields in a record, an event or an input), or
 * any declaration the contract refuses.
 */
import {
  answerFits, checkEvent, checkOperationBody, describeProblems, inputFits, WIRE_VERSION,
  type WireAnswerField, type WireDescribe, type WireEventDecl, type WireInputField, type WireOperationDecl,
} from "./wire.js";

/** What an operation's function is told about the request. */
export interface OperationContext<Tx> {
  readonly pairing: string;
  readonly keyId: string;
  /** The retry key, for a write; null for a read that carried none. */
  readonly retryKey: string | null;
  /**
   * The body's `marked`: true when the run that asked had received outside text. An operation may refuse a marked request itself
   * (`throw new WireRefusal("conflict")`, or whichever code fits). False says only that the run had seen no outside text: it is never
   * trust in the words of a text field, which are data either way.
   */
  readonly marked: boolean;
  /** For a write, the transaction (a savepoint of it) that also keeps its answer; undefined for a read. */
  readonly tx: Tx | undefined;
  /** For a read, aborted at the deadline: stop work nobody will wait for. A write's is never aborted (it runs to its end). */
  readonly signal: AbortSignal;
}

export interface WireOperation<Tx = unknown> {
  readonly name: string;
  readonly write: boolean;
  /**
   * What the operation takes, in the wire's typed fields: at most 32, each a scalar with its type's own narrowing, a `text` with its
   * `maxLength`, a list of one scalar, or a list of one-level records; `optional: true` where a key may be absent. `[]` when it takes
   * nothing. Never a JSON Schema, and no `provenance`.
   */
  readonly input: readonly WireInputField[];
  /** What it answers: at most 64 typed fields, each with its `provenance` (a list of records states one on each record field). */
  readonly answer: readonly WireAnswerField[];
  /**
   * Does the work and answers the data: exactly the declared answer fields (an optional one may be absent), each fitting. `input` is
   * the checked input: exactly the declared input fields, each fitting; its text is data, whoever wrote it. To refuse, throw
   * `new WireRefusal(code)` with `not_found`, `conflict`, `bad_input` or `unavailable`; a write's work before the refusal is rolled
   * back. Any other code, or any other throw, is answered `internal`.
   */
  readonly run: (input: Readonly<Record<string, unknown>>, ctx: OperationContext<Tx>) => Promise<Record<string, unknown>>;
}

/** An operation's refusal, answered as `{"error":{"code":...}}`. */
export class WireRefusal extends Error {
  constructor(readonly code: "not_found" | "conflict" | "bad_input" | "unavailable") {
    super(code);
  }
}

const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const outside = (f: unknown): boolean =>
  isObject(f) && (f.provenance === "outside" || f.provenance === "modelFromOutside" || f.type === "text");

/** `freeText`, worked out from the fields (a list of records is outside when any of its fields is), so it is never declared wrong. */
export function isFreeText(answer: readonly WireAnswerField[]): boolean {
  return Array.isArray(answer)
    && answer.some((f: unknown) => outside(f) || (isObject(f) && f.type === "list" && Array.isArray(f.of) && f.of.some(outside)));
}

export interface WireRegistry<Tx = unknown> {
  /** The answer to `describe`, generated from the operations and events given; deep-frozen. */
  readonly describe: WireDescribe;
  operation(name: string): WireOperation<Tx> | undefined;
  /**
   * An operation's body as the contract checks it (`checkOperationBody`, against this registry's own declarations), in its order: the
   * body's own shape first (UTF-8 JSON nested no deeper than 32, no key twice, exactly `op`, `input` and `marked`, `op` equal to
   * `name`, the path's), else `bad_input` whatever `name` is; then `name` is an operation the site offers, else `unknown_operation`;
   * then `marked` is a boolean and `input` holds exactly the declared input fields, else `bad_input`.
   */
  checkBody(body: Uint8Array | string, name: string): ReturnType<typeof checkOperationBody>;
  /** Whether an input object is exactly the operation's declared input (`inputFits`). */
  inputFits(op: WireOperation<Tx>, input: unknown): boolean;
  /** Whether data is exactly the operation's answer: every declared field that is not optional present, each fitting, nothing else. */
  answerFits(op: WireOperation<Tx>, data: unknown): boolean;
  /**
   * The JSON body of an outgoing event, checked against the site's own declaration exactly as the board will check it. Throws when the
   * kind is not declared or a field does not fit, naming only the field.
   */
  eventBody(kind: string, id: string, at: string, fields: Readonly<Record<string, unknown>>): string;
}

export class RegistryProblems extends Error {
  constructor(readonly problems: readonly string[]) {
    super(`the registry has problems:\n${problems.join("\n")}`);
  }
}

function deepFreeze<T>(v: T): T {
  if (v !== null && typeof v === "object") {
    Object.freeze(v);
    for (const x of Object.values(v)) deepFreeze(x);
  }
  return v;
}
/** A deep, frozen JSON copy: what the registry checks against can never be changed by the caller afterwards. */
function frozenCopy<T>(v: T): T {
  return v === undefined ? v : deepFreeze(JSON.parse(JSON.stringify(v)) as T);
}

export function createRegistry<Tx = unknown>(given: readonly WireOperation<Tx>[], givenEvents: readonly WireEventDecl[]): WireRegistry<Tx> {
  if (!Array.isArray(given) || !Array.isArray(givenEvents)) throw new RegistryProblems(["a registry is a list of operations and a list of events"]);
  // The registry works only from its own frozen copies of the declarations; the caller's objects are read once, here.
  let operations: readonly WireOperation<Tx>[];
  let describe: WireDescribe;
  try {
    operations = Object.freeze(given.map((o) => Object.freeze({
      name: o.name, write: o.write, input: frozenCopy(o.input), answer: frozenCopy(o.answer), run: o.run,
    })));
    // One describe, made once and frozen whole: the handler answers it, and every check below is made against these same objects.
    describe = deepFreeze({
      wire: WIRE_VERSION,
      operations: operations.map((o): WireOperationDecl => ({
        name: o.name, write: o.write, input: o.input, answer: o.answer, freeText: isFreeText(o.answer),
      })),
      events: frozenCopy(givenEvents),
    });
  } catch {
    throw new RegistryProblems(["a registry's operations and events are plain JSON values, and each operation an object"]);
  }
  // The contract's own check of a describe decides: its caps, each name and each kind once, every pattern and every declaration. A
  // thing is named by its position, as the contract's problem lines name it.
  const problems = [
    ...describeProblems(describe),
    ...operations.flatMap((o, i) => (typeof o.run === "function" ? [] : [`operation ${i + 1}: run is a function`])),
  ];
  if (problems.length > 0) throw new RegistryProblems(problems);
  const byName = new Map(operations.map((o) => [o.name, o]));
  return {
    describe,
    operation: (name) => byName.get(name),
    checkBody: (body, name) => checkOperationBody(body, name, describe.operations),
    inputFits: (op, input) => inputFits(op.input, input),
    answerFits: (op, data) => answerFits(op.answer, data),
    eventBody(kind, id, at, fields) {
      const body = JSON.stringify({ event: kind, id, at, fields });
      // The check is the board's own, run whole: the kind is declared, `id` and `at` are well formed, the fields fit.
      const r = checkEvent(body, describe.events);
      if (!r.ok) throw new Error(r.field ? `event ${kind}: ${r.code} at field ${r.field}` : `event ${kind}: ${r.code}`);
      return body;
    },
  };
}

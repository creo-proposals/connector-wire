import { describe, expect, it } from "vitest";
import { parseWireJson } from "../src/index.js";

describe("parseWireJson", () => {
  it("reads JSON", () => {
    expect(parseWireJson('{"a":1,"b":[{"c":2},{"c":3}]}')).toEqual({ value: { a: 1, b: [{ c: 2 }, { c: 3 }] } });
    expect(parseWireJson("[1,2]")).toEqual({ value: [1, 2] });
  });
  it("refuses text that is not JSON", () => {
    expect(parseWireJson("{")).toBeNull();
    expect(parseWireJson("")).toBeNull();
  });
  it("refuses a key repeated in any object, compared after unescaping", () => {
    expect(parseWireJson('{"a":1,"a":2}')).toBeNull();
    expect(parseWireJson('{"x":{"c":1,"\\u0063":2}}')).toBeNull();
    expect(parseWireJson('{"rows":[{"k":1},{"k":2,"k":3}]}')).toBeNull();
  });
  it("refuses a body nested deeper than 32, the body's own object being the first level", () => {
    const nested = (depth: number): string => `{"a":${"[".repeat(depth - 1)}${"]".repeat(depth - 1)}}`;
    expect(parseWireJson(nested(32))).not.toBeNull();
    expect(parseWireJson(nested(33))).toBeNull();
    // Brackets inside a string are not nesting.
    expect(parseWireJson(JSON.stringify({ a: "[{".repeat(100) }))).not.toBeNull();
  });
  it("refuses 100,000 brackets without parsing them, open or balanced", () => {
    expect(parseWireJson("[".repeat(100_000))).toBeNull();
    expect(parseWireJson("[".repeat(50_000) + "]".repeat(50_000))).toBeNull();
    expect(parseWireJson('{"a":'.repeat(50_000) + "1" + "}".repeat(50_000))).toBeNull();
  });
  it("allows the same key in sibling objects and keys that look alike in strings", () => {
    expect(parseWireJson('{"a":{"k":1},"b":{"k":2}}')).not.toBeNull();
    expect(parseWireJson('{"a":"\\"a\\":","b":"{\\"a\\""}')).not.toBeNull();
  });
});

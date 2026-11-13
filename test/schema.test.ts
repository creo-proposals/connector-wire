import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { WIRE_SCHEMA_SQL, wireSchemaSql } from "../src/postgres.js";

describe("the schema", () => {
  it("in code is the same as sql/0001_wire.sql", () => {
    expect(WIRE_SCHEMA_SQL).toBe(readFileSync(new URL("../sql/0001_wire.sql", import.meta.url), "utf8"));
    expect(wireSchemaSql()).toBe(WIRE_SCHEMA_SQL);
  });
});

describe("the package", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as Record<string, unknown>;
  it("is Apache-2.0 with its licence text, and not marked private", () => {
    expect(pkg.license).toBe("Apache-2.0");
    expect(pkg.private).toBeUndefined();
    expect(readFileSync(new URL("../LICENSE", import.meta.url), "utf8")).toMatch(/^\s*Apache License\s+Version 2\.0, January 2004/);
  });
  it("has no runtime dependency, and postgres only as an optional peer", () => {
    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.peerDependencies).toEqual({ postgres: "^3.4.0" });
    expect(pkg.peerDependenciesMeta).toEqual({ postgres: { optional: true } });
  });
  it("gives every entry a default condition", () => {
    for (const entry of Object.values(pkg.exports as Record<string, Record<string, string>>)) expect(entry.default).toBe(entry.import);
  });
});

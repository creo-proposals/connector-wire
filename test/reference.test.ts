import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// The pure half (src/wire.ts) is the reviewed reference implementation, taken whole (vectors/SOURCE.md). A change to it is a
// change away from the reference: copy the reference again and update the hash, never edit the file here.
const text = readFileSync(new URL("../src/wire.ts", import.meta.url));

describe("the contract, shipped with the package", () => {
  const contract = readFileSync(new URL("../CONTRACT.md", import.meta.url));
  it("is the page vectors/SOURCE.md names, byte for byte", () => {
    expect(createHash("sha256").update(contract).digest("hex")).toBe("5cdad7e13f9bdb693245b7b6e003ff6022291ea4c816181251f06b64827b9760");
  });
  it("holds the copied vectors as its JSON block, and is packed", () => {
    const vectors = readFileSync(new URL("../vectors/connector-wire-v0.json", import.meta.url), "utf8");
    // A boolean, so a failure does not print half a megabyte.
    expect(contract.toString("utf8").includes(`\n\`\`\`json\n${vectors}\`\`\`\n`)).toBe(true);
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { files: string[] };
    expect(pkg.files).toContain("CONTRACT.md");
  });
});

describe("the pure half", () => {
  it("is the reference implementation, byte for byte", () => {
    expect(createHash("sha256").update(text).digest("hex")).toBe("db040e298e851d28d8704d1dd3c28aec4edb839eab1f2eb88a20a2144a02c8e6");
  });
  it("imports only node:crypto", () => {
    const from = [...text.toString("utf8").matchAll(/^import\s.*?\sfrom\s+"([^"]+)";$/gm)].map((m) => m[1]);
    expect(from.length).toBeGreaterThan(0);
    expect([...new Set(from)]).toEqual(["node:crypto"]);
  });
});

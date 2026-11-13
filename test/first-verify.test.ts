import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import ts from "typescript";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Contract section 7, what an implementer must test itself: "time the first request that names a held key against requests that name
// no key, in a fresh process: the two must not be told apart". A receiver that checked or imported a key on its first use would answer
// that first request many times slower (the curve check is about a millisecond, a signature check a small fraction of that), and the
// difference would list the held key ids.
//
// Each fresh process is `first-verify-child.ts`: a receiver that loads its keys, answers requests naming a key it does not hold, then
// the first request naming the key it holds. One timing is one sample on a shared machine, so the comparison is made in several
// fresh processes and the bound is generous: it fails only when, in every one of them, the first held-key request was several times
// slower than a request naming no held key and slower by more than a quarter of a millisecond. A pause in one process cannot cause
// that, and a key checked on first use always does.
const PROCESSES = 7;
const TIMES_SLOWER = 4;
const SLOWER_BY_NS = 250_000;

interface Run {
  problems: string[];
  notHeldAnswers: string[];
  notHeldNs: number;
  heldAnswer: string;
  heldNs: number;
  workBefore: { curveChecks: number; keyImports: number };
  workAfter: { curveChecks: number; keyImports: number };
}

describe("the first request that names a held key, in a fresh process (contract section 7)", () => {
  let dir = "";
  const runs: Run[] = [];

  beforeAll(async () => {
    // The tests run from the TypeScript sources and there is no build yet, so the two files a fresh process needs are compiled here,
    // each on its own: the pure half imports nothing but node:crypto, and the child imports nothing but the pure half.
    const compiled = (file: string): string => ts.transpileModule(readFileSync(new URL(file, import.meta.url), "utf8"), {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    dir = mkdtempSync(join(tmpdir(), "connector-wire-first-verify-"));
    writeFileSync(join(dir, "wire.mjs"), compiled("../src/wire.ts"));
    const child = compiled("./first-verify-child.ts").split("../src/wire.js").join("./wire.mjs");
    if (!child.includes("./wire.mjs")) throw new Error("the child does not import the compiled pure half");
    writeFileSync(join(dir, "child.mjs"), child);
    // One process at a time: each is alone on its timings as far as this test can arrange it.
    for (let i = 0; i < PROCESSES; i++) {
      const { stdout } = await promisify(execFile)(process.execPath, [join(dir, "child.mjs")], { timeout: 60_000, env: { ...process.env, NODE_OPTIONS: "" } });
      runs.push(JSON.parse(stdout) as Run);
    }
  }, 300_000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("is answered, as the requests before it were: a key that is not held is bad_signature, the held key verifies", () => {
    expect(runs).toHaveLength(PROCESSES);
    for (const r of runs) {
      expect(r.problems).toEqual([]);
      expect(r.notHeldAnswers).toEqual(["bad_signature"]);
      expect(r.heldAnswer).toBe("ok");
    }
  });

  it("checks and imports no key: that was done when the keys were loaded", () => {
    for (const r of runs) {
      // The one key's curve check and its import were done before any request, and no request added to either.
      expect(r.workBefore.curveChecks).toBeGreaterThanOrEqual(1);
      expect(r.workBefore.keyImports).toBeGreaterThanOrEqual(1);
      expect(r.workAfter).toEqual(r.workBefore);
    }
  });

  it("cannot be told from a request that names no held key by the time it takes", () => {
    const shown = runs.map((r) => `${r.heldNs} ns against ${r.notHeldNs} ns`).join("; ");
    // Told apart in a process: the first held-key request far slower than a request naming no held key, or far faster.
    const slower = runs.filter((r) => r.heldNs > TIMES_SLOWER * r.notHeldNs && r.heldNs - r.notHeldNs > SLOWER_BY_NS);
    const faster = runs.filter((r) => r.notHeldNs > TIMES_SLOWER * r.heldNs && r.notHeldNs - r.heldNs > SLOWER_BY_NS);
    expect(runs).toHaveLength(PROCESSES);
    expect(slower.length, shown).toBeLessThan(PROCESSES);
    expect(faster.length, shown).toBeLessThan(PROCESSES);
  });
});

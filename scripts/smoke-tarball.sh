#!/usr/bin/env bash
# Installs a packed tarball into an empty folder, the way a consumer installs a release, and imports both entry points.
# Usage: scripts/smoke-tarball.sh <path to .tgz> [npm|bun]
set -euo pipefail
TGZ="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
TOOL="${2:-npm}"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

# What the tarball must hold: the build, the SQL, the vectors, the contract and the licence; never the sources or tests.
LIST="$(tar -tzf "$TGZ")"
for f in package/dist/index.js package/dist/index.d.ts package/dist/postgres.js package/dist/postgres.d.ts \
         package/sql/0001_wire.sql package/vectors/connector-wire-v0.json package/CONTRACT.md package/LICENSE package/package.json; do
  grep -qx "$f" <<<"$LIST" || { echo "missing from the tarball: $f"; exit 1; }
done
if grep -qE '^package/(src|test)/' <<<"$LIST"; then echo "sources or tests in the tarball"; exit 1; fi

cd "$DIR"
echo '{"name":"smoke","version":"0.0.0","private":true,"type":"module"}' > package.json
cat > smoke.mjs <<'JS'
import * as wire from "@creo-proposals/connector-wire";
import * as pg from "@creo-proposals/connector-wire/postgres";
const need = (o, names) => { for (const n of names) if (!(n in o)) throw new Error(`missing export: ${n}`); };
need(wire, ["signWire", "verifyWire", "handleOperation", "createRegistry", "callOperation", "sendEvent", "drainOutbox", "newKeyPair"]);
need(pg, ["postgresStores", "WIRE_SCHEMA_SQL", "wireSchemaSql"]);
if (!pg.WIRE_SCHEMA_SQL.includes("CREATE TABLE wire_nonces")) throw new Error("the schema is not in the build");
const pair = wire.newKeyPair();
if (!wire.wirePublicKey(pair.publicKey)) throw new Error("a fresh key does not read back");
console.log("both entry points import and work");
JS
case "$TOOL" in
  npm) npm install --no-audit --no-fund --silent "$TGZ" && node smoke.mjs ;;
  bun) bun add "$TGZ" >/dev/null && bun smoke.mjs ;;
  *) echo "tool is npm or bun"; exit 2 ;;
esac

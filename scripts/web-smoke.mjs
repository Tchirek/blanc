// 窓の外
// 試しの声を
// 掛けにけり
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import assert from "node:assert/strict";

const [web = "dist/web", data = "testdata"] = process.argv.slice(2);
await import(pathToFileURL(join(web, "wasm_exec.js")).href);

const ready = new Promise((resolve) => { globalThis.blancReady = resolve; });
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(readFileSync(join(web, "blanc.wasm")), go.importObject);
go.run(instance);
await ready;

const names = ["report.json", "domains-trackers.txt", "domains-functional.txt", "domains-other.txt"];
const files = {};
for (const name of names) files[`noir-out/${name}`] = new Uint8Array(readFileSync(join(data, name)));
files["noir-out/report.md"] = "# ignored";

let reply = JSON.parse(globalThis.blancCompile(files, ""));
assert.equal(reply.ok, true, reply.error);
assert.equal(reply.result.stats.global_rules, 5);
assert.equal(reply.result.device.model, "Pixel 7");
assert.match(reply.result.files["mihomo.rules.yaml"], /DOMAIN-SUFFIX,alog\.umeng\.com,REJECT/);
assert.equal(JSON.parse(reply.result.files["singbox.json"]).version, 3);

reply = JSON.parse(globalThis.blancCompile(files, "version: 2\napps:\n  jp.quietreader.app: allow\n"));
assert.equal(reply.ok, true, reply.error);
assert.equal(reply.result.policy, "pasted");
assert.match(reply.result.files["mihomo.rules.yaml"], /NOT,\(\(PROCESS-NAME,jp\.quietreader\.app\)\)/);

reply = JSON.parse(globalThis.blancCompile({ "report.json": "{}" }, ""));
assert.equal(reply.ok, false);
assert.match(reply.error, /domains-trackers\.txt/);

reply = JSON.parse(globalThis.blancCompile("nope"));
assert.equal(reply.ok, false);

console.log(`web smoke ok (BLANC ${globalThis.blancVersion})`);
process.exit(0);

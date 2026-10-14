#!/usr/bin/env node
// Test shim standing in for powershell.exe / cmd.exe so the suite runs on any OS.
import { spawnSync } from "node:child_process";
const a = process.argv.slice(2);
let script;
const i = a.indexOf("-EncodedCommand");
if (i >= 0) {
  script = Buffer.from(a[i + 1], "base64").toString("utf16le");
  script = script.replace(/^.*?UTF8; /s, "");
  if (script.includes("$PSVersionTable")) { process.stdout.write("7.4.0"); process.exit(0); }
} else {
  script = a[3].replace(/^"|"$/g, "");
}
const r = spawnSync("sh", ["-c", script], { stdio: "inherit" });
process.exit(r.status ?? 1);

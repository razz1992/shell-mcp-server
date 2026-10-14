import type { ShellMode } from "./config.js";

export type ShellKind = "powershell" | "cmd";
export interface Verdict {
  allowed: boolean;
  reason?: string;
}

interface Rule {
  id: string;
  reason: string;
  re: RegExp;
}

/**
 * Denylist for "standard" mode. This is a SPEED BUMP against accidents and obvious
 * misuse, NOT a security boundary: PowerShell can obfuscate almost anything.
 * The real boundary is running the server as a low-privilege Windows user.
 */
export const DENY_RULES: Rule[] = [
  { id: "recursive-delete", reason: "Recursive deletion (Remove-Item -Recurse, rd/rmdir /s, del /s)", re: /\bRemove-Item\b[^\n|;]*-Recurse|\b(rd|rmdir)\b[^\n|;]*\/s\b|\bdel\b[^\n|;]*\/s\b/i },
  { id: "disk-format", reason: "Disk/partition destructive operations", re: /\bFormat-Volume\b|\bformat(\.com)?\s+[a-z]:|\bdiskpart\b|\bClear-Disk\b|\bInitialize-Disk\b|\bRemove-Partition\b/i },
  { id: "registry-delete", reason: "Registry deletion or hive export of SAM/SECURITY", re: /\breg(\.exe)?\s+(delete|save)\b|\bRemove-Item(Property)?\b[^\n|;]*\bHK(LM|CU|CR|U|CC)\b/i },
  { id: "exec-policy", reason: "Changing PowerShell execution policy", re: /\bSet-ExecutionPolicy\b/i },
  { id: "power-state", reason: "Shutdown/restart", re: /\bshutdown(\.exe)?\b|\bStop-Computer\b|\bRestart-Computer\b/i },
  { id: "security-tamper", reason: "Disabling or altering security controls (Defender, firewall, boot config, shadow copies, event logs)", re: /\b(Set|Add)-MpPreference\b|\bnetsh\s+advfirewall\b|\bbcdedit\b|\bvssadmin\s+delete\b|\bwevtutil\s+cl\b|\bClear-EventLog\b|\bDisable-NetFirewallRule\b|\bUninstall-WindowsFeature\b/i },
  { id: "privilege-escalation", reason: "Privilege escalation or account/service/persistence changes", re: /-Verb\s+RunAs\b|\brunas\b|\bnet\s+(user|localgroup)\b|\bNew-LocalUser\b|\bAdd-LocalGroupMember\b|\bschtasks(\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b|\bNew-Service\b|\bsc(\.exe)?\s+(create|config|delete)\b/i },
  { id: "dynamic-execution", reason: "Dynamic code execution / nested encoded commands (Invoke-Expression, iex, -EncodedCommand, FromBase64String)", re: /\bInvoke-Expression\b|(^|[\s;|(&])iex(\s|$|\()|-enc(odedcommand)?\b|\bFromBase64String\b/i },
  { id: "credential-access", reason: "Credential dumping or credential store access", re: /\bmimikatz\b|\bsekurlsa\b|\blsass\b|\bcmdkey\b|\bConvertFrom-SecureString\b|\bGet-Credential\b/i },
  { id: "ownership", reason: "Taking ownership / wiping free space", re: /\btakeown\b|\bcipher(\.exe)?\s+\/w\b/i },
];

const READ_ONLY_PS = /^(Get|Test|Select|Where|Measure|Sort|Group|Format|Out-String|Resolve|ConvertTo-Json|ConvertTo-Csv|Compare|Split-Path|Join-Path)(-|$)/i;
const READ_ONLY_CMD = new Set([
  "dir", "type", "ver", "hostname", "whoami", "ipconfig", "systeminfo", "tasklist",
  "netstat", "echo", "where", "findstr", "vol", "set", "path", "date", "time",
]);

export function evaluate(shell: ShellKind, command: string, mode: ShellMode): Verdict {
  if (!command.trim()) return { allowed: false, reason: "Empty command." };
  if (mode === "unrestricted") return { allowed: true };

  if (mode === "read_only") {
    if (/[`>]|\$\(|&(?!&)|\bInvoke-|\bStart-|\bStop-|\bSet-|\bRemove-|\bNew-/i.test(command))
      return { allowed: false, reason: "read_only mode blocks redirection, subexpressions, and state-changing verbs." };
    const segments = command.split(/\||;|&&/).map((s) => s.trim()).filter(Boolean);
    for (const seg of segments) {
      const first = seg.split(/\s+/)[0] ?? "";
      const ok = shell === "powershell" ? READ_ONLY_PS.test(first) || READ_ONLY_CMD.has(first.toLowerCase())
                                        : READ_ONLY_CMD.has(first.toLowerCase());
      if (!ok)
        return { allowed: false, reason: `read_only mode: '${first}' is not on the read-only allowlist.` };
    }
    return { allowed: true };
  }

  for (const r of DENY_RULES) {
    if (r.re.test(command)) return { allowed: false, reason: `Blocked by policy rule '${r.id}': ${r.reason}.` };
  }
  return { allowed: true };
}

export function describePolicy(mode: ShellMode) {
  return {
    mode,
    note:
      mode === "standard"
        ? "Commands run as a normal (non-admin) user. Anything matching a denylist rule is rejected before execution."
        : mode === "read_only"
          ? "Only an allowlist of inspection commands (Get-*, dir, ipconfig, ...) is permitted; redirection and state-changing verbs are rejected."
          : "No command filtering is applied.",
    denylist: mode === "standard" ? DENY_RULES.map((r) => ({ id: r.id, blocks: r.reason })) : [],
  };
}

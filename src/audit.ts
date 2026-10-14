import fs from "node:fs";
import path from "node:path";

export interface AuditEvent {
  subject: string;
  tool: string;
  decision: "allowed" | "denied" | "error";
  detail?: string; // command text (truncated) or denial reason
  exit_code?: number | null;
  duration_ms?: number;
}

export class Audit {
  constructor(private file: string) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
  }
  log(e: AuditEvent) {
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      ...e,
      detail: e.detail && e.detail.length > 2000 ? e.detail.slice(0, 2000) + "…" : e.detail,
    });
    try {
      fs.appendFileSync(this.file, line + "\n");
    } catch (err) {
      console.error("[audit] write failed:", err);
    }
  }
}

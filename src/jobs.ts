import { randomUUID } from "node:crypto";
import type { Config } from "./config.js";
import type { ShellKind } from "./policy.js";
import { startShell, type ExecResult, type Running } from "./shell.js";

interface Job {
  id: string;
  shell: ShellKind;
  command: string;
  owner: string;
  started_at: string;
  running: Running;
  result?: ExecResult;
}

export class JobManager {
  private jobs = new Map<string, Job>();
  constructor(private cfg: Config) {}

  activeCount() {
    return [...this.jobs.values()].filter((j) => !j.result).length;
  }

  start(owner: string, shell: ShellKind, command: string, cwd?: string): Job | { error: string } {
    if (this.activeCount() >= this.cfg.maxJobs)
      return { error: `Too many running background jobs (max ${this.cfg.maxJobs}). Cancel or wait for one to finish.` };
    const running = startShell(this.cfg, {
      shell, command, cwd,
      timeoutMs: 60 * 60 * 1000, // hard 1h ceiling for background jobs
      maxOutputBytes: this.cfg.maxOutputBytes,
      keep: "tail",
    });
    const job: Job = { id: randomUUID().slice(0, 8), shell, command, owner, started_at: new Date().toISOString(), running };
    running.done.then((r) => (job.result = r));
    this.jobs.set(job.id, job);
    this.prune();
    return job;
  }

  get(id: string) {
    return this.jobs.get(id);
  }

  list() {
    return [...this.jobs.values()].map((j) => ({
      job_id: j.id, shell: j.shell, status: j.result ? "finished" : "running",
      started_at: j.started_at, command: j.command.slice(0, 200),
    }));
  }

  cancel(id: string) {
    const j = this.jobs.get(id);
    if (!j) return false;
    if (!j.result) j.running.kill();
    return true;
  }

  private prune() {
    const finished = [...this.jobs.values()].filter((j) => j.result);
    for (const j of finished.slice(0, Math.max(0, finished.length - 20))) this.jobs.delete(j.id);
  }
}

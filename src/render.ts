import pc from "picocolors";
import { VERSION } from "./version.js";

export function header(target: string, mode: string, surfaces: string[]) {
  console.log("");
  console.log(
    `  ${pc.bold("Brektra")}  ${pc.gray(`v${VERSION}`)}  ${mode === "safe" ? pc.green("Safe Mode") : pc.red("Aggressive")}  ${pc.gray(surfaces.join(" / "))}`,
  );
  console.log("");
  console.log(pc.gray(`  target  ${target}`));
  console.log("");
}

export function info(line: string) {
  console.log(pc.gray("*"), line);
}

export function attackFailed(name: string) {
  console.log(pc.gray("*"), `Attack: ${name}`, pc.red("[FAILED]"));
}

export function attackSuccess(name: string, firstExploitSec?: number | null) {
  const tail = firstExploitSec
    ? pc.gray(` (first exploit at ${firstExploitSec}s)`)
    : "";
  console.log(
    pc.gray("*"),
    `Attack: ${name}`,
    pc.green("[SUCCESS]"),
    tail,
  );
}

export function attackSkipped(name: string, reason: string) {
  console.log(pc.gray("*"), `Attack: ${name}`, pc.gray(`[${reason}]`));
}

export function findingProof(opts: {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  owasp?: string | null;
  excerpt?: string | null;
}) {
  if (opts.excerpt) {
    console.log("    ", pc.gray("proof   "), excerpt(opts.excerpt));
  }
  const sev = severityColor(opts.severity)(opts.severity.toUpperCase());
  const owasp = opts.owasp ? pc.gray(` OWASP ${opts.owasp}`) : "";
  console.log("    ", pc.gray("severity"), sev + owasp);
}

export function summary(opts: {
  findings: number;
  high: number;
  medium: number;
  low: number;
  durationSec: number;
  replayUrl?: string | null;
}) {
  console.log("");
  const counts = [
    `${opts.findings} findings`,
    opts.high ? pc.red(`${opts.high} high`) : null,
    opts.medium ? `${opts.medium} medium` : null,
    opts.low ? pc.gray(`${opts.low} low`) : null,
  ]
    .filter(Boolean)
    .join("  ");
  console.log(`  ${counts}  ${pc.gray("duration")} ${formatDuration(opts.durationSec)}`);
  if (opts.replayUrl) {
    console.log(`  ${pc.gray("replay  ")} ${pc.cyan(opts.replayUrl)}`);
  }
  console.log("");
}

function severityColor(sev: string) {
  if (sev === "critical" || sev === "high") return pc.red;
  if (sev === "medium") return pc.yellow;
  return pc.gray;
}

function excerpt(s: string) {
  const trimmed = s.replace(/\s+/g, " ").trim();
  return `"${trimmed.length > 80 ? trimmed.slice(0, 77) + "..." : trimmed}"`;
}

function formatDuration(sec: number) {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m === 0) return `${s}s`;
  return `${m}m ${s}s`;
}

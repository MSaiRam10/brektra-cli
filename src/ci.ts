import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { Surface } from "./api.js";
import { emitFindings, emitSummary, exitForFindings, runAndPoll } from "./scan.js";
import { sanitizeForDisplay } from "./safety.js";

const VALID_SURFACES: Surface[] = ["web", "ai", "cloud", "cicd", "mobile", "host"];

export async function runCi(rest: string[]) {
  const sub = rest[0];
  if (sub !== "scan") {
    console.error(pc.red("usage: brektra ci scan <target> [--surfaces web,ai,...] [--fail-on-severity high]"));
    process.exit(1);
  }
  const target = rest[1];
  if (!target) {
    console.error(pc.red("usage: brektra ci scan <target> [flags]"));
    process.exit(1);
  }
  // SECURITY: target shape check so control chars can't be logged or
  // forwarded; URL parse rejects javascript:/file:/etc.
  if (target.length > 2048 || /[\x00-\x1f\x7f]/.test(target)) {
    console.error(pc.red("invalid target"));
    process.exit(1);
  }
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error();
  } catch {
    console.error(pc.red("ci target must be an http(s) url"));
    process.exit(1);
  }
  const flags = parseFlags(rest.slice(2));
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";
  const surfaces = parseSurfaces(flags.surfaces);

  await requireApiKey();

  console.log(
    pc.gray("*"),
    `CI scan starting on ${pc.cyan(sanitizeForDisplay(target))}  surfaces=${surfaces.join(",")}  mode=${mode}`,
  );

  const last = await runAndPoll({ target, mode, surfaces });
  emitFindings(last);
  emitSummary(last);
  exitForFindings(last, flags);
}

function parseSurfaces(v: string | boolean | undefined): Surface[] {
  if (typeof v !== "string" || !v.trim()) return ["web", "ai"];
  const parts = v
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  for (const p of parts) {
    if (!(VALID_SURFACES as string[]).includes(p)) {
      console.error(pc.red(`unknown surface: ${p}`));
      console.error(pc.gray("surfaces: " + VALID_SURFACES.join(", ")));
      process.exit(1);
    }
  }
  return parts as Surface[];
}

function parseFlags(rest: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a) continue;
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const next = rest[i + 1];
      if (next && !next.startsWith("--")) {
        out[k] = next;
        i++;
      } else {
        out[k] = true;
      }
    }
  }
  return out;
}

import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { startAtlasRun, getCiScan } from "./api.js";
import * as r from "./render.js";
import { sanitizeForDisplay } from "./safety.js";

export async function runAtlas(slug: string, flags: Record<string, string | boolean>) {
  const target = typeof flags.target === "string" ? flags.target : null;
  if (!target) {
    console.error(pc.red("--target required for atlas runs"));
    process.exit(1);
  }
  // SECURITY: validate slug + target shape so they can't smuggle control
  // chars into log output or non-http schemes into the backend.
  if (!/^[A-Za-z0-9_\-]{1,128}$/.test(slug)) {
    console.error(pc.red("invalid pattern slug"));
    process.exit(1);
  }
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad scheme");
  } catch {
    console.error(pc.red("--target must be an http(s) url"));
    process.exit(1);
  }
  await requireApiKey();
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";

  r.header(sanitizeForDisplay(target), mode, ["ai"]);
  r.info(`Running Atlas pattern: ${pc.cyan(slug)}`);

  let scan;
  try {
    scan = await startAtlasRun({ pattern_slug: slug, target, mode });
  } catch (e) {
    console.error(pc.red("atlas run failed:"), (e as Error).message);
    process.exit(1);
  }

  const start = Date.now();
  let last = scan;
  while (last.status !== "complete" && last.status !== "failed") {
    await sleep(3000);
    try {
      last = await getCiScan(scan.id);
    } catch {
      // transient errors during polling, ignored
    }
  }

  for (const f of last.findings ?? []) {
    const title = sanitizeForDisplay(f.title);
    const cat = sanitizeForDisplay(f.category);
    r.attackSuccess(title);
    r.findingProof({ title, severity: f.severity, owasp: cat });
  }
  r.summary({
    findings: last.findings?.length ?? 0,
    high: (last.findings ?? []).filter((f) => f.severity === "high" || f.severity === "critical").length,
    medium: (last.findings ?? []).filter((f) => f.severity === "medium").length,
    low: (last.findings ?? []).filter((f) => f.severity === "low" || f.severity === "info").length,
    durationSec: last.duration_seconds ?? Math.round((Date.now() - start) / 1000),
    replayUrl: last.replay_url,
  });
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

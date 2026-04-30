import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { startAtlasRun, getCiScan } from "./api.js";
import * as r from "./render.js";

export async function runAtlas(slug: string, flags: Record<string, string | boolean>) {
  const target = typeof flags.target === "string" ? flags.target : null;
  if (!target) {
    console.error(pc.red("--target required for atlas runs"));
    process.exit(1);
  }
  await requireApiKey();
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";

  r.header(target, mode, ["ai"]);
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
    r.attackSuccess(f.title);
    r.findingProof({ title: f.title, severity: f.severity, owasp: f.category });
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

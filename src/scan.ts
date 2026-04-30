import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { getCiScan, startCiScan } from "./api.js";
import * as r from "./render.js";
import { runLocalScan } from "./local-scan.js";

export async function runScan(target: string, flags: Record<string, string | boolean>) {
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";
  const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/.test(target);

  if (isLocal) {
    // localhost runs don't touch our cloud at all. no auth.
    await runLocalScan(target, mode);
    return;
  }

  const apiKey = await requireApiKey();
  if (!apiKey) return;

  r.header(target, mode, ["ai"]);
  r.info("Starting cloud scan");

  let scan;
  try {
    scan = await startCiScan({ target, mode, surfaces: ["ai"] });
  } catch (e) {
    console.error(pc.red("could not start scan:"), (e as Error).message);
    process.exit(1);
  }

  // poll until complete or timeout
  const start = Date.now();
  const timeoutMs = 10 * 60 * 1000;
  let last: typeof scan = scan;
  while (last.status !== "complete" && last.status !== "failed") {
    if (Date.now() - start > timeoutMs) {
      console.error(pc.red("timed out waiting for scan"));
      process.exit(1);
    }
    await sleep(3000);
    try {
      last = await getCiScan(scan.id);
    } catch {
      // transient errors are fine, just keep polling
    }
  }

  for (const f of last.findings ?? []) {
    r.attackSuccess(f.title);
    r.findingProof({
      title: f.title,
      severity: f.severity,
      owasp: f.category.startsWith("LLM") || f.category.startsWith("A0") ? f.category : null,
    });
  }

  const sevs = (last.findings ?? []).reduce<{ high: number; medium: number; low: number }>(
    (acc, f) => {
      if (f.severity === "high" || f.severity === "critical") acc.high++;
      else if (f.severity === "medium") acc.medium++;
      else acc.low++;
      return acc;
    },
    { high: 0, medium: 0, low: 0 },
  );
  r.summary({
    findings: last.findings_count ?? last.findings?.length ?? 0,
    high: sevs.high,
    medium: sevs.medium,
    low: sevs.low,
    durationSec: last.duration_seconds ?? Math.round((Date.now() - start) / 1000),
    replayUrl: last.replay_url,
  });

  if ((last.findings_count ?? 0) > 0 || (last.exploits_confirmed ?? 0) > 0) {
    process.exit(2);
  }
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

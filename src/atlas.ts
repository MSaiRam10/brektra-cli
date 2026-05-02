import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { startAtlasRun, getCiScan } from "./api.js";
import * as r from "./render.js";
import { sanitizeForDisplay, stripUserInfo } from "./safety.js";

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
    if (u.username || u.password) {
      // SECURITY: refuse userinfo to avoid leaking embedded creds.
      throw new Error("userinfo in target");
    }
  } catch {
    console.error(pc.red("--target must be an http(s) url with no userinfo"));
    process.exit(1);
  }
  const cleanTarget = stripUserInfo(target);
  await requireApiKey();
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";

  r.header(sanitizeForDisplay(cleanTarget), mode, ["ai"]);
  r.info(`Running Atlas pattern: ${pc.cyan(slug)}`);

  let scan;
  try {
    // SECURITY: forward the cleaned target (userinfo stripped) so any
    // embedded creds never reach the backend payload.
    scan = await startAtlasRun({ pattern_slug: slug, target: cleanTarget, mode });
  } catch (e) {
    console.error(pc.red("atlas run failed:"), (e as Error).message);
    process.exit(1);
  }

  const start = Date.now();
  // SECURITY: poll with a hard timeout so we don't loop forever on a
  // backend that wedges with status "running" or returns persistent 4xx.
  const POLL_TIMEOUT_MS = 15 * 60 * 1000;
  let last = scan;
  while (last.status !== "complete" && last.status !== "failed") {
    if (Date.now() - start > POLL_TIMEOUT_MS) {
      console.error(pc.red("timed out waiting for atlas run"));
      process.exit(1);
    }
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

  // SECURITY: validate server-supplied replay url before printing.
  let safeReplay: string | undefined;
  if (last.replay_url) {
    try {
      const u = new URL(last.replay_url);
      if (u.protocol === "http:" || u.protocol === "https:") {
        safeReplay = sanitizeForDisplay(u.toString());
      }
    } catch {
      /* drop */
    }
  }

  r.summary({
    findings: last.findings?.length ?? 0,
    high: (last.findings ?? []).filter((f) => f.severity === "high" || f.severity === "critical").length,
    medium: (last.findings ?? []).filter((f) => f.severity === "medium").length,
    low: (last.findings ?? []).filter((f) => f.severity === "low" || f.severity === "info").length,
    durationSec: last.duration_seconds ?? Math.round((Date.now() - start) / 1000),
    replayUrl: safeReplay,
  });
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

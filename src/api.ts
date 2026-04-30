import { apiBase, loadConfig } from "./config.js";

export interface CiScanResponse {
  id: string;
  status: string;
  findings_count?: number;
  exploits_confirmed?: number;
  duration_seconds?: number;
  replay_url?: string;
  findings?: Array<{
    id: string;
    title: string;
    severity: "info" | "low" | "medium" | "high" | "critical";
    category: string;
  }>;
}

async function authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const cfg = await loadConfig();
  const headers = new Headers(init.headers);
  if (cfg.api_key) headers.set("authorization", `Bearer ${cfg.api_key}`);
  if (!headers.has("content-type") && init.body) {
    headers.set("content-type", "application/json");
  }
  return fetch(`${apiBase(cfg)}${path}`, { ...init, headers });
}

export async function startCiScan(opts: {
  target: string;
  mode: "safe" | "aggressive";
  surfaces: string[];
}): Promise<CiScanResponse> {
  const r = await authedFetch("/api/v1/scans/ci", {
    method: "POST",
    body: JSON.stringify(opts),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`startCiScan ${r.status}: ${t || r.statusText}`);
  }
  return (await r.json()) as CiScanResponse;
}

export async function getCiScan(id: string): Promise<CiScanResponse> {
  const r = await authedFetch(`/api/v1/scans/ci/${id}`);
  if (!r.ok) throw new Error(`getCiScan ${r.status}`);
  return (await r.json()) as CiScanResponse;
}

export async function startAtlasRun(opts: {
  pattern_slug: string;
  target: string;
  mode: "safe" | "aggressive";
}): Promise<CiScanResponse> {
  // we reuse the ci scan endpoint with a pattern hint until /api/v1/atlas/run lands
  const r = await authedFetch("/api/v1/scans/ci", {
    method: "POST",
    body: JSON.stringify({
      target: opts.target,
      mode: opts.mode,
      surfaces: ["ai"],
      atlas_pattern_slug: opts.pattern_slug,
    }),
  });
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`atlas run ${r.status}: ${t || r.statusText}`);
  }
  return (await r.json()) as CiScanResponse;
}

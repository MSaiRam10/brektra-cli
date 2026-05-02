import { apiBase, loadConfig } from "./config.js";
import { MAX_ARTIFACT_BYTES, redactErrorBody, validateArtifactPath } from "./safety.js";

export type Surface = "web" | "ai" | "cloud" | "cicd" | "mobile" | "host";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  cvss?: number;
  epss?: number;
  composite?: number;
}

export interface CiScanResponse {
  id: string;
  status: string;
  findings_count?: number;
  exploits_confirmed?: number;
  duration_seconds?: number;
  replay_url?: string;
  findings?: Finding[];
}

export interface ScanStartOpts {
  target: string;
  mode: "safe" | "aggressive";
  surfaces: Surface[];
  // surface-specific options forwarded as-is to the backend
  options?: Record<string, unknown>;
  atlas_pattern_slug?: string;
  // path to a local artifact (mobile APK/IPA) once uploaded
  artifact_id?: string;
}

export interface AgentSummary {
  id: string;
  name: string;
  version: string;
  status: "online" | "offline" | "degraded";
  capabilities: string[];
  last_seen: string;
}

export interface AgentUpdate {
  agent_id: string;
  current_version: string;
  available_version: string;
  channel: "stable" | "beta";
}

export interface EngineSummary {
  id: string;
  name: string;
  version: string;
  surfaces: Surface[];
  status: "online" | "offline" | "degraded";
  modules: number;
}

export interface Playbook {
  finding_id: string;
  title: string;
  steps: { title: string; body: string }[];
  references: { label: string; url: string }[];
}

export interface ComplianceExport {
  id: string;
  framework: string;
  status: "queued" | "running" | "complete" | "failed";
  download_url?: string;
}

async function authedFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const cfg = await loadConfig();
  const headers = new Headers(init.headers);
  if (cfg.api_key) headers.set("authorization", `Bearer ${cfg.api_key}`);
  if (!headers.has("content-type") && init.body) {
    headers.set("content-type", "application/json");
  }
  // apiBase() validates the destination scheme/host so the bearer token
  // can't be sent to javascript:/file:/data: or plain http:// non-loopback.
  return fetch(`${apiBase(cfg)}${path}`, {
    ...init,
    headers,
    // 60s default per HTTP request — prevents indefinite hangs leaking
    // process resources and gives polling loops a predictable timeout.
    signal: init.signal ?? AbortSignal.timeout(60_000),
  });
}

async function jsonOrThrow<T>(label: string, r: Response): Promise<T> {
  if (!r.ok) {
    // SECURITY: server error bodies can echo request headers (including
    // Authorization) or PII. Redact bearer-shaped tokens and truncate.
    const raw = await r.text().catch(() => "");
    throw new Error(`${label} ${r.status}: ${redactErrorBody(raw) || r.statusText}`);
  }
  return (await r.json()) as T;
}

export async function startCiScan(opts: ScanStartOpts): Promise<CiScanResponse> {
  return jsonOrThrow(
    "startCiScan",
    await authedFetch("/api/v1/scans/ci", {
      method: "POST",
      body: JSON.stringify(opts),
    }),
  );
}

export async function getCiScan(id: string): Promise<CiScanResponse> {
  return jsonOrThrow("getCiScan", await authedFetch(`/api/v1/scans/ci/${id}`));
}

export async function startAtlasRun(opts: {
  pattern_slug: string;
  target: string;
  mode: "safe" | "aggressive";
}): Promise<CiScanResponse> {
  return startCiScan({
    target: opts.target,
    mode: opts.mode,
    surfaces: ["ai"],
    atlas_pattern_slug: opts.pattern_slug,
  });
}

export async function uploadMobileArtifact(filePath: string): Promise<{ artifact_id: string }> {
  validateArtifactPath(filePath);
  const { promises: fs } = await import("node:fs");
  const { basename } = await import("node:path");

  // SECURITY: refuse symlinks (avoid the user accidentally pointing at a
  // symlink whose target is a sensitive file like ~/.aws/credentials)
  // and enforce a hard size cap so a typo can't read & ship a 50GB file.
  const st = await fs.lstat(filePath);
  if (st.isSymbolicLink()) {
    throw new Error("refusing to upload a symlink as a mobile artifact");
  }
  if (!st.isFile()) {
    throw new Error("mobile artifact path is not a regular file");
  }
  if (st.size > MAX_ARTIFACT_BYTES) {
    throw new Error(
      `mobile artifact too large: ${st.size} bytes (max ${MAX_ARTIFACT_BYTES})`,
    );
  }

  const buf = await fs.readFile(filePath);
  const blob = new Blob([new Uint8Array(buf)]);
  const form = new FormData();
  form.append("file", blob, basename(filePath));
  const cfg = await loadConfig();
  const headers = new Headers();
  if (cfg.api_key) headers.set("authorization", `Bearer ${cfg.api_key}`);
  // apiBase() asserts https:// for non-loopback hosts before we ship the
  // artifact + bearer over the network.
  const r = await fetch(`${apiBase(cfg)}/api/v1/artifacts/mobile`, {
    method: "POST",
    body: form,
    headers,
    signal: AbortSignal.timeout(10 * 60 * 1000),
  });
  return jsonOrThrow("uploadMobileArtifact", r);
}

export async function listAgents(): Promise<AgentSummary[]> {
  const res = await jsonOrThrow<{ agents: AgentSummary[] }>(
    "listAgents",
    await authedFetch("/api/v1/agents"),
  );
  return res.agents;
}

export async function listAgentUpdates(): Promise<AgentUpdate[]> {
  const res = await jsonOrThrow<{ updates: AgentUpdate[] }>(
    "listAgentUpdates",
    await authedFetch("/api/v1/agents/updates"),
  );
  return res.updates;
}

export async function listEngines(): Promise<EngineSummary[]> {
  const res = await jsonOrThrow<{ engines: EngineSummary[] }>(
    "listEngines",
    await authedFetch("/api/v1/engines"),
  );
  return res.engines;
}

export async function getPlaybook(findingId: string): Promise<Playbook> {
  return jsonOrThrow("getPlaybook", await authedFetch(`/api/v1/findings/${findingId}/playbook`));
}

export async function startComplianceExport(framework: string): Promise<ComplianceExport> {
  return jsonOrThrow(
    "startComplianceExport",
    await authedFetch(`/api/v1/compliance/exports`, {
      method: "POST",
      body: JSON.stringify({ framework }),
    }),
  );
}

export async function getComplianceExport(id: string): Promise<ComplianceExport> {
  return jsonOrThrow("getComplianceExport", await authedFetch(`/api/v1/compliance/exports/${id}`));
}

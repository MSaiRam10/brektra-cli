import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import {
  CiScanResponse,
  Finding,
  ScanStartOpts,
  Severity,
  Surface,
  getCiScan,
  startCiScan,
  uploadMobileArtifact,
} from "./api.js";
import * as r from "./render.js";
import { runLocalScan } from "./local-scan.js";

type Flags = Record<string, string | boolean>;

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const VALID_SURFACES: Surface[] = ["web", "ai", "cloud", "cicd", "mobile", "host"];

export async function runScanCommand(rest: string[]) {
  const first = rest[0];
  if (!first) {
    console.error(pc.red("usage: brektra scan <surface> <target>  (surfaces: " + VALID_SURFACES.join(", ") + ")"));
    process.exit(1);
  }

  // legacy form: `brektra scan https://example.com` is treated as a web scan
  if (/^https?:\/\//i.test(first)) {
    await dispatch("web", first, parseFlags(rest.slice(1)));
    return;
  }

  if (!(VALID_SURFACES as string[]).includes(first)) {
    console.error(pc.red(`unknown surface: ${first}`));
    console.error(pc.gray("surfaces: " + VALID_SURFACES.join(", ")));
    process.exit(1);
  }

  const surface = first as Surface;
  const target = rest[1];
  if (!target) {
    console.error(pc.red(`usage: brektra scan ${surface} <target>`));
    process.exit(1);
  }
  await dispatch(surface, target, parseFlags(rest.slice(2)));
}

async function dispatch(surface: Surface, target: string, flags: Flags) {
  const mode = (flags.mode === "aggressive" ? "aggressive" : "safe") as "safe" | "aggressive";

  if (surface === "web" && /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(target)) {
    await runLocalScan(target, mode);
    return;
  }

  const apiKey = await requireApiKey();
  if (!apiKey) return;

  const options = collectSurfaceOptions(surface, flags);

  let resolvedTarget = target;
  let artifactId: string | undefined;
  if (surface === "mobile") {
    r.info(`Uploading ${pc.cyan(target)} for static analysis`);
    try {
      const up = await uploadMobileArtifact(target);
      artifactId = up.artifact_id;
      resolvedTarget = `mobile://${artifactId}`;
    } catch (e) {
      console.error(pc.red("upload failed:"), (e as Error).message);
      process.exit(1);
    }
  }

  r.header(resolvedTarget, mode, [surface]);
  r.info(`Starting ${surface} scan`);

  const startOpts: ScanStartOpts = {
    target: resolvedTarget,
    mode,
    surfaces: [surface],
    options,
  };
  if (artifactId) startOpts.artifact_id = artifactId;

  const last = await runAndPoll(startOpts);
  emitFindings(last);
  emitSummary(last);
  exitForFindings(last, flags);
}

function collectSurfaceOptions(surface: Surface, flags: Flags): Record<string, unknown> {
  const opts: Record<string, unknown> = {};

  if (surface === "ai") {
    const enabled: string[] = [];
    if (flags.crescendo) enabled.push("crescendo");
    if (flags["skeleton-key"]) enabled.push("skeleton-key");
    if (flags.multimodal) enabled.push("multimodal");
    if (flags.gcg) enabled.push("gcg");
    if (flags.pair) enabled.push("pair");
    if (flags.tap) enabled.push("tap");
    if (enabled.length) opts.attacks = enabled;
  }

  if (surface === "cloud") {
    if (typeof flags["aws-profile"] === "string") opts.aws_profile = flags["aws-profile"];
    if (typeof flags["gcp-creds"] === "string") opts.gcp_creds = flags["gcp-creds"];
    if (typeof flags["azure-sub"] === "string") opts.azure_subscription = flags["azure-sub"];
    if (typeof flags["k8s-config"] === "string") opts.k8s_config = flags["k8s-config"];
  }

  if (surface === "cicd") {
    if (typeof flags["github-token"] === "string") opts.github_token = flags["github-token"];
    if (typeof flags["gitlab-token"] === "string") opts.gitlab_token = flags["gitlab-token"];
    if (typeof flags["jenkins-url"] === "string") opts.jenkins_url = flags["jenkins-url"];
  }

  if (surface === "web") {
    const enabled: string[] = [];
    for (const k of ["dom-xss", "ssti", "nosql", "ldap", "xxe", "oauth", "jwt", "graphql"]) {
      if (flags[k]) enabled.push(k);
    }
    if (enabled.length) opts.attacks = enabled;
  }

  return opts;
}

export async function runAndPoll(opts: ScanStartOpts): Promise<CiScanResponse> {
  let scan: CiScanResponse;
  try {
    scan = await startCiScan(opts);
  } catch (e) {
    console.error(pc.red("could not start scan:"), (e as Error).message);
    process.exit(1);
  }

  const start = Date.now();
  const timeoutMs = 15 * 60 * 1000;
  let last = scan;
  while (last.status !== "complete" && last.status !== "failed") {
    if (Date.now() - start > timeoutMs) {
      console.error(pc.red("timed out waiting for scan"));
      process.exit(1);
    }
    await sleep(3000);
    try {
      last = await getCiScan(scan.id);
    } catch {
      // transient errors during polling, ignored
    }
  }
  return last;
}

export function emitFindings(last: CiScanResponse) {
  for (const f of last.findings ?? []) {
    r.attackSuccess(f.title);
    r.findingProof({
      title: f.title,
      severity: f.severity,
      owasp: f.category.startsWith("LLM") || f.category.startsWith("A0") ? f.category : null,
    });
  }
}

export function emitSummary(last: CiScanResponse, startMs?: number) {
  const sevs = (last.findings ?? []).reduce(
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
    durationSec:
      last.duration_seconds ?? (startMs ? Math.round((Date.now() - startMs) / 1000) : 0),
    replayUrl: last.replay_url,
  });
}

export function exitForFindings(last: CiScanResponse, flags: Flags) {
  const threshold = parseSeverityThreshold(flags["fail-on-severity"]);
  if (threshold !== null) {
    const breached = (last.findings ?? []).some(
      (f: Finding) => SEVERITY_RANK[f.severity] >= threshold,
    );
    if (breached) process.exit(2);
    return;
  }
  if ((last.findings_count ?? 0) > 0 || (last.exploits_confirmed ?? 0) > 0) {
    process.exit(2);
  }
}

function parseSeverityThreshold(v: string | boolean | undefined): number | null {
  if (typeof v !== "string") return null;
  const k = v.toLowerCase() as Severity;
  if (k in SEVERITY_RANK) return SEVERITY_RANK[k];
  console.error(pc.red(`invalid --fail-on-severity: ${v} (use info|low|medium|high|critical)`));
  process.exit(1);
}

function parseFlags(rest: string[]): Flags {
  const out: Flags = {};
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

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

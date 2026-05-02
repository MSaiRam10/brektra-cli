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
import {
  parseFlagsSafe,
  sanitizeForDisplay,
  stripUserInfo,
  validateBearerLike,
  validateOpaqueArg,
} from "./safety.js";

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

  // legacy form: `brektra scan https://example.com` is treated as a web scan.
  // SECURITY: must validate the target on this branch too — without
  // this, control chars / userinfo would otherwise bypass the per-surface
  // checks that the explicit form runs.
  if (/^https?:\/\//i.test(first)) {
    try {
      validateTarget("web", first);
    } catch (e) {
      console.error(pc.red((e as Error).message));
      process.exit(1);
    }
    await dispatch("web", first, parseFlagsSafe(rest.slice(1)));
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
  // SECURITY: validate target shape per surface so we don't pass control
  // characters or hostile schemes through to logging or to the backend.
  try {
    validateTarget(surface, target);
  } catch (e) {
    console.error(pc.red((e as Error).message));
    process.exit(1);
  }
  await dispatch(surface, target, parseFlagsSafe(rest.slice(2)));
}

function validateTarget(surface: Surface, target: string): void {
  if (target.length > 2048) throw new Error("target too long");
  if (/[\x00-\x1f\x7f]/.test(target)) {
    // newlines/control chars in a logged target enable terminal-injection
    // and log forging. reject before display.
    throw new Error("target contains control characters");
  }
  if (surface === "web" || surface === "ai") {
    if (!/^https?:\/\//i.test(target)) throw new Error(`${surface} target must be an http(s) url`);
    // delegate full parse to URL — throws on malformed input
    const u = new URL(target);
    // SECURITY: refuse userinfo in the target. http://user:pass@host
    // would otherwise leak embedded creds to the backend payload, to
    // logs, and to the OS shell handler if ever passed to open().
    if (u.username || u.password) {
      throw new Error("target must not contain userinfo (user:pass@); pass credentials separately");
    }
    return;
  }
  if (surface === "host") {
    // accept CIDR, ip, or hostname. strict charset.
    if (!/^[A-Za-z0-9.:_\-/]{1,256}$/.test(target)) {
      throw new Error("host target must be an ip, hostname, or cidr");
    }
    return;
  }
  if (surface === "cloud") {
    if (!/^(aws|gcp|azure|k8s)$/.test(target)) {
      throw new Error("cloud provider must be one of: aws, gcp, azure, k8s");
    }
    return;
  }
  if (surface === "cicd") {
    if (!/^(github|gitlab|circleci|jenkins|bitbucket|azure-devops)$/.test(target)) {
      throw new Error("cicd platform must be one of: github, gitlab, circleci, jenkins, bitbucket, azure-devops");
    }
    return;
  }
  if (surface === "mobile") {
    // SECURITY: anchored regex (the previous unanchored form silently
    // accepted any input). Path validation also happens at upload time.
    if (!/^[A-Za-z0-9._\-/\\: ]{1,1024}$/.test(target)) {
      throw new Error("invalid mobile artifact path");
    }
    return;
  }
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

  // SECURITY: strip any userinfo (user:pass@) from the forwarded/displayed
  // target so embedded creds don't leak to backend body, console, or logs.
  let resolvedTarget = stripUserInfo(target);
  let artifactId: string | undefined;
  if (surface === "mobile") {
    r.info(`Uploading ${pc.cyan(sanitizeForDisplay(resolvedTarget))} for static analysis`);
    try {
      const up = await uploadMobileArtifact(target);
      // SECURITY: shape-check the artifact id returned by the server
      // before embedding it in the resolvedTarget the rest of the flow
      // logs and forwards.
      if (!/^[A-Za-z0-9_\-]{1,128}$/.test(up.artifact_id)) {
        throw new Error("server returned invalid artifact id");
      }
      artifactId = up.artifact_id;
      resolvedTarget = `mobile://${artifactId}`;
    } catch (e) {
      console.error(pc.red("upload failed:"), (e as Error).message);
      process.exit(1);
    }
  }

  // sanitize before display: a hostile target with embedded \r\n would
  // otherwise inject forged log lines into the user's terminal.
  r.header(sanitizeForDisplay(resolvedTarget), mode, [surface]);
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
    // SECURITY: validate length and reject control characters before
    // forwarding to the backend / printing locally (log forge, term inj).
    if (typeof flags["aws-profile"] === "string") {
      opts.aws_profile = validateOpaqueArg("--aws-profile", flags["aws-profile"], 256);
    }
    if (typeof flags["gcp-creds"] === "string") {
      opts.gcp_creds = validateOpaqueArg("--gcp-creds", flags["gcp-creds"]);
    }
    if (typeof flags["azure-sub"] === "string") {
      opts.azure_subscription = validateOpaqueArg("--azure-sub", flags["azure-sub"], 128);
    }
    if (typeof flags["k8s-config"] === "string") {
      opts.k8s_config = validateOpaqueArg("--k8s-config", flags["k8s-config"]);
    }
  }

  if (surface === "cicd") {
    // SECURITY: bearer-shape validate, and warn that argv-supplied tokens
    // are visible in process listings — recommend env var passthrough.
    if (typeof flags["github-token"] === "string") {
      warnArgvSecret("--github-token");
      opts.github_token = validateBearerLike("github-token", flags["github-token"]);
    }
    if (typeof flags["gitlab-token"] === "string") {
      warnArgvSecret("--gitlab-token");
      opts.gitlab_token = validateBearerLike("gitlab-token", flags["gitlab-token"]);
    }
    if (typeof flags["jenkins-url"] === "string") {
      // SECURITY: parse, require http(s), strip embedded user:pass so
      // the URL we forward to the backend / display in logs cannot
      // carry credentials.
      const u = new URL(flags["jenkins-url"]);
      if (u.protocol !== "http:" && u.protocol !== "https:") {
        throw new Error("--jenkins-url must be http(s)");
      }
      if (u.username || u.password) {
        u.username = "";
        u.password = "";
      }
      opts.jenkins_url = u.toString();
    }
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
    // server-supplied finding fields are escaped before display — see
    // playbooks.ts for the same rationale (terminal/ANSI injection).
    const title = sanitizeForDisplay(f.title);
    const cat = sanitizeForDisplay(f.category);
    r.attackSuccess(title);
    r.findingProof({
      title,
      severity: f.severity,
      owasp: cat.startsWith("LLM") || cat.startsWith("A0") ? cat : null,
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
  // Replay URL is server-controlled. Validate it as http(s) before
  // printing so a poisoned response can't trick the user into pasting a
  // javascript:/file: url into their browser.
  let safeReplay: string | null | undefined = last.replay_url;
  if (safeReplay) {
    try {
      const u = new URL(safeReplay);
      if (u.protocol !== "http:" && u.protocol !== "https:") safeReplay = null;
    } catch {
      safeReplay = null;
    }
  }
  r.summary({
    findings: last.findings_count ?? last.findings?.length ?? 0,
    high: sevs.high,
    medium: sevs.medium,
    low: sevs.low,
    durationSec:
      last.duration_seconds ?? (startMs ? Math.round((Date.now() - startMs) / 1000) : 0),
    replayUrl: safeReplay ? sanitizeForDisplay(safeReplay) : undefined,
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

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

let warnedAboutArgv = false;
function warnArgvSecret(flag: string): void {
  // Tokens passed on the command line are visible to anything reading
  // /proc/<pid>/cmdline, ps, Windows Task Manager, parent shell history,
  // and any process snapshot. We can't unleak it, but we can warn once.
  if (warnedAboutArgv) return;
  warnedAboutArgv = true;
  console.warn(
    pc.yellow(
      `warning: secret passed on argv via ${flag} is visible in process listings; prefer piping via env or stdin`,
    ),
  );
}

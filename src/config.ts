import { promises as fs, constants as fsc } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { assertSafeApiBase, parseConfigSafely } from "./safety.js";

const CFG_DIR = join(homedir(), ".brektra");
const CFG_PATH = join(CFG_DIR, "config.json");
const DEFAULT_BASE = "https://brektra.com";

export interface Cfg {
  api_key?: string;
  api_url?: string;
}

export async function loadConfig(): Promise<Cfg> {
  let raw: string;
  try {
    raw = await fs.readFile(CFG_PATH, "utf8");
  } catch {
    return {};
  }
  // SECURITY: hostile config could include __proto__ keys that pollute
  // Object.prototype. parseConfigSafely strips them via a JSON reviver
  // and copies only the expected scalar fields.
  return parseConfigSafely(raw);
}

export async function saveConfig(cfg: Cfg): Promise<void> {
  await fs.mkdir(CFG_DIR, { recursive: true, mode: platform() === "win32" ? undefined : 0o700 });

  // SECURITY: build the payload from only the expected, scalar fields
  // — never serialize whatever shape `cfg` happens to have, in case a
  // caller passes an object with extra/dangerous keys.
  const sanitized: Cfg = {};
  if (typeof cfg.api_key === "string") sanitized.api_key = cfg.api_key;
  if (typeof cfg.api_url === "string") sanitized.api_url = cfg.api_url;
  const payload = JSON.stringify(sanitized, null, 2);

  // SECURITY: writeFile honors `mode` only on file creation. To avoid
  // leaving a pre-existing world-readable config in place, write to a
  // temp file with strict mode, then atomically rename over the target.
  // Atomic rename also avoids partial-write corruption on crash.
  const tmpName = `config.json.${randomBytes(8).toString("hex")}.tmp`;
  const tmp = join(CFG_DIR, tmpName);
  // Use fs.open with O_CREAT|O_EXCL|O_WRONLY so we get a fresh file with
  // strict mode — no pre-existing TOCTOU on the path.
  const fh = await fs.open(tmp, fsc.O_CREAT | fsc.O_EXCL | fsc.O_WRONLY, 0o600);
  try {
    await fh.writeFile(payload);
    if (platform() !== "win32") await fh.chmod(0o600);
  } finally {
    await fh.close();
  }
  await fs.rename(tmp, CFG_PATH);
}

export function apiBase(cfg: Cfg): string {
  // SECURITY: validate the configured/env api base before any code uses
  // it as a destination for credentials. Refuses non-http(s) schemes
  // and refuses plain http:// to non-loopback hosts so bearer tokens
  // can't be sent in cleartext over the wire.
  const raw = cfg.api_url ?? process.env.BREKTRA_API_URL ?? DEFAULT_BASE;
  const u = assertSafeApiBase(raw);
  // strip any trailing slash so callers can do `${apiBase}${path}`
  return u.toString().replace(/\/$/, "");
}

export function isCustomApiBase(cfg: Cfg): boolean {
  // True when the user has overridden the default base — the login()
  // browser-auto-open uses this to decide whether to refuse to launch
  // (anti-phishing: a poisoned base would otherwise host a fake
  // api-keys page that the user pastes their real key into).
  const raw = cfg.api_url ?? process.env.BREKTRA_API_URL;
  if (!raw) return false;
  try {
    return new URL(raw).toString() !== new URL(DEFAULT_BASE).toString();
  } catch {
    return true;
  }
}


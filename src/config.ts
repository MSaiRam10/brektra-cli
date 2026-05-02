import { promises as fs } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { assertSafeApiBase } from "./safety.js";

const CFG_DIR = join(homedir(), ".brektra");
const CFG_PATH = join(CFG_DIR, "config.json");
const DEFAULT_BASE = "https://brektra.com";

export interface Cfg {
  api_key?: string;
  api_url?: string;
}

export async function loadConfig(): Promise<Cfg> {
  try {
    const raw = await fs.readFile(CFG_PATH, "utf8");
    return JSON.parse(raw) as Cfg;
  } catch {
    return {};
  }
}

export async function saveConfig(cfg: Cfg): Promise<void> {
  // mode 0o600 is honored on POSIX. Windows ignores the bit but
  // %USERPROFILE%\.brektra inherits the user's ACL by default which is
  // already user-only. We make the directory restrictive on POSIX too.
  await fs.mkdir(CFG_DIR, { recursive: true, mode: platform() === "win32" ? undefined : 0o700 });
  await fs.writeFile(CFG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
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

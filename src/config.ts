import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CFG_DIR = join(homedir(), ".brektra");
const CFG_PATH = join(CFG_DIR, "config.json");

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
  await fs.mkdir(CFG_DIR, { recursive: true });
  await fs.writeFile(CFG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

export function apiBase(cfg: Cfg): string {
  return cfg.api_url ?? process.env.BREKTRA_API_URL ?? "https://brektra.com";
}

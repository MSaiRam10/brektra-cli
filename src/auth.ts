import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import open from "open";
import pc from "picocolors";
import { apiBase, loadConfig, saveConfig } from "./config.js";

export async function login() {
  const cfg = await loadConfig();
  const url = `${apiBase(cfg)}/settings/api-keys?cli=1`;
  console.log(pc.gray("opening"), pc.cyan(url));
  // some headless terminals won't open; ignore that, the user can copy-paste
  open(url).catch(() => undefined);
  const rl = readline.createInterface({ input, output });
  const key = (await rl.question("paste your api key: ")).trim();
  rl.close();
  if (!key.startsWith("bk_")) {
    console.error(pc.red("that doesn't look right. keys start with bk_"));
    process.exit(1);
  }
  await saveConfig({ ...cfg, api_key: key });
  console.log(pc.green("ok, logged in"));
}

export async function requireApiKey(): Promise<string> {
  const cfg = await loadConfig();
  if (!cfg.api_key) {
    console.error(pc.red("not logged in. run: brektra login"));
    process.exit(1);
  }
  return cfg.api_key;
}

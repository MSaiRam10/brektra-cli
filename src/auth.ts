import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import open from "open";
import pc from "picocolors";
import { apiBase, isCustomApiBase, loadConfig, saveConfig } from "./config.js";
import { assertSafeOpenUrl, validateApiKey } from "./safety.js";

export async function login() {
  const cfg = await loadConfig();
  const url = assertSafeOpenUrl(`${apiBase(cfg)}/settings/api-keys?cli=1`);

  // SECURITY: anti-phishing — if the api base has been overridden via
  // config or BREKTRA_API_URL, do NOT auto-open the browser. A poisoned
  // base (https://evil.com) would otherwise host a fake api-keys page
  // and the user would paste a real bk_ key into it. Print the URL and
  // require the user to make the explicit decision to visit it.
  if (isCustomApiBase(cfg)) {
    console.log(pc.yellow("warning: custom api base in use; refusing to auto-open browser"));
    console.log(pc.gray("if you trust this base, open manually:"), pc.cyan(url));
  } else {
    console.log(pc.gray("opening"), pc.cyan(url));
    // some headless terminals won't open; ignore that, the user can copy-paste
    open(url).catch(() => undefined);
  }

  // SECURITY: prompt for the key with echo disabled so the secret never
  // hits terminal scrollback or screenshare/recording.
  const key = (await silentPrompt("paste your api key: ")).trim();

  try {
    validateApiKey(key);
  } catch (e) {
    // never echo the key back, even on validation failure
    console.error(pc.red((e as Error).message));
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
  try {
    return validateApiKey(cfg.api_key);
  } catch (e) {
    // a malformed key on disk is itself a problem (file tampering, copy
    // paste error). never echo the value, only the shape.
    console.error(pc.red("api key in ~/.brektra/config.json is invalid:"), (e as Error).message);
    process.exit(1);
  }
}

// SECURITY: cap the buffer at the configured max api-key length so a
// pasted megabyte of garbage can't grow process memory unbounded.
const SILENT_PROMPT_MAX = 512;

async function silentPrompt(question: string): Promise<string> {
  // Best-effort no-echo prompt. On a TTY we toggle raw mode so keystrokes
  // aren't echoed; off-TTY (CI piped stdin) we fall back to readline.
  const isTTY = (input as unknown as { isTTY?: boolean }).isTTY === true;
  if (!isTTY) {
    const rl = readline.createInterface({ input, output });
    const ans = await rl.question(question);
    rl.close();
    return ans.slice(0, SILENT_PROMPT_MAX);
  }
  return new Promise<string>((resolve) => {
    output.write(question);
    let buf = "";
    const stdin = input as unknown as NodeJS.ReadStream & { setRawMode: (b: boolean) => void };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const finish = (val: string) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      output.write("\n");
      resolve(val);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        // \n, \r, or Ctrl+D (\x04) terminate input
        if (ch === "\n" || ch === "\r" || ch === "\x04") {
          finish(buf);
          return;
        }
        // Ctrl+C: restore terminal before exiting so the parent shell
        // isn't left in raw mode.
        if (ch === "\x03") {
          stdin.setRawMode(false);
          stdin.pause();
          process.exit(130);
        }
        // backspace / DEL
        if (ch === "\x7f" || ch === "\b") {
          buf = buf.slice(0, -1);
          continue;
        }
        if (buf.length >= SILENT_PROMPT_MAX) {
          // truncate further input rather than allow unbounded growth
          finish(buf);
          return;
        }
        buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

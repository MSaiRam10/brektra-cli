import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import open from "open";
import pc from "picocolors";
import { apiBase, loadConfig, saveConfig } from "./config.js";
import { assertSafeOpenUrl, validateApiKey } from "./safety.js";

export async function login() {
  const cfg = await loadConfig();
  const url = assertSafeOpenUrl(`${apiBase(cfg)}/settings/api-keys?cli=1`);
  console.log(pc.gray("opening"), pc.cyan(url));
  // some headless terminals won't open; ignore that, the user can copy-paste
  open(url).catch(() => undefined);

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

async function silentPrompt(question: string): Promise<string> {
  // Best-effort no-echo prompt. On a TTY we toggle raw mode so keystrokes
  // aren't echoed; off-TTY (CI piped stdin) we fall back to readline.
  const isTTY = (input as unknown as { isTTY?: boolean }).isTTY === true;
  if (!isTTY) {
    const rl = readline.createInterface({ input, output });
    const ans = await rl.question(question);
    rl.close();
    return ans;
  }
  return new Promise<string>((resolve) => {
    output.write(question);
    let buf = "";
    const stdin = input as unknown as NodeJS.ReadStream & { setRawMode: (b: boolean) => void };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\n" || ch === "\r" || ch === "") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener("data", onData);
          output.write("\n");
          resolve(buf);
          return;
        }
        if (ch === "") {
          // Ctrl+C
          stdin.setRawMode(false);
          process.exit(130);
        }
        if (ch === "" || ch === "\b") {
          buf = buf.slice(0, -1);
          continue;
        }
        buf += ch;
      }
    };
    stdin.on("data", onData);
  });
}

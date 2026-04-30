#!/usr/bin/env node
import pc from "picocolors";
import { runScan } from "./scan.js";
import { runAtlas } from "./atlas.js";
import { login } from "./auth.js";
import { openReplay } from "./replay.js";

const VERSION = "0.1.0";

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  const rest = argv.slice(1);

  if (!cmd || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }
  if (cmd === "--version" || cmd === "-v") {
    console.log(VERSION);
    return;
  }

  switch (cmd) {
    case "scan": {
      const url = rest[0];
      if (!url) {
        console.error(pc.red("usage: brektra scan <url>"));
        process.exit(1);
      }
      await runScan(url, parseFlags(rest.slice(1)));
      return;
    }
    case "atlas": {
      const slug = rest[0];
      if (!slug) {
        console.error(pc.red("usage: brektra atlas <pattern> --target <url>"));
        process.exit(1);
      }
      await runAtlas(slug, parseFlags(rest.slice(1)));
      return;
    }
    case "login": {
      await login();
      return;
    }
    case "replay": {
      const id = rest[0];
      if (!id) {
        console.error(pc.red("usage: brektra replay <scan_id>"));
        process.exit(1);
      }
      await openReplay(id);
      return;
    }
    default:
      console.error(pc.red(`unknown command: ${cmd}`));
      printHelp();
      process.exit(1);
  }
}

function parseFlags(rest: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
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

function printHelp() {
  console.log(`brektra-cli ${VERSION}

usage:
  brektra scan <url>           run a quick scan
  brektra atlas <pattern>      run a single Atlas pattern (--target required for non-localhost)
  brektra login                authenticate
  brektra replay <scan_id>     open the replay url in your browser

flags:
  --target <url>               override target for atlas runs
  --mode safe|aggressive       defaults to safe
  --json                       machine-readable output

docs: https://brektra.com/docs/cli
`);
}

main().catch((err) => {
  // top-level errors are messy on purpose, just dump and exit
  console.error(pc.red("error:"), err?.message ?? err);
  process.exit(1);
});

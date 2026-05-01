#!/usr/bin/env node
import pc from "picocolors";
import { runScanCommand } from "./scan.js";
import { runAtlas } from "./atlas.js";
import { login } from "./auth.js";
import { openReplay } from "./replay.js";
import { runAgents } from "./agents.js";
import { runEngines } from "./engines.js";
import { runPlaybook } from "./playbooks.js";
import { runCompliance } from "./compliance.js";
import { runCi } from "./ci.js";
import { VERSION } from "./version.js";

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
    case "scan":
      await runScanCommand(rest);
      return;
    case "atlas": {
      const slug = rest[0];
      if (!slug) {
        console.error(pc.red("usage: brektra atlas <pattern> --target <url>"));
        process.exit(1);
      }
      await runAtlas(slug, parseFlags(rest.slice(1)));
      return;
    }
    case "ci":
      await runCi(rest);
      return;
    case "agents":
      await runAgents(rest);
      return;
    case "engines":
      await runEngines(rest);
      return;
    case "playbooks":
    case "playbook":
      await runPlaybook(rest[0]);
      return;
    case "compliance":
      await runCompliance(rest);
      return;
    case "login":
      await login();
      return;
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
  brektra scan web   <url>                       web attack surface (E10)
  brektra scan ai    <endpoint>                  AI attack surface  (E11)
  brektra scan cloud aws|gcp|azure|k8s           cloud attack surface (E12)
  brektra scan cicd  github|gitlab|jenkins|...   CI/CD attack surface (E13)
  brektra scan mobile <apk-or-ipa>               mobile static analysis (E14)
  brektra scan host  <cidr>                      network/AD scan via agent

  brektra atlas <pattern> --target <url>         run a single Atlas pattern

  brektra ci scan <target> [--surfaces ...]      CI mode multi-surface scan

  brektra agents list                            list connected agents
  brektra agents update                          show available agent updates
  brektra engines list                           list connected engines
  brektra playbooks <finding-id>                 fetch a finding's playbook
  brektra compliance export <framework>          soc2|pci|hipaa|iso|nist|gdpr|fedramp

  brektra login                                  authenticate
  brektra replay <scan_id>                       open the replay url

flags (selected):
  --mode safe|aggressive                         defaults to safe
  --fail-on-severity info|low|medium|high|critical   nonzero exit if matched
  --json                                         machine-readable output (planned)

  ai surface:    --crescendo --skeleton-key --multimodal --gcg --pair --tap
  web surface:   --dom-xss --ssti --nosql --ldap --xxe --oauth --jwt --graphql
  cloud surface: --aws-profile <p> --gcp-creds <path> --azure-sub <id> --k8s-config <path>
  cicd surface:  --github-token <t> --gitlab-token <t> --jenkins-url <url>

docs: https://brektra.com/docs/cli
`);
}

main().catch((err) => {
  // top-level errors are messy on purpose, just dump and exit
  console.error(pc.red("error:"), err?.message ?? err);
  process.exit(1);
});

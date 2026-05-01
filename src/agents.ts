import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { listAgentUpdates, listAgents } from "./api.js";

export async function runAgents(rest: string[]) {
  const sub = rest[0];
  if (!sub || sub === "list") {
    await runList();
    return;
  }
  if (sub === "update" || sub === "updates") {
    await runUpdates();
    return;
  }
  console.error(pc.red(`unknown subcommand: brektra agents ${sub}`));
  console.error(pc.gray("subcommands: list, update"));
  process.exit(1);
}

async function runList() {
  await requireApiKey();
  let agents;
  try {
    agents = await listAgents();
  } catch (e) {
    console.error(pc.red("could not list agents:"), (e as Error).message);
    process.exit(1);
  }
  if (agents.length === 0) {
    console.log(pc.gray("no agents connected"));
    return;
  }
  console.log("");
  for (const a of agents) {
    const status =
      a.status === "online" ? pc.green(a.status) : a.status === "degraded" ? pc.yellow(a.status) : pc.gray(a.status);
    console.log(`  ${pc.bold(a.name)}  ${pc.gray(a.id)}`);
    console.log(`    ${pc.gray("version  ")} ${a.version}`);
    console.log(`    ${pc.gray("status   ")} ${status}`);
    console.log(`    ${pc.gray("seen     ")} ${a.last_seen}`);
    if (a.capabilities.length) {
      console.log(`    ${pc.gray("caps     ")} ${a.capabilities.join(", ")}`);
    }
    console.log("");
  }
}

async function runUpdates() {
  await requireApiKey();
  let updates;
  try {
    updates = await listAgentUpdates();
  } catch (e) {
    console.error(pc.red("could not fetch updates:"), (e as Error).message);
    process.exit(1);
  }
  if (updates.length === 0) {
    console.log(pc.green("all agents up to date"));
    return;
  }
  console.log("");
  for (const u of updates) {
    console.log(
      `  ${pc.bold(u.agent_id)}  ${pc.gray(u.current_version)} -> ${pc.cyan(u.available_version)}  ${pc.gray(`(${u.channel})`)}`,
    );
  }
  console.log("");
}

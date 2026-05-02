import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { listAgentUpdates, listAgents } from "./api.js";
import { sanitizeForDisplay } from "./safety.js";

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
    // SECURITY: escape server-supplied strings before display so a compromised
    // backend can't inject ANSI escapes. Even the strict-equality branches
    // re-render the value through the colorizer, so we sanitize before
    // colorizing rather than trusting the equality match.
    const safeStatus = sanitizeForDisplay(String(a.status));
    const status =
      a.status === "online"
        ? pc.green(safeStatus)
        : a.status === "degraded"
          ? pc.yellow(safeStatus)
          : pc.gray(safeStatus);
    console.log(`  ${pc.bold(sanitizeForDisplay(a.name))}  ${pc.gray(sanitizeForDisplay(a.id))}`);
    console.log(`    ${pc.gray("version  ")} ${sanitizeForDisplay(a.version)}`);
    console.log(`    ${pc.gray("status   ")} ${status}`);
    console.log(`    ${pc.gray("seen     ")} ${sanitizeForDisplay(a.last_seen)}`);
    if (a.capabilities.length) {
      console.log(`    ${pc.gray("caps     ")} ${a.capabilities.map(sanitizeForDisplay).join(", ")}`);
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
      `  ${pc.bold(sanitizeForDisplay(u.agent_id))}  ${pc.gray(sanitizeForDisplay(u.current_version))} -> ${pc.cyan(sanitizeForDisplay(u.available_version))}  ${pc.gray(`(${sanitizeForDisplay(u.channel)})`)}`,
    );
  }
  console.log("");
}

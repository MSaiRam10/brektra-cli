import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { listEngines } from "./api.js";

export async function runEngines(rest: string[]) {
  const sub = rest[0];
  if (sub && sub !== "list") {
    console.error(pc.red(`unknown subcommand: brektra engines ${sub}`));
    process.exit(1);
  }
  await requireApiKey();
  let engines;
  try {
    engines = await listEngines();
  } catch (e) {
    console.error(pc.red("could not list engines:"), (e as Error).message);
    process.exit(1);
  }
  if (engines.length === 0) {
    console.log(pc.gray("no engines connected"));
    return;
  }
  console.log("");
  for (const e of engines) {
    const status =
      e.status === "online" ? pc.green(e.status) : e.status === "degraded" ? pc.yellow(e.status) : pc.gray(e.status);
    console.log(`  ${pc.bold(e.name)}  ${pc.gray(e.id)}`);
    console.log(`    ${pc.gray("version  ")} ${e.version}`);
    console.log(`    ${pc.gray("status   ")} ${status}`);
    console.log(`    ${pc.gray("surfaces ")} ${e.surfaces.join(", ")}`);
    console.log(`    ${pc.gray("modules  ")} ${e.modules}`);
    console.log("");
  }
}

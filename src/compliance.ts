import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { getComplianceExport, startComplianceExport } from "./api.js";

const FRAMEWORKS = ["soc2", "pci", "hipaa", "iso", "nist", "gdpr", "fedramp"];

export async function runCompliance(rest: string[]) {
  const sub = rest[0];
  if (sub !== "export") {
    console.error(pc.red("usage: brektra compliance export <framework>"));
    console.error(pc.gray("frameworks: " + FRAMEWORKS.join(", ")));
    process.exit(1);
  }
  const framework = (rest[1] || "").toLowerCase();
  if (!FRAMEWORKS.includes(framework)) {
    console.error(pc.red(`unknown framework: ${framework || "(missing)"}`));
    console.error(pc.gray("frameworks: " + FRAMEWORKS.join(", ")));
    process.exit(1);
  }

  await requireApiKey();
  let exp;
  try {
    exp = await startComplianceExport(framework);
  } catch (e) {
    console.error(pc.red("export failed to start:"), (e as Error).message);
    process.exit(1);
  }

  console.log(pc.gray("*"), `Export queued for ${pc.cyan(framework)} (${pc.gray(exp.id)})`);

  const start = Date.now();
  const timeoutMs = 5 * 60 * 1000;
  let last = exp;
  while (last.status !== "complete" && last.status !== "failed") {
    if (Date.now() - start > timeoutMs) {
      console.error(pc.red("timed out waiting for export"));
      process.exit(1);
    }
    await sleep(2000);
    try {
      last = await getComplianceExport(exp.id);
    } catch {
      // transient errors, keep polling
    }
  }

  if (last.status === "failed") {
    console.error(pc.red("export failed"));
    process.exit(1);
  }
  if (last.download_url) {
    console.log(pc.green("ready"), pc.cyan(last.download_url));
  } else {
    console.log(pc.green("ready"), pc.gray("(no download url)"));
  }
}

function sleep(ms: number) {
  return new Promise((res) => setTimeout(res, ms));
}

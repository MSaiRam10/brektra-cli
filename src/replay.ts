import pc from "picocolors";
import open from "open";
import { apiBase, loadConfig } from "./config.js";

export async function openReplay(scanId: string) {
  const cfg = await loadConfig();
  const url = `${apiBase(cfg)}/scans/${scanId}/replay`;
  console.log(pc.gray("opening"), pc.cyan(url));
  await open(url);
}

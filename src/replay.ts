import pc from "picocolors";
import open from "open";
import { apiBase, loadConfig } from "./config.js";
import { assertSafeOpenUrl } from "./safety.js";

export async function openReplay(scanId: string) {
  // SECURITY: validate scan id shape so it can't smuggle path traversal
  // or query/fragment hijacks into the URL we hand to the OS shell.
  if (!/^[A-Za-z0-9_\-]{1,64}$/.test(scanId)) {
    console.error(pc.red("invalid scan id"));
    process.exit(1);
  }
  const cfg = await loadConfig();
  const url = assertSafeOpenUrl(`${apiBase(cfg)}/scans/${encodeURIComponent(scanId)}/replay`);
  console.log(pc.gray("opening"), pc.cyan(url));
  await open(url);
}

import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { getPlaybook } from "./api.js";
import { sanitizeForDisplay } from "./safety.js";

export async function runPlaybook(findingId: string | undefined) {
  if (!findingId) {
    console.error(pc.red("usage: brektra playbooks <finding-id>"));
    process.exit(1);
  }
  // SECURITY: finding ids are server-issued. Refuse anything that could
  // smuggle path traversal (../) or query parameters into the URL.
  if (!/^[A-Za-z0-9_\-]{1,64}$/.test(findingId)) {
    console.error(pc.red("invalid finding id"));
    process.exit(1);
  }
  await requireApiKey();
  let pb;
  try {
    pb = await getPlaybook(findingId);
  } catch (e) {
    console.error(pc.red("could not fetch playbook:"), (e as Error).message);
    process.exit(1);
  }
  // SECURITY: server-supplied strings are escaped of control chars before
  // display. A compromised or hostile playbook payload cannot forge log
  // lines or move the cursor with ANSI escapes.
  console.log("");
  console.log(`  ${pc.bold(sanitizeForDisplay(pb.title))}  ${pc.gray(sanitizeForDisplay(pb.finding_id))}`);
  console.log("");
  pb.steps.forEach((s, i) => {
    console.log(`  ${pc.cyan(`${i + 1}. ${sanitizeForDisplay(s.title)}`)}`);
    for (const line of s.body.split("\n")) {
      console.log(`     ${sanitizeForDisplay(line)}`);
    }
    console.log("");
  });
  if (pb.references.length) {
    console.log(pc.gray("  references"));
    for (const ref of pb.references) {
      console.log(
        `    ${pc.gray("-")} ${sanitizeForDisplay(ref.label)}  ${pc.cyan(sanitizeForDisplay(ref.url))}`,
      );
    }
    console.log("");
  }
}

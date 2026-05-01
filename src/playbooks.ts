import pc from "picocolors";
import { requireApiKey } from "./auth.js";
import { getPlaybook } from "./api.js";

export async function runPlaybook(findingId: string | undefined) {
  if (!findingId) {
    console.error(pc.red("usage: brektra playbooks <finding-id>"));
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
  console.log("");
  console.log(`  ${pc.bold(pb.title)}  ${pc.gray(pb.finding_id)}`);
  console.log("");
  pb.steps.forEach((s, i) => {
    console.log(`  ${pc.cyan(`${i + 1}. ${s.title}`)}`);
    for (const line of s.body.split("\n")) {
      console.log(`     ${line}`);
    }
    console.log("");
  });
  if (pb.references.length) {
    console.log(pc.gray("  references"));
    for (const ref of pb.references) {
      console.log(`    ${pc.gray("-")} ${ref.label}  ${pc.cyan(ref.url)}`);
    }
    console.log("");
  }
}

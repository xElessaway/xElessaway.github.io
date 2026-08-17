import { readFile } from "node:fs/promises";
import { triageTarget } from "./core/triage.mjs";
import { extractIntelligence } from "./core/extractor.mjs";
import { generateContent } from "./core/generator.mjs";

const configRaw = await readFile("./config.json", "utf-8");
const config = JSON.parse(configRaw);

const args = process.argv.slice(2);
let targets = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--target" || args[i] === "-t") {
    targets.push(args[++i]);
  } else if (args[i].startsWith("http")) {
    targets.push(args[i]);
  }
}

if (targets.length === 0) {
  console.log(`
===========================================================
  🛡️ AUTONOMOUS THREAT INTELLIGENCE AGENT (Full Agent)
===========================================================
Usage:
  node agent.mjs <http://target_ip:port/>
  node agent.mjs --target <http://target_ip:port/>

Example:
  node agent.mjs http://101.42.255.92:8001/
===========================================================
`);
  process.exit(0);
}

async function run() {
  console.log(`🚀 Starting autonomous intelligence extraction for ${targets.length} target(s)...`);

  for (const url of targets) {
    console.log(`\n===========================================================`);
    console.log(`🎯 TARGET: ${url}`);
    console.log(`===========================================================`);

    // 1. Passive Triage & Scraping
    const triageData = await triageTarget(url, config);
    if (!triageData) continue;

    // 2. Feature Extraction & Mapping
    const intel = extractIntelligence(triageData);

    // 3. Dossier & Report Generation
    const output = await generateContent(intel, config);

    console.log(`\n🎉 Pipeline completed for ${url}!`);
    console.log(`👉 Dossier: ${output.actorSlug}`);
    console.log(`👉 Report:  ${output.reportSlug}`);
  }

  console.log(`\n✅ All targets processed successfully!`);
}

run();

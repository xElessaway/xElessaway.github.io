import { mkdir, writeFile } from "node:fs/promises";

/**
 * Threat Intelligence Acquisition & Triage Engine
 * Usage: node ./scripts/auto-analyze-target.mjs <URL1> [URL2] ...
 */
const targets = process.argv.slice(2);

if (targets.length === 0) {
  console.log("Usage: node ./scripts/auto-analyze-target.mjs <http://ip:port/> [http://ip2:port2/]");
  process.exit(1);
}

const BASE_DIR = "./threat_intel_acquisitions";

async function analyzeTarget(urlStr) {
  const url = new URL(urlStr);
  const hostSafe = `${url.hostname}_${url.port || "80"}`.replace(/[^a-zA-Z0-9_]/g, "_");
  const targetDir = `${BASE_DIR}/${hostSafe}`;
  await mkdir(targetDir, { recursive: true });

  console.log(`\n🔍 [Probing Target] ${urlStr}`);
  let html = "";
  try {
    const res = await fetch(url.href, {
      signal: AbortSignal.timeout(10000),
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
    });
    console.log(`📡 Status: ${res.status} ${res.statusText}`);
    console.log(`🖥️ Server Header: ${res.headers.get("server") || "N/A"}`);
    html = await res.text();
    await writeFile(`${targetDir}/index.html`, html);
  } catch (err) {
    console.error(`❌ Connection failed to ${urlStr}: ${err.message}`);
    return;
  }

  // Extract directory file links
  const links = [...html.matchAll(/href="([^"?#]+)"/g)]
    .map((m) => m[1])
    .filter((f) => !f.endsWith("/") && f !== "../");

  console.log(`📁 Found ${links.length} files exposed on directory listing.`);

  let downloadedCount = 0;
  for (const filename of links) {
    // Skip heavy binary formats for passive triage, prioritize logs/configs/sources
    if (/\.(exe|bin|iso|vmdk|zip|tar\.gz)$/i.test(filename) && filename.length > 50) {
      continue;
    }

    try {
      const fileUrl = new URL(filename, url.href).href;
      const fileRes = await fetch(fileUrl, { signal: AbortSignal.timeout(8000) });
      if (fileRes.ok) {
        const text = await fileRes.text();
        const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
        await writeFile(`${targetDir}/${safeName}`, text);
        downloadedCount++;
      }
    } catch (e) {
      // ignore individual file timeouts
    }
  }

  console.log(`✅ Successfully acquired and triaged ${downloadedCount} operational artifacts into ${targetDir}`);
}

for (const target of targets) {
  await analyzeTarget(target);
}

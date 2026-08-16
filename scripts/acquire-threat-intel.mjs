import { mkdir, writeFile } from "node:fs/promises";

const BASE_DIR = "./threat_intel_acquisitions";
await mkdir(BASE_DIR + "/server1_101_42_255_92", { recursive: true });
await mkdir(BASE_DIR + "/server2_2_27_63_244", { recursive: true });

async function acquireServer1() {
  console.log("=== Acquiring Server 1 (101.42.255.92:8001) ===");
  const base = "http://101.42.255.92:8001/";
  const res = await fetch(base);
  const html = await res.text();
  await writeFile(BASE_DIR + "/server1_101_42_255_92/index.html", html);

  const matches = [...html.matchAll(/href="([^"]+)"/g)]
    .map((m) => m[1])
    .filter((f) => !f.endsWith("/") && !f.startsWith("?"));

  console.log("Server 1 files found:", matches.length);

  for (const f of matches) {
    if (f.endsWith(".zip")) {
      console.log("Skipping large zip:", f);
      continue;
    }
    try {
      const fileRes = await fetch(base + f);
      if (fileRes.ok) {
        const text = await fileRes.text();
        const safeName = f.replace(/[^a-zA-Z0-9._-]/g, "_");
        await writeFile(`${BASE_DIR}/server1_101_42_255_92/${safeName}`, text);
        console.log(`[Acquired] ${f} (${text.length} bytes)`);
      }
    } catch (e) {
      console.error(`[Error] ${f}:`, e.message);
    }
  }
}

async function acquireServer2() {
  console.log("\n=== Acquiring Server 2 (2.27.63.244:9999) ===");
  const base = "http://2.27.63.244:9999/";
  const res = await fetch(base);
  const html = await res.text();
  await writeFile(BASE_DIR + "/server2_2_27_63_244/index.html", html);

  const matches = [...html.matchAll(/href="([^"]+)"/g)]
    .map((m) => m[1])
    .filter((f) => !f.endsWith("/") && !f.startsWith("?"));

  console.log("Server 2 files found:", matches.length);

  for (const f of matches) {
    if (f.endsWith(".exe") || f.endsWith(".bin") || f.endsWith(".zip") || f.endsWith(".tar.gz")) {
      console.log(`[Skipping Binary] ${f}`);
      continue;
    }
    try {
      const fileRes = await fetch(base + f);
      if (fileRes.ok) {
        const text = await fileRes.text();
        const safeName = f.replace(/[^a-zA-Z0-9._-]/g, "_");
        await writeFile(`${BASE_DIR}/server2_2_27_63_244/${safeName}`, text);
        console.log(`[Acquired] ${f} (${text.length} bytes)`);
      }
    } catch (e) {
      console.error(`[Error] ${f}:`, e.message);
    }
  }
}

await acquireServer1();
await acquireServer2();
console.log("\n=== Acquisition complete! ===");

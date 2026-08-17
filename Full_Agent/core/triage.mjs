import { mkdir, writeFile } from "node:fs/promises";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

/**
 * Passive Triage & Acquisition Module (Supports HTTP & Self-Signed HTTPS)
 */
export async function triageTarget(urlStr, config) {
  const url = new URL(urlStr);
  const hostSafe = `${url.hostname}_${url.port || "80"}`.replace(/[^a-zA-Z0-9_]/g, "_");
  const targetDir = `${config.paths.acquisitionsDir}/${hostSafe}`;
  await mkdir(targetDir, { recursive: true });

  console.log(`\n🔍 [Probing Threat Target] ${urlStr}`);
  let html = "";
  let serverHeader = "Unknown";
  try {
    const res = await fetch(url.href, {
      signal: AbortSignal.timeout(config.crawler.timeoutMs),
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
    });
    serverHeader = res.headers.get("server") || "Unknown";
    console.log(`📡 HTTP Response: ${res.status} ${res.statusText} (Server: ${serverHeader})`);
    html = await res.text();
    await writeFile(`${targetDir}/index.html`, html);
  } catch (err) {
    console.error(`❌ Connection failed to ${urlStr}: ${err.message}`);
    return null;
  }

  // Extract file links from directory listing
  const links = [...html.matchAll(/href="([^"?#]+)"/g)]
    .map((m) => m[1])
    .filter((f) => !f.endsWith("/") && f !== "../" && !f.startsWith("?"));

  console.log(`📁 Discovered ${links.length} artifacts listed in directory.`);

  const downloadedFiles = [];
  for (const filename of links) {
    const isBinary = config.crawler.skipBinaryExtensions.some((ext) => filename.toLowerCase().endsWith(ext));
    if (isBinary && filename.length > 50) {
      continue;
    }

    try {
      const fileUrl = new URL(filename, url.href).href;
      const fileRes = await fetch(fileUrl, { signal: AbortSignal.timeout(8000) });
      if (fileRes.ok) {
        const text = await fileRes.text();
        const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
        const filePath = `${targetDir}/${safeName}`;
        await writeFile(filePath, text);
        downloadedFiles.push({ filename: safeName, originalName: filename, path: filePath, size: text.length, content: text });
      }
    } catch (e) {
      // ignore
    }
  }

  console.log(`✅ Triaged ${downloadedFiles.length} text artifacts into ${targetDir}`);
  return {
    targetUrl: urlStr,
    hostname: url.hostname,
    port: url.port || "80",
    serverHeader,
    targetDir,
    files: downloadedFiles
  };
}

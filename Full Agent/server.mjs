import http from "node:http";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { triageTarget } from "./core/triage.mjs";
import { extractIntelligence } from "./core/extractor.mjs";
import { generateContent } from "./core/generator.mjs";

const PORT = 3888;
const configRaw = await readFile("./config.json", "utf-8");
const config = JSON.parse(configRaw);

// Memory cache for recent target analyses
const recentAnalyses = [];

const MIME_TYPES = {
  ".html": "text/html",
  ".css": "text/css",
  ".js": "text/javascript",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml"
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // API 1: Health & Status
  if (url.pathname === "/api/status" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "active", version: "1.0.0", port: PORT, count: recentAnalyses.length }));
    return;
  }

  // API 2: Analyze Target URL
  if (url.pathname === "/api/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { targetUrl } = JSON.parse(body);
        if (!targetUrl || !targetUrl.startsWith("http")) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid target URL. Must start with http:// or https://" }));
          return;
        }

        console.log(`\n[UI Triggered Analysis] Target: ${targetUrl}`);

        // 1. Passive Triage
        const triageData = await triageTarget(targetUrl, config);
        if (!triageData) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Connection failed or could not probe target ${targetUrl}` }));
          return;
        }

        // 2. Feature Extraction & Mapping
        const intel = extractIntelligence(triageData);

        // 3. Markdown Generation
        const output = await generateContent(intel, config);

        const resultObj = {
          id: Date.now(),
          targetUrl,
          host: intel.host,
          port: intel.port,
          serverHeader: triageData.serverHeader,
          filesFound: triageData.files.length,
          tools: intel.tools,
          ttps: intel.ttps,
          iocs: intel.iocs,
          actorSlug: output.actorSlug,
          reportSlug: output.reportSlug,
          timestamp: new Date().toISOString()
        };

        recentAnalyses.unshift(resultObj);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(resultObj));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API 3: List Recent Investigations
  if (url.pathname === "/api/history" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(recentAnalyses));
    return;
  }

  // Serve Web UI Single Page App
  if (url.pathname === "/" || url.pathname === "/index.html") {
    try {
      const html = await readFile("./public/index.html", "utf-8");
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(html);
    } catch (e) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("Error loading UI: " + e.message);
    }
    return;
  }

  // Fallback 404
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

server.listen(PORT, () => {
  console.log(`
========================================================================
  🛡️ THREAT INTEL AUTONOMOUS AGENT WEB CONSOLE IS LIVE!
========================================================================
  🚀 Open UI in your browser:  http://localhost:${PORT}/
  📡 Background Server Port:   ${PORT}
========================================================================
`);
});

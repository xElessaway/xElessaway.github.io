import http from "node:http";
import { readFile } from "node:fs/promises";
import { triageTarget } from "./core/triage.mjs";
import { extractIntelligence } from "./core/extractor.mjs";
import { generateDraftContent, publishContent } from "./core/generator.mjs";
import { checkOllamaStatus } from "./core/ollama.mjs";

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (reason) => console.error("Unhandled rejection:", reason));

const PORT = 3888;
const configRaw = await readFile("./config.json", "utf-8");
const config = JSON.parse(configRaw);

const recentAnalyses = [];

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

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
    const ollama = await checkOllamaStatus();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      status: "active",
      version: "2.1.0",
      port: PORT,
      count: recentAnalyses.length,
      ollama
    }));
    return;
  }

  // API 2: Ollama Status check
  if (url.pathname === "/api/ollama/status" && req.method === "GET") {
    const ollama = await checkOllamaStatus();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(ollama));
    return;
  }

  // API 3: Analyze Target URL (Draft & Review Mode)
  if (url.pathname === "/api/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { targetUrl, modelName } = JSON.parse(body);
        if (!targetUrl || !targetUrl.startsWith("http")) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid target URL. Must start with http:// or https://" }));
          return;
        }

        console.log(`\n[UI Triggered Analysis v2.1] Target: ${targetUrl} (Model: ${modelName || "auto"})`);

        const triageData = await triageTarget(targetUrl, config);
        if (!triageData) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Connection failed or could not probe target ${targetUrl}` }));
          return;
        }

        const intel = await extractIntelligence(triageData, modelName);
        const drafts = generateDraftContent(intel, config);

        const resultObj = {
          id: Date.now(),
          targetUrl,
          host: intel.host,
          port: intel.port,
          serverHeader: triageData.serverHeader,
          filesFound: triageData.files.length,
          tools: intel.tools,
          ttps: intel.ttps,
          highConfidenceIOCs: intel.highConfidenceIOCs,
          ambientIOCs: intel.ambientIOCs,
          deobfuscation: intel.deobfuscation,
          forensics: intel.forensics,
          aiAnalysis: intel.aiAnalysis,
          actorSlug: drafts.actorSlug,
          reportSlug: drafts.reportSlug,
          draftDossier: drafts.dossierMarkdown,
          draftReport: drafts.blogMarkdown,
          published: false,
          timestamp: new Date().toISOString()
        };

        recentAnalyses.unshift(resultObj);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(resultObj));
      } catch (err) {
        console.error("Analysis pipeline error:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API 4: Publish Reviewed & Edited Reports
  if (url.pathname === "/api/publish" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { actorSlug, dossierMarkdown, reportSlug, blogMarkdown } = JSON.parse(body);
        if (!actorSlug || !dossierMarkdown || !reportSlug || !blogMarkdown) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Missing required fields for publishing." }));
          return;
        }

        const { actorFile, blogFile } = await publishContent(actorSlug, dossierMarkdown, reportSlug, blogMarkdown, config);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          success: true,
          actorFile,
          blogFile,
          dossierUrl: `https://xelessaway.me/threat-intelligence/${actorSlug}/`,
          reportUrl: `https://xelessaway.me/blog/${reportSlug}/`
        }));
      } catch (err) {
        console.error("Publishing error:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API 5: List Recent Investigations
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

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

server.listen(PORT, () => {
  console.log(`
========================================================================
  🛡️ THREAT INTEL AUTONOMOUS AGENT WEB CONSOLE v2.1 IS LIVE!
========================================================================
  🚀 Open UI in your browser:  http://localhost:${PORT}/
  🧠 Local Ollama LLM Ready:   qwen2.5:3b (Offline, Zero-Cost)
  📝 Review & Edit Mode:       Edit & Approve Drafts Before Publishing
========================================================================
`);
});

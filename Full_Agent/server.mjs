import http from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { triageTarget } from "./core/triage.mjs";
import { extractIntelligence } from "./core/extractor.mjs";
import { generateDraftContent, publishContent } from "./core/generator.mjs";
import { checkOllamaStatus, chatWithOllama } from "./core/ollama.mjs";

process.on("uncaughtException", (err) => console.error("Uncaught exception:", err));
process.on("unhandledRejection", (reason) => console.error("Unhandled rejection:", reason));

const PORT = 3888;
const SESSIONS_FILE = "./threat_intel_acquisitions/sessions.json";
const configRaw = await readFile("./config.json", "utf-8");
const config = JSON.parse(configRaw);

// Load persisted sessions from disk
let sessions = [];
async function loadSessions() {
  try {
    if (existsSync(SESSIONS_FILE)) {
      const data = await readFile(SESSIONS_FILE, "utf-8");
      sessions = JSON.parse(data);
    }
  } catch (e) {
    console.error("Failed to load sessions:", e);
  }
}
async function saveSessions() {
  try {
    await mkdir("./threat_intel_acquisitions", { recursive: true });
    await writeFile(SESSIONS_FILE, JSON.stringify(sessions, null, 2), "utf-8");
  } catch (e) {
    console.error("Failed to save sessions:", e);
  }
}
await loadSessions();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
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
      version: "3.0.0 (Claude-Style Studio)",
      port: PORT,
      sessionCount: sessions.length,
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

  // API 3: List / Search Sessions (Sidebar History)
  if (url.pathname === "/api/sessions" && req.method === "GET") {
    const summaries = sessions.map((s) => ({
      id: s.id,
      title: s.title || `Investigation: ${s.host || s.targetUrl}`,
      targetUrl: s.targetUrl,
      host: s.host,
      timestamp: s.timestamp,
      toolsCount: (s.tools || []).length,
      carvedCount: (s.deobfuscation?.carvedBinaries || []).length
    }));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(summaries));
    return;
  }

  // API 4: Get Specific Session by ID
  if (url.pathname.startsWith("/api/sessions/") && req.method === "GET") {
    const id = url.pathname.split("/").pop();
    const session = sessions.find((s) => String(s.id) === String(id));
    if (!session) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Session not found" }));
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(session));
    return;
  }

  // API 5: Delete Session
  if (url.pathname.startsWith("/api/sessions/") && req.method === "DELETE") {
    const id = url.pathname.split("/").pop();
    sessions = sessions.filter((s) => String(s.id) !== String(id));
    await saveSessions();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // API 6: Analyze Target URL (Launch Investigation)
  if (url.pathname === "/api/analyze" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { targetUrl, modelName, customPrompt } = JSON.parse(body);
        if (!targetUrl || !targetUrl.startsWith("http")) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid target URL. Must start with http:// or https://" }));
          return;
        }

        console.log(`\n[Claude Studio] Probing Target: ${targetUrl} (Model: ${modelName || "auto"})`);

        const triageData = await triageTarget(targetUrl, config);
        if (!triageData) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Connection failed or could not probe target ${targetUrl}` }));
          return;
        }

        const intel = await extractIntelligence(triageData, modelName);
        const drafts = generateDraftContent(intel, config);

        const newSession = {
          id: Date.now().toString(),
          title: `${intel.host} Threat Hunt`,
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
          secrets: intel.secrets,
          aiAnalysis: intel.aiAnalysis,
          actorSlug: drafts.actorSlug,
          reportSlug: drafts.reportSlug,
          draftDossier: drafts.dossierMarkdown,
          draftReport: drafts.blogMarkdown,
          chatHistory: [
            {
              role: "user",
              content: customPrompt ? `Analyze target: ${targetUrl}\n${customPrompt}` : `Probe and triage target: ${targetUrl}`,
              timestamp: new Date().toISOString()
            },
            {
              role: "assistant",
              content: `### 🎯 Investigation Initialized: \`${intel.host}\`\n\n` +
                `* **Server**: \`${triageData.serverHeader || "Apache/Windows"}\`\n` +
                `* **Triaged Files**: ${triageData.files.length} artifacts\n` +
                `* **Recovered Keys**: ${(intel.deobfuscation?.recoveredKeys || []).length} XOR decryption keys\n` +
                `* **Carved Binaries**: ${(intel.deobfuscation?.carvedBinaries || []).length} executables/DLLs\n` +
                `* **Secrets Found**: ${(intel.secrets || []).length} credentials\n\n` +
                `I have generated the initial **Threat Intel Dossier** and **DFIR Report** in the Artifacts panel on the right. You can ask me to refine sections, extract specific indicators, or rewrite summaries!`,
              timestamp: new Date().toISOString()
            }
          ],
          timestamp: new Date().toISOString()
        };

        sessions.unshift(newSession);
        await saveSessions();

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(newSession));
      } catch (err) {
        console.error("Analysis pipeline error:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API 7: Interactive Chat with Ollama
  if (url.pathname === "/api/chat" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { sessionId, message, modelName } = JSON.parse(body);
        const session = sessions.find((s) => String(s.id) === String(sessionId));

        const messages = session ? [...(session.chatHistory || [])] : [];
        messages.push({ role: "user", content: message, timestamp: new Date().toISOString() });

        const context = session || {};
        const reply = await chatWithOllama(messages, context, modelName);

        const assistantMsg = {
          role: "assistant",
          content: reply.message,
          timestamp: new Date().toISOString(),
          model: reply.model
        };

        if (session) {
          session.chatHistory = session.chatHistory || [];
          session.chatHistory.push({ role: "user", content: message, timestamp: new Date().toISOString() });
          session.chatHistory.push(assistantMsg);
          await saveSessions();
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ response: reply.message, session }));
      } catch (err) {
        console.error("Chat error:", err);
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // API 8: Update Draft in Session
  if (url.pathname === "/api/drafts/update" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", async () => {
      try {
        const { sessionId, draftDossier, draftReport } = JSON.parse(body);
        const session = sessions.find((s) => String(s.id) === String(sessionId));
        if (session) {
          if (draftDossier !== undefined) session.draftDossier = draftDossier;
          if (draftReport !== undefined) session.draftReport = draftReport;
          await saveSessions();
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API 9: Publish Reviewed Content
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
  🛡️ CLAUDE-STYLE THREAT INTEL WORKSPACE (v3.0) IS LIVE!
========================================================================
  🚀 Open Studio in browser:   http://localhost:${PORT}/
  🧠 Local Ollama LLM Bridge:  Offline, Zero-Cost AI Reasoning
  💬 Interactive Sidebar:      Recent Investigations & Multi-Turn Chat
  📝 Live Artifacts Panel:     Real-Time Markdown & HTML Dossier Previews
========================================================================
`);
});

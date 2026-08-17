/**
 * Local Ollama LLM Bridge (Zero-Cost, 100% Offline AI Reasoning)
 */
const OLLAMA_HOST = process.env.OLLAMA_HOST || "http://localhost:11434";
const PREFERRED_MODELS = ["qwen2.5:3b", "llama3.2:3b", "qwen2.5:7b", "llama3.1:8b", "deepseek-r1:8b", "mistral:7b", "llama3:8b", "qwen2.5:latest"];

// 1. Check if Ollama is Online and detect loaded models
export async function checkOllamaStatus() {
  try {
    const res = await fetch(`${OLLAMA_HOST}/api/tags`, {
      signal: AbortSignal.timeout(2500)
    });
    if (res.ok) {
      const data = await res.json();
      const availableModels = (data.models || []).map((m) => m.name);
      
      // Pick preferred model according to priority
      let activeModel = PREFERRED_MODELS.find((p) => availableModels.some((m) => m === p || m.startsWith(p))) || availableModels[0] || "qwen2.5:3b";

      return {
        online: true,
        host: OLLAMA_HOST,
        models: availableModels,
        selectedModel: activeModel
      };
    }
    return { online: false, reason: `HTTP ${res.status}` };
  } catch (err) {
    return { online: false, reason: "Ollama service offline or not reachable on localhost:11434." };
  }
}

// 2. Query Local Model for Deep CTI Code Analysis
export async function analyzeWithOllama(triageData, deobfData, modelName = null) {
  const status = await checkOllamaStatus();
  if (!status.online) {
    return {
      used: false,
      reason: "Ollama offline. Skipped LLM reasoning."
    };
  }

  const model = modelName || status.selectedModel || "qwen2.5:3b";

  // Prepare concise analytical context
  const sourceCodeSnippets = triageData.files
    .filter((f) => /\.(c|py|sh|ps1|hta|json|h|yara)$/i.test(f.filename))
    .slice(0, 4)
    .map((f) => `--- [FILE: ${f.filename}] ---\n${f.content.slice(0, 1500)}`)
    .join("\n\n");

  const prompt = `You are an elite Cyber Threat Intelligence (CTI) and DFIR reverse engineer.
Analyze the following operational threat staging files and deobfuscation telemetry acquired from target host [${triageData.host || triageData.targetUrl}]:

${sourceCodeSnippets}

Deobfuscation Telemetry:
${JSON.stringify(deobfData, null, 2)}

Provide a concise technical assessment answering:
1. Threat Actor Tradecraft & Objectives (1-2 paragraphs)
2. Command and Control (C2) Architecture & Transport Channels
3. Defense Evasion & Kernel Blinding (BYOVD / Hooks / Task Hijacking)
4. Strategic Assessment & Recommended Mitigations

Format your output in clean Markdown.`;

  try {
    console.log(`🧠 [Ollama LLM] Generating deep technical analysis with local model '${model}'...`);
    const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: model,
        prompt: prompt,
        stream: false,
        options: {
          temperature: 0.2,
          num_predict: 512
        }
      }),
      signal: AbortSignal.timeout(120000)
    });

    if (res.ok) {
      const data = await res.json();
      return {
        used: true,
        model: model,
        analysisText: data.response
      };
    } else {
      return { used: false, reason: `Ollama error: HTTP ${res.status}` };
    }
  } catch (err) {
    return { used: false, reason: `Ollama query timeout or error: ${err.message}` };
  }
}

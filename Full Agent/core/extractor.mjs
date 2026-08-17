import { createHash } from "node:crypto";
import { defang } from "./defang.mjs";
import { analyzeAndDeobfuscateFiles } from "./deobfuscator.mjs";
import { performForensicAnalysis } from "./forensics.mjs";
import { harvestSecrets } from "./secrets_harvester.mjs";
import { analyzeWithOllama } from "./ollama.mjs";

/**
 * Enterprise Intelligence Aggregator & Deep Threat Extraction Engine
 */
export async function extractIntelligence(triageResult, modelName = null) {
  if (!triageResult || !triageResult.files) return null;

  const { hostname, port, files } = triageResult;
  const nonLogFiles = files.filter((f) => !f.filename.endsWith(".log") && !f.filename.includes("access_log"));
  const allFilesText = files.map((f) => f.content).join("\n");

  // 1. Run Automated Deobfuscation (XOR, Hex, Base64, AST)
  const deobfResults = analyzeAndDeobfuscateFiles(files);

  // 2. Run Windows Forensics, Magic Bytes & WSL Reverse Engineering
  const forensicResults = await performForensicAnalysis(files);

  // 3. Run Deep Credential & Secret Harvester
  const harvestedSecrets = harvestSecrets(files);

  // 4. Run Local Ollama AI Reasoning
  const aiAnalysis = await analyzeWithOllama(triageResult, deobfResults, modelName);

  // 5. Tooling & Malware Heuristics
  const observedTools = new Set();
  const ttps = new Set();

  if (/havoc|demon/i.test(allFilesText)) {
    observedTools.add("Havoc C2 Framework (Demon Implant)");
    ttps.add("T1071.001 - Application Layer Protocol: Web Protocols");
  }
  if (/cobaltstrike|teamserver|beacon_keys|gencrossc2/i.test(allFilesText)) {
    observedTools.add("Cobalt Strike 4.9.1");
    ttps.add("T1071.001 - Application Layer Protocol: Web Protocols");
  }
  if (/gencrossc2/i.test(allFilesText)) {
    observedTools.add("CrossC2 (genCrossC2.Linux)");
  }
  if (/adaptix|rrr_c2/i.test(allFilesText)) {
    observedTools.add("Adaptix C2 Framework");
  }
  if (/mythic/i.test(allFilesText)) {
    observedTools.add("Mythic C2 Framework");
  }
  if (/mshta|win\.hta|\.hta/i.test(allFilesText) || deobfResults.scriptBehaviors.some((b) => b.filename.includes(".hta"))) {
    observedTools.add("MSHTA Script Dropper");
    ttps.add("T1218.005 - System Binary Proxy Execution: Mshta");
  }
  if (/schtasks|Schedule\.Service/i.test(allFilesText) || deobfResults.scriptBehaviors.some((b) => b.scheduledTasks.length > 0)) {
    observedTools.add("Scheduled Task Hijacking (Persistence)");
    ttps.add("T1053.005 - Scheduled Task/Job: Scheduled Task");
  }
  if (/ISO|LNK|PrivatBank|Payment.*invoice/i.test(allFilesText) || forensicResults.lnkArtifacts.length > 0) {
    observedTools.add("Malicious ISO / LNK Phishing Lures");
    ttps.add("T1566.001 - Phishing: Spearphishing Attachment");
    ttps.add("T1204.002 - User Execution: Malicious File");
  }
  if (/VirtualAlloc|CreateThread|Marshal\.Copy|DocFix/i.test(allFilesText) || deobfResults.scriptBehaviors.some((b) => b.pInvokeMethods.length > 0)) {
    observedTools.add("In-Memory Shellcode Injector (P/Invoke)");
    ttps.add("T1055 - Process Injection");
  }
  if (/bxor|\$k=\[byte\[\]\]|\$decryptionHexKey/i.test(allFilesText) || deobfResults.recoveredKeys.length > 0) {
    observedTools.add("Multi-Byte XOR Shellcode Decryptor");
    ttps.add("T1140 - Deobfuscate/Decode Files or Information");
  }
  if (/github_c2|api\.github\.com/i.test(allFilesText) || harvestedSecrets.some((s) => s.type.includes("GitHub"))) {
    observedTools.add("GitHub Contents API C2 Transport");
    ttps.add("T1102.001 - Web Service: Dead Drop Resolver");
  }
  if (/google_sheets|sheets\.googleapis\.com/i.test(allFilesText) || harvestedSecrets.some((s) => s.type.includes("Google"))) {
    observedTools.add("Google Sheets API C2 Transport");
    ttps.add("T1102.001 - Web Service: Dead Drop Resolver");
  }
  if (/hwinfo|trixx|\.sys/i.test(allFilesText) || forensicResults.binaryArtifacts.some((b) => b.filename.endsWith(".sys"))) {
    observedTools.add("BYOVD Vulnerable Signed Drivers (Kernel Blinding)");
    ttps.add("T1068 - Exploitation for Privilege Escalation");
    ttps.add("T1562.001 - Disable or Modify Tools");
  }
  if (/rogue_mysql|mysql-fake-server|ALLOWLOADLOCALINFILE/i.test(allFilesText)) {
    observedTools.add("Rogue MySQL Server (Arbitrary File Exfiltration)");
    ttps.add("T1552.001 - Credentials in Files");
  }
  if (/sshpass/i.test(allFilesText) || harvestedSecrets.some((s) => s.type.includes("SSH"))) {
    observedTools.add("Automated SSH Lateral Movement Tool");
    ttps.add("T1021.004 - Remote Services: SSH");
  }

  // 6. Cryptographic SHA-256 Hashes
  const verifiedHashes = [];
  files.forEach((f) => {
    if (!f.filename.endsWith(".log") && !f.filename.endsWith(".html") && !f.filename.endsWith(".txt")) {
      const sha256 = createHash("sha256").update(f.content).digest("hex");
      verifiedHashes.push({
        type: "SHA-256 Hash",
        value: sha256,
        role: `Artifact: ${f.filename}`,
        confidence: "High (100%)"
      });
    }
  });

  // 7. High-Fidelity Verified Indicators
  const highConfidenceIOCs = [];

  highConfidenceIOCs.push({
    type: "Staging Host IPv4",
    value: defang(hostname),
    role: "Primary Adversary Staging Node",
    confidence: "High (100%)"
  });

  if (port) {
    highConfidenceIOCs.push({
      type: "Service Port",
      value: `${defang(hostname)}:${port}`,
      role: "Exposed Staging Directory",
      confidence: "High (100%)"
    });
  }

  // Recovered XOR Keys
  deobfResults.recoveredKeys.forEach((key) => {
    highConfidenceIOCs.push({
      type: "XOR Decryption Key",
      value: `${key.ascii} (Hex: ${key.hex.slice(0, 32)}...)`,
      role: `Recovered from ${key.source}`,
      confidence: "High (100%)"
    });
  });

  const combinedHighConfidence = [...highConfidenceIOCs, ...verifiedHashes];

  // 8. Ambient Traffic Isolation (Logs)
  const logIps = [...allFilesText.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((m) => m[0]);
  const ambientIps = [...new Set(logIps)]
    .filter((ip) => ip !== hostname && !ip.startsWith("127.") && !ip.startsWith("0.0.") && !ip.startsWith("192.168."))
    .slice(0, 10)
    .map((ip) => ({
      type: "Ambient / Log IPv4",
      value: defang(ip),
      role: "Connecting Client / Scanner (Needs Verification)",
      confidence: "Low (Unverified Noise)"
    }));

  return {
    host: hostname,
    port,
    tools: [...observedTools],
    ttps: [...ttps],
    highConfidenceIOCs: combinedHighConfidence,
    ambientIOCs: ambientIps,
    deobfuscation: deobfResults,
    forensics: forensicResults,
    secrets: harvestedSecrets,
    aiAnalysis: aiAnalysis
  };
}

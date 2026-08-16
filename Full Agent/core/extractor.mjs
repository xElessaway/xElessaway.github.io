import { createHash } from "node:crypto";
import { defang } from "./defang.mjs";

/**
 * Intelligent IOC Classifier & Confidence Scorer
 */
export function extractIntelligence(triageResult) {
  if (!triageResult || !triageResult.files) return null;

  const { hostname, port, files } = triageResult;
  const nonLogFiles = files.filter((f) => !f.filename.endsWith(".log") && !f.filename.includes("access_log"));
  const combinedCodeText = nonLogFiles.map((f) => f.content).join("\n");
  const allFilesText = files.map((f) => f.content).join("\n");

  // 1. Tooling heuristics
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
  if (/mshta|win\.hta|\.hta/i.test(allFilesText)) {
    observedTools.add("MSHTA Script Dropper");
    ttps.add("T1218.005 - System Binary Proxy Execution: Mshta");
  }
  if (/schtasks.*MsCtfMonitor|Schedule\.Service/i.test(allFilesText)) {
    observedTools.add("Scheduled Task Hijacking (MsCtfMonitor)");
    ttps.add("T1053.005 - Scheduled Task/Job: Scheduled Task");
  }
  if (/ISO|LNK|PrivatBank|Payment.*invoice/i.test(allFilesText)) {
    observedTools.add("Malicious ISO / LNK Phishing Lures");
    ttps.add("T1566.001 - Phishing: Spearphishing Attachment");
    ttps.add("T1204.002 - User Execution: Malicious File");
  }
  if (/VirtualAlloc|CreateThread|Marshal\.Copy|DocFix/i.test(allFilesText)) {
    observedTools.add("In-Memory Shellcode Injector (P/Invoke)");
    ttps.add("T1055 - Process Injection");
  }
  if (/bxor|\$k=\[byte\[\]\]/i.test(allFilesText)) {
    observedTools.add("Multi-Byte XOR Shellcode Decryptor");
    ttps.add("T1140 - Deobfuscate/Decode Files or Information");
  }
  if (/github_c2|api\.github\.com/i.test(allFilesText)) {
    observedTools.add("GitHub Contents API C2 Transport");
    ttps.add("T1102.001 - Web Service: Dead Drop Resolver");
  }
  if (/google_sheets|sheets\.googleapis\.com/i.test(allFilesText)) {
    observedTools.add("Google Sheets API C2 Transport");
    ttps.add("T1102.001 - Web Service: Dead Drop Resolver");
  }
  if (/hwinfo|trixx|\.sys/i.test(allFilesText)) {
    observedTools.add("BYOVD Vulnerable Signed Drivers (Kernel Blinding)");
    ttps.add("T1068 - Exploitation for Privilege Escalation");
    ttps.add("T1562.001 - Disable or Modify Tools");
  }
  if (/rogue_mysql|mysql-fake-server|ALLOWLOADLOCALINFILE/i.test(allFilesText)) {
    observedTools.add("Rogue MySQL Server (Arbitrary File Exfiltration)");
    ttps.add("T1552.001 - Credentials in Files");
  }
  if (/marshalsec|jndi|ysoserial/i.test(allFilesText)) {
    observedTools.add("JNDI / Marshalsec Deserialization RCE");
    ttps.add("T1190 - Exploit Public-Facing Application");
  }
  if (/enscan/i.test(allFilesText)) {
    observedTools.add("ENScan_GO Enterprise Recon");
    ttps.add("T1596 - Search Open Technical Databases");
  }
  if (/hollow\.c|process.*hollow/i.test(allFilesText)) {
    observedTools.add("Process Hollowing Injector");
    ttps.add("T1055.012 - Process Hollowing");
  }

  // 2. High-Fidelity Cryptographic File Hashes
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

  // 3. Extract Explicit C2 & Delivery Endpoints
  const highConfidenceIOCs = [];

  // Primary staging node
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

  // Additional ports found in Python/C code
  const portMatches = [...combinedCodeText.matchAll(/(?:port\s*=\s*|:\s*)(\d{2,5})/gi)].map((m) => m[1]);
  [...new Set(portMatches)].forEach((p) => {
    if (p !== port && parseInt(p, 10) > 1000 && parseInt(p, 10) < 65535) {
      highConfidenceIOCs.push({
        type: "Observed Listener Port",
        value: `${defang(hostname)}:${p}`,
        role: "Discovered Backend Listener Endpoint",
        confidence: "High (Code Verified)"
      });
    }
  });

  // Extract XOR keys if found in code
  const xorKeyMatch = combinedCodeText.match(/\$k\s*=\s*\[byte\[\]\]@\(([0-9,\s]+)\)/);
  if (xorKeyMatch) {
    const bytes = xorKeyMatch[1].split(",").map((s) => parseInt(s.trim(), 10));
    const keyStr = String.fromCharCode(...bytes);
    highConfidenceIOCs.push({
      type: "XOR Decryption Key",
      value: `${keyStr} (Hex: ${bytes.map((b) => b.toString(16).padStart(2, "0")).join("")})`,
      role: "Payload Decryption Key",
      confidence: "High (100%)"
    });
  }

  // Combine high confidence indicators
  const combinedHighConfidence = [...highConfidenceIOCs, ...verifiedHashes];

  // 4. Extract Low Confidence / Ambient Traffic (from logs) for human review
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
    ambientIOCs: ambientIps
  };
}

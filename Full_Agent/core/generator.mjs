import { writeFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { defang } from "./defang.mjs";

/**
 * High-Precision Dossier & Research Article Markdown Generator
 */

export function generateDraftContent(intel, config) {
  const safeSlug = intel.host.replace(/\./g, "-");
  const actorSlug = `cluster-${safeSlug}`;
  const reportSlug = `investigation-exposed-infrastructure-${safeSlug}`;
  const actorName = `Threat Cluster ${defang(intel.host)}`;

  // 1. Generate Draft Threat Dossier
  const dossierMarkdown = `---
name: "${actorName}"
aliases:
  - "UNC-${intel.host.replace(/\./g, "").slice(0, 5)}"
status: "active"
origin: "Unknown / Threat Staging Infrastructure"
motivation: "Targeted reconnaissance, credential harvesting, and persistent C2 staging."
targets:
  - "Enterprise Networks & Staging Targets"
firstSeen: "${new Date().toISOString().slice(0, 7)}"
lastSeen: "${new Date().toISOString().slice(0, 7)}"
tools: ${JSON.stringify(intel.tools)}
ttps: ${JSON.stringify(intel.ttps)}
tags:
  - "threat-intelligence"
  - "c2-infrastructure"
timeline:
  - date: "${new Date().toISOString().slice(0, 10)}"
    title: "Staging Server Telemetry Discovery"
    summary: "Exposed operational staging server identified hosting active toolchain and command artifacts."
references:
  - title: "Companion Investigation Report"
    url: "https://xelessaway.me/blog/${reportSlug}/"
    publisher: "Ahmed Elessaway Threat Research"
relatedPosts:
  - "${reportSlug}"
featured: true
---

### Key Operational Findings

* **Exposed Infrastructure**: Host \`${defang(intel.host)}\` operates as an active staging and C2 node.
* **Arsenal Observed**: ${intel.tools.join(", ") || "Custom malicious artifacts and scripts."}
* **MITRE ATT&CK Mapping**: Includes ${intel.ttps.slice(0, 3).join(", ") || "Standard evasion & C2 techniques."}

${intel.secrets && intel.secrets.length > 0 ? `### Discovered Secrets & Infrastructure Credentials\n\n| Category | Type | Observed Value / Identifier | Risk Level |\n|---|---|---|---|\n${intel.secrets.map((s) => `| **${s.category}** | ${s.type} | \`${s.value}\` | \`${s.risk}\` |`).join("\n")}\n` : ""}

${intel.aiAnalysis && intel.aiAnalysis.used ? `### AI Threat Assessment Summary\n\n${intel.aiAnalysis.analysisText}\n` : ""}

---

### Technical Telemetry & Verified Indicators (High Confidence)

| Indicator Type | Defanged Value / Cryptographic Hash | Operational Role & Context | Confidence |
|---|---|---|---|
${intel.highConfidenceIOCs.map((ioc) => `| **${ioc.type}** | \`${ioc.value}\` | ${ioc.role} | ${ioc.confidence} |`).join("\n")}
`;

  // 2. Generate Draft Blog Report
  const blogMarkdown = `---
title: "Technical Teardown of Staging Infrastructure at ${defang(intel.host)}"
description: "Forensic analysis of exposed malware staging, reverse engineering findings, and credentials at ${defang(intel.host)}."
publishedAt: ${new Date().toISOString().slice(0, 10)}
archiveSection: reports
tags:
  - "threat-intelligence"
  - "dfir"
  - "infrastructure"
cover: "/images/posts/exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure/img-01.png"
featured: true
draft: false
---

### Executive Summary

Analysis of exposed operational directory telemetry at \`${defang(intel.host)}:${intel.port || "443"}\` identified active staging artifacts, offensive tooling, and cryptographic components.

### 1. Observed Tooling & Capabilities
${intel.tools.map((t) => `* **${t}**`).join("\n")}

${intel.secrets && intel.secrets.length > 0 ? `### 2. Discovered Secrets, Cloud API Keys & Credentials\n\n| Category | Type | Identifier / Redacted Value | Source File | Risk |\n|---|---|---|---|---|\n${intel.secrets.map((s) => `| **${s.category}** | ${s.type} | \`${s.value}\` | \`${s.sourceFile}\` | \`${s.risk}\` |`).join("\n")}\n` : ""}

${intel.deobfuscation && intel.deobfuscation.recoveredKeys.length > 0 ? `### 3. Deobfuscated Payloads & Encryption Keys\n\n${intel.deobfuscation.recoveredKeys.map((k) => `* **Recovered Key**: \`${k.ascii}\` (Hex: \`${k.hex}\`) from ${k.source}`).join("\n")}\n` : ""}

${intel.forensics && intel.forensics.magicByteFindings.length > 0 ? `### 4. Binary Identification & Magic Byte Analysis\n\n| Filename | Signature Type | Hex Signature | Architecture / Details |\n|---|---|---|---|\n${intel.forensics.magicByteFindings.map((m) => `| \`${m.filename}\` | **${m.type}** | \`${m.hexSignature}\` | ${m.details} |`).join("\n")}\n` : ""}

${intel.aiAnalysis && intel.aiAnalysis.used ? `### 5. Local AI Technical Breakdown (${intel.aiAnalysis.model})\n\n${intel.aiAnalysis.analysisText}\n` : ""}

### 6. Verified High-Fidelity Indicators (IOCs)

| IOC Type | Indicator / Hash | Role & Context | Confidence |
|---|---|---|---|
${intel.highConfidenceIOCs.map((ioc) => `| **${ioc.type}** | \`${ioc.value}\` | ${ioc.role} | ${ioc.confidence} |`).join("\n")}

### 7. MITRE ATT&CK Mapping
${intel.ttps.map((ttp) => `* **${ttp}**`).join("\n")}
`;

  return {
    actorSlug,
    reportSlug,
    actorName,
    dossierMarkdown,
    blogMarkdown
  };
}

export async function publishContent(actorSlug, dossierMarkdown, reportSlug, blogMarkdown, config) {
  const actorsDir = resolve(config.paths.actorsOutputDir);
  const blogDir = resolve(config.paths.blogOutputDir);

  await mkdir(actorsDir, { recursive: true });
  await mkdir(blogDir, { recursive: true });

  const actorFile = `${actorsDir}/${actorSlug}.md`;
  const blogFile = `${blogDir}/${reportSlug}.md`;

  await writeFile(actorFile, dossierMarkdown);
  await writeFile(blogFile, blogMarkdown);

  console.log(`\n✅ [Published Dossier] ${actorFile}`);
  console.log(`✅ [Published Report] ${blogFile}`);

  return { actorFile, blogFile };
}

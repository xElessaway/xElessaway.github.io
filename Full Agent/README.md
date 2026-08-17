# 🛡️ Autonomous Cyber Threat Intelligence (CTI) Full Agent

This standalone package provides an end-to-end autonomous threat intelligence acquisition, forensic extraction, defanging, and dossier publishing engine.

---

## 📁 Architecture & File Structure

```
Full Agent/
├── agent.mjs            # Main CLI Autonomous Agent Runner
├── config.json          # Agent settings, GitHub integration & crawler limits
├── package.json         # Module definition & scripts
├── README.md            # Architecture & Extension guide
└── core/
    ├── triage.mjs       # Passive crawler, directory scraper & artifact saver
    ├── extractor.mjs    # Heuristic analyzer for C2s, tools, drivers & TTPs
    ├── defang.mjs       # IOC defanging engine for IPv4, domains, URLs
    └── generator.mjs    # Structured Markdown Dossier & Report generator
```

---

## ⚡ Quick Start

### 1. Run Analysis on a Target Link
```bash
node agent.mjs http://<target_ip>:<port>/
```

### 2. Run Analysis on Multiple Staging Servers
```bash
node agent.mjs http://101.42.255.92:8001/ http://2.27.63.244:9999/
```

---

## 🔬 How the Pipeline Works

1. **Passive Acquisition (`core/triage.mjs`)**:
   * Scrapes open directory indexes.
   * Downloads non-binary artifacts (`.bash_history`, `.log`, `.c`, `.py`, `config.h`, `.json`, `.sql`) into `./threat_intel_acquisitions/<target_host>/`.
2. **Feature Extraction (`core/extractor.mjs`)**:
   * Identifies C2 frameworks (Cobalt Strike, Adaptix, Mythic, CrossC2).
   * Identifies BYOVD vulnerable drivers (`HWiNFO`, `TRIXX`).
   * Maps behaviors to **MITRE ATT&CK TTPs** (`T1190`, `T1552.001`, `T1102.001`, `T1068`).
   * Extracts and defangs all observed IOCs.
3. **Dossier & Report Generation (`core/generator.mjs`)**:
   * Generates a structured **Threat Intel Dossier** in `src/content/actors/<slug>.md`.
   * Generates a companion **DFIR Investigation Report** in `src/content/blog/<slug>.md`.

---

## 🚀 How to Enhance & Expand in the Future

You can easily enhance this agent with:
* **LLM Integration**: Plug in local **Ollama** (`ollama run llama3`) or Cloud APIs (Gemini / OpenAI) in `core/extractor.mjs` to summarize complex `.c` code or binary reverse engineering outputs.
* **VirusTotal / Shodan API**: Enrich IP addresses with ASN, geolocations, and certificate histories in `core/triage.mjs`.
* **YARA Rule Generator**: Automatically synthesize YARA rules from extracted string tables.

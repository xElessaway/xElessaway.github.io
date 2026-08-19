---
title: "Imikom Agent: Analyzing GitHub and Google Sheets Cloud Dead-Drop C2 Tradecraft"
description: "Technical teardown of a sophisticated C-based malware development pipeline featuring GitHub Contents API and Google Sheets C2 channels, BYOVD EDR blinding, and process hollowing."
publishedAt: 2026-08-16
archiveSection: reports
tags: ["threat-intelligence","malware-analysis","byovd","mythic-c2","github-c2","edr-evasion"]
cover: "/images/posts/imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft/img-01.png"
featured: false
draft: false
---

### Executive Summary

Analysis of an exposed malware staging server at `2[.]27[.]63[.]244:9999` exposed the source code, automated compiler toolchains, and driver payloads for a stealthy implant framework designated **Imikom Agent**.

Designed specifically to operate within tightly monitored corporate enclaves with strict outbound traffic restrictions (e.g., Deep Packet Inspection on **FortiGate** and **Palo Alto** firewalls), Imikom replaces standard direct HTTP/HTTPS connections with **Cloud Dead-Drop Resolvers** running over **GitHub's Contents API** and **Google Sheets API**.

Furthermore, the framework incorporates **Bring Your Own Vulnerable Driver (BYOVD)** tradecraft, bundling signed kernel drivers (`HWiNFO_x64_206.sys` and `TRIXX.sys`) to disable endpoint detection and response (EDR) kernel hooks.

---

### 1. Cloud Dead-Drop C2 Transports

The most distinctive capability in the Imikom codebase is its pluggable transport architecture designed to blend malicious command-and-control into reputable cloud provider traffic.

#### A. GitHub Contents API Transport (`github_c2.c`)
As documented directly in the source comments:
> *`"FortiGate bypass: agent → api.github.com (trusted CDN) → relay → Mythic"`*

```c
/* Protocol sequence in github_c2.c */
// 1. Agent writes encrypted Mythic payload -> nodes/{agent_id}/out
// 2. Cloud Relay reads out, forwards to backend Mythic C2, writes response -> nodes/{agent_id}/in
// 3. Relay clears out, agent polls in, executes tasks and clears in
```

Because all client network traffic terminates on `https://api[.]github[.]com` over valid TLS certificates, corporate firewalls categorizing traffic by domain reputation perceive the communication as benign developer activity.

* **Relay Repository**: `derwingoww/edge-nodes`
* **Transport Headers**: Authenticated via embedded GitHub Personal Access Tokens (`ghp_...`).

#### B. Google Sheets API Transport (`deploy_google_sheets.c`)
In environments where GitHub access is restricted, the builder compiles an alternate transport utilizing **Google Sheets** as an asynchronous message queue:
* Interacts with `sheets[.]googleapis[.]com` and `oauth2[.]googleapis[.]com`.
* Uses OAuth2 client IDs and refresh tokens to read task commands from designated spreadsheet cells and write Base64-encoded execution results back to output sheets.

---

### 2. BYOVD: Kernel-Level EDR Blinding

The staging repository contained multiple signed, legitimate Windows hardware drivers known to possess arbitrary kernel read/write vulnerabilities:

* **`HWiNFO_x64_206.sys`** (HWiNFO kernel driver)
* **`TRIXX.sys`** (Sapphire TRIXX overclocking driver)

#### Mechanism of Action
By dropping and temporarily loading these signed drivers via the Service Control Manager (`CreateServiceA`), the unprivileged malware abuses driver IOCTL interfaces to write directly to kernel space (`ntoskrnl.exe`), nullifying EDR process creation callbacks (`PspCreateProcessNotifyRoutine`) and thread inspection routines.

---

### 3. Masquerading & In-Memory Execution

Imikom's build pipeline compiles customized binaries disguised as standard administrative tools:
* **`OfficeSupport.exe`** (Persists under `C:\ProgramData\Microsoft\Office` with a scheduled task)
* **`WindowsTelemetry.exe`**

#### Anti-Analysis & Memory Protections
1. **Stack String Obfuscation (`obfstr.h`)**: Crucial telemetry strings, C2 paths (`/api/v2/telemetry/batch`), and registry locations are encrypted at rest with multi-byte XOR keys and only decrypted onto the stack immediately prior to usage.
2. **Process Hollowing (`hollow.c`)**: Unpacks and injects the core PE payload into legitimate Windows host binaries (`svchost.exe`, `RuntimeBroker.exe`).
3. **AMSI & ETW Patching**: Automatically disables Antimalware Scan Interface (`AmsiScanBuffer`) and Event Tracing for Windows (`EtwEventWrite`) in memory before executing scripts.

---

### 4. Indicators of Compromise (Defanged)

| IOC Type | Indicator | Context |
|---|---|---|
| **IPv4** | `2[.]27[.]63[.]244` | Staging & Build Server (Fastweb, Italy) |
| **Port / Service** | `2[.]27[.]63[.]244:9999` | Exposed Tooling & Artifact Repository |
| **Domain** | `cdn-staticfiles[.]com` | Default Fallback HTTPS C2 Domain |
| **GitHub Repo** | `derwingoww/edge-nodes` | Covert Dead-Drop Relay Repository |
| **Driver Hash (SHA256)** | `HWiNFO_x64_206.sys` | Vulnerable Driver for BYOVD Kernel Blinding |
| **Driver Hash (SHA256)** | `TRIXX.sys` | Vulnerable Driver for BYOVD Kernel Blinding |
| **Persistence Task** | `OfficeSupport` | Scheduled Task Persistence |
| **Persistence Path** | `%APPDATA%\Microsoft\Office\OfficeSupport.exe` | Dropped Payload Path |

---

### 5. MITRE ATT&CK Mapping

* **T1102.001** – Web Service: Dead Drop Resolver (GitHub / Google Sheets C2)
* **T1068** – Exploitation for Privilege Escalation (BYOVD driver exploitation)
* **T1055.012** – Process Hollowing (Injection into trusted binaries)
* **T1562.001** – Disable or Modify Tools (AMSI patching & EDR callback blinding)
* **T1036.005** – Masquerading: Match Legitimate Name (`WindowsTelemetry.exe`)
* **T1027** – Obfuscated Files or Information (Stack string encryption)
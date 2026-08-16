---
name: "Imikom Ghost: Cloud Dead-Drop & Mythic C2 Operation"
aliases:
  - "Imikom Agent"
  - "EdgeNodes-C2"
  - "UNC-22763"
status: "active"
origin: "Unknown / European Infrastructure"
motivation: "Targeted infiltration of hardened corporate perimeters using cloud dead-drop channels and driver-level EDR blinding."
targets:
  - "Enterprises with Strict Egress Controls & Next-Gen Firewalls"
  - "Corporate Windows Workstations & Active Directory Networks"
firstSeen: "2026-06"
lastSeen: "2026-08"
tools:
  - "Imikom Agent (payload_win_prod.c)"
  - "Mythic C2 Framework"
  - "GitHub API Dead-Drop Relay (github_c2.c)"
  - "Google Sheets API C2 Transport (deploy_google_sheets.c)"
  - "HWiNFO_x64_206.sys (BYOVD Vulnerable Driver)"
  - "TRIXX.sys (BYOVD Vulnerable Driver)"
  - "Process Hollowing Engine (hollow.c)"
ttps:
  - "T1102.001 - Web Service: Dead Drop Resolver (GitHub / Google Sheets API)"
  - "T1068 - Exploitation for Privilege Escalation (BYOVD Driver Exploitation)"
  - "T1055.012 - Process Hollowing"
  - "T1562.001 - Disable or Modify Tools (AMSI & EDR Driver Blinding)"
  - "T1027 - Obfuscated Files or Information (Stack String Encryption / obfstr.h)"
  - "T1053.005 - Scheduled Task (OfficeSupport Persistence)"
  - "T1036.005 - Masquerading: Match Legitimate Name (WindowsTelemetry.exe, OfficeSupport.exe)"
tags:
  - "mythic-c2"
  - "byovd"
  - "github-c2"
  - "google-sheets-c2"
  - "edr-evasion"
timeline:
  - date: "2026-06-18"
    title: "Staging Pipeline & Mythic Backend Setup"
    summary: "Host 2[.]27[.]63[.]244 operationalized with automated C compilation toolchain (Mingw-w64) and Mythic C2 backend database."
  - date: "2026-07-02"
    title: "BYOVD Driver Weaponization"
    summary: "Integration of signed vulnerable hardware drivers (HWiNFO_x64_206.sys and TRIXX.sys) into payload builders for ring-0 kernel callback unhooking."
  - date: "2026-07-20"
    title: "GitHub & Google Sheets Dead-Drop Relay Integration"
    summary: "Development of github_c2.c and deploy_google_sheets.c transports specifically engineered to bypass corporate FortiGate deep packet inspection."
  - date: "2026-08-16"
    title: "Automated Build Pipeline Deployment"
    summary: "Active compilation of polymorphic loaders (Imikom v1-v10) masquerading as Microsoft Office Support and Windows Telemetry binaries."
references:
  - title: "Imikom Agent: Analyzing GitHub and Google Sheets Cloud Dead-Drop C2 Tradecraft"
    url: "https://xelessaway.me/blog/imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft/"
    publisher: "Ahmed Elessaway Threat Research"
relatedPosts:
  - "imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft"
featured: true
---

### Key Operational Findings

* **Cloud Dead-Drop Egress Bypasses**: Imikom replaces direct outbound connections with trusted CDN endpoints:
  - **GitHub Contents API (`github_c2.c`)**: Relays commands via repository `derwingoww/edge-nodes` (`nodes/{id}/out` and `nodes/{id}/in`) using authenticated PAT tokens to defeat Next-Gen Firewall (FortiGate/Palo Alto) inspection.
  - **Google Sheets API (`deploy_google_sheets.c`)**: Bi-directional command exchange via `sheets[.]googleapis[.]com` over OAuth2.
* **Kernel EDR Blinding (BYOVD)**: Staging signed drivers **`HWiNFO_x64_206.sys`** and **`TRIXX.sys`** to execute ring-0 kernel writes that disable `PspCreateProcessNotifyRoutine` callbacks.
* **Evasion & Masquerading**: Obfuscated binaries disguise as **`OfficeSupport.exe`** and **`WindowsTelemetry.exe`**, using in-memory process hollowing and XOR stack string decryption.

---

### Technical Telemetry & Indicators

| Indicator Type | Defanged Value | Operational Role |
|---|---|---|
| **IPv4 Address** | `2[.]27[.]63[.]244` | Staging & Compilation Node (Fastweb, Italy) |
| **Port / Service** | `2[.]27[.]63[.]244:9999` | Exposed Tooling & Staging Repository |
| **Domain** | `cdn-staticfiles[.]com` | Default Fallback HTTPS C2 Domain |
| **GitHub Relay** | `derwingoww/edge-nodes` | Covert Dead-Drop Relay Repository |
| **Driver (BYOVD)** | `HWiNFO_x64_206.sys` | Vulnerable Signed Driver for Kernel Callback Unhooking |
| **Driver (BYOVD)** | `TRIXX.sys` | Vulnerable Signed Driver for Kernel EDR Blinding |
| **Persistence** | `OfficeSupport` | Scheduled Task (`%APPDATA%\Microsoft\Office\OfficeSupport.exe`) |

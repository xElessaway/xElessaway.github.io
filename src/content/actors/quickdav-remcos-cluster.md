---
name: "QuickDAV Remcos Delivery Cluster"
aliases:
  - "QuickDAV-RAT"
  - "SciActive Cluster"
status: "active"
origin: "Unknown / Eastern Europe"
motivation: "Commodity malware distribution, credential theft, and persistent remote access infrastructure."
targets:
  - "Enterprise Networks"
  - "Financial Services"
  - "Government & Defense Contractors"
firstSeen: "2026-05"
lastSeen: "2026-08"
tools:
  - "Remcos 7.2.5 Pro"
  - "Remcos 7.2.4 Pro"
  - "SciActive QuickDAV 3.4.0"
  - "Donut PIC Shellcode"
  - "PowerShell Memory Loaders"
ttps:
  - "T1059.001 - Command and Scripting Interpreter: PowerShell"
  - "T1053.005 - Scheduled Task"
  - "T1027 - Obfuscated Files or Information"
  - "T1562.001 - Disable or Modify Tools (Defender Exclusions)"
  - "T1055.002 - Portable Executable Injection (Heap/VirtualAlloc)"
tags:
  - "remcos-rat"
  - "quickdav"
  - "c2-infrastructure"
  - "powershell"
timeline:
  - date: "2026-05-25"
    title: "Initial Repository Exposure"
    summary: "Earliest file modification timestamp recorded on the SciActive QuickDAV 3.4.0 server."
  - date: "2026-07-28"
    title: "Stage-0 Batch & Loader Deployment"
    summary: "Upload of open.bat and aiemgqgiewigsq279.jpj stage-1 delivery script."
  - date: "2026-08-13"
    title: "Passive Acquisition & Analysis"
    summary: "Extraction of 39 files, 7 Remcos C2 configs, and license/TLS certificate clustering."
references:
  - title: "Exposed: QuickDAV Malware Distribution Repository and Remcos RAT Infrastructure"
    url: "https://xelessaway.me/blog/exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure/"
    publisher: "Ahmed Elessaway Research"
relatedPosts:
  - "exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure"
featured: true
---

### Executive Summary

The **QuickDAV Remcos Delivery Cluster** is a persistent malware distribution network utilizing misconfigured/exposed **SciActive QuickDAV 3.4.0** WebDAV services on Node.js/Express to host multi-stage loaders and commodity RAT payloads.

#### Key Architectural Findings
- **Dual Delivery Paths**: Operates both registry-resident persistence loaders (via Scheduled Tasks and headless `conhost.exe`) and disk-backed `%APPDATA%\Microsoft\Windows\Themes` carriers with automated Windows Defender exclusions.
- **Payload Diversity**: Delivers 32-bit native **Remcos Pro (7.2.4 & 7.2.5)** with hardcoded C2 controllers, along with unmanaged position-independent Donut shellcode blobs.
- **Cluster Fingerprinting**: Static extraction identified 4 major infrastructure clusters sharing identical Remcos license IDs and TLS key material across the `151.241.154.0/24` subnet.

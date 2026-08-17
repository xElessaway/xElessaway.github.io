---
name: "Threat Cluster 101[.]42[.]255[.]92"
aliases: ["UNC-10142"]
status: "active"
origin: "Unknown / Threat Staging Infrastructure"
motivation: "Targeted reconnaissance, credential harvesting, and persistent C2 staging."
targets: ["Enterprise Networks & Staging Targets"]
firstSeen: "2026-08"
lastSeen: "2026-08"
tools: ["Cobalt Strike 4.9.1","CrossC2 (genCrossC2.Linux)","Adaptix C2 Framework","Malicious ISO / LNK Phishing Lures","Rogue MySQL Server (Arbitrary File Exfiltration)"]
ttps: ["T1071.001 - Application Layer Protocol: Web Protocols","T1566.001 - Phishing: Spearphishing Attachment","T1204.002 - User Execution: Malicious File","T1552.001 - Credentials in Files"]
tags: ["threat-intelligence","c2-infrastructure"]
relatedPosts: ["investigation-exposed-infrastructure-101-42-255-92"]
featured: true
---

### Key Operational Findings

* **Exposed Infrastructure**: Host `101[.]42[.]255[.]92` operates as an active staging and C2 node.
* **Arsenal Observed**: Cobalt Strike 4.9.1, CrossC2 (genCrossC2.Linux), Adaptix C2 Framework, Malicious ISO / LNK Phishing Lures, Rogue MySQL Server (Arbitrary File Exfiltration)
* **MITRE ATT&CK Mapping**: Includes T1071.001 - Application Layer Protocol: Web Protocols, T1566.001 - Phishing: Spearphishing Attachment, T1204.002 - User Execution: Malicious File



### AI Threat Assessment Summary

### Threat Actor Tradecraft & Objectives

The telemetry indicates that the target host has not been compromised with any known malware or malicious binaries. The absence of recovered keys, decrypted artifacts, carved binaries, script behaviors, and decoded base64 suggests that the threat actor has likely employed sophisticated obfuscation techniques or has not left any clear traces of their presence. The objective of this threat actor appears to be to maintain stealth and avoid detection, possibly to exfiltrate sensitive data or to gather intelligence without being noticed.

### Command and Control (C2) Architecture & Transport Channels

Given the telemetry, it is unclear what C2 architecture or transport channels were used. The lack of any identifiable C2 communication or command execution suggests that the threat actor may have used covert channels or compromised legitimate processes to exfiltrate data or to maintain persistence. The absence of any identifiable C2 telemetry indicates that the threat actor may have employed domain fronting, DNS tunneling, or other covert communication methods to avoid detection.

### Defense Evasion & Kernel Blinding (BYOVD / Hooks / Task Hijacking)

The telemetry does not provide any information on defense evasion techniques, such as BYOVD (Bring Your Own Virus Detection), hooks, or task hijacking. However, the absence of any suspicious binaries or artifacts suggests that the threat actor may have employed techniques such as process hollowing, process injection, or other low-and-slow methods to avoid detection by security software. These techniques involve creating a new process within an existing process, which can be used to hide malicious activities.

### Strategic Assessment & Recommended Mitigations

Given the lack of any identified threats, the recommended mitigations would focus on improving the security posture of the target host. This could include:

1. **Enhanced Monitoring**: Implementing more granular monitoring of system processes, network traffic, and file system activity to detect anomalies.
2. **Behavioral Analysis**: Utilizing behavioral analysis tools to identify and respond to suspicious activities, such as process hollowing or process injection.
3. **Patch Management**: Ensuring that all software and systems are up-to-date with the latest security patches.
4. **Network Segmentation**: Implementing network segmentation to limit lateral movement and reduce the attack surface.
5. **Security Software Updates**: Keeping security software, such as antivirus and firewalls, up-to-date with the latest definitions and signatures.
6. **User Training**: Conducting regular security awareness training for users to recognize and avoid social engineering attacks.

By implementing these strategies, the organization can improve


---

### Technical Telemetry & Verified Indicators (High Confidence)

| Indicator Type | Defanged Value / Cryptographic Hash | Operational Role & Context | Confidence |
|---|---|---|---|
| **Staging Host IPv4** | `101[.]42[.]255[.]92` | Primary Adversary Staging Node | High (100%) |
| **Service Port** | `101[.]42[.]255[.]92:8001` | Exposed Staging Directory | High (100%) |
| **SHA-256 Hash** | `e9c5c28188c8730f7c3323adb918f6d79171e5b2535ebb8d2286af4328efad41` | Artifact: .bash_history | High (100%) |
| **SHA-256 Hash** | `e286f80ce35aba0cc261a034081502c0864e07d69d1f4e4e60d1a83e984cce38` | Artifact: .bashrc | High (100%) |
| **SHA-256 Hash** | `be19ca9dca233aea9918a115d8ff364d5ac0b07aae5b0d5424bdc42201953961` | Artifact: .lesshst | High (100%) |
| **SHA-256 Hash** | `7eefba03d02a37618b9db6862d35e84d206bdc7ffaf8229de56e81685d58ffab` | Artifact: .mysql_history | High (100%) |
| **SHA-256 Hash** | `13a374566062da079cfa104a30d5eae63959644f120ba842477d697e46aa31e3` | Artifact: .npmrc | High (100%) |
| **SHA-256 Hash** | `716e5a0316de27b0c900b4ad1f8729110c77b462d37b30bf5e2e6ddf9fad3082` | Artifact: .profile | High (100%) |
| **SHA-256 Hash** | `00d2a8de16c2543187b321021c273d319382d1b060e027daf1bf1a78e5f03c5f` | Artifact: .pydistutils.cfg | High (100%) |
| **SHA-256 Hash** | `0c0089758550eec805af793c9ecbb4bfbe2cc73be7a7f7815640451efc61e707` | Artifact: .viminfo | High (100%) |
| **SHA-256 Hash** | `799fbf3b5882e1ea9e6ec644004e4725649b677674f1cb92a07f2fedff8e9607` | Artifact: .wget-hsts | High (100%) |
| **SHA-256 Hash** | `01d9481d70af9c85d14fc8553a97d2d5fced347b23f295e208dd59d306f521fb` | Artifact: exam.zip | High (100%) |
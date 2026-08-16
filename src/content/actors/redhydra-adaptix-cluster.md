---
name: "RedHydra Adaptix & Cobalt Strike Cluster"
aliases:
  - "RedHydra-C2"
  - "RRR_C2 Cluster"
  - "UNC-10142"
status: "active"
origin: "China / Asia-Pacific"
motivation: "Targeted reconnaissance, access brokerage, and exploitation of public health and municipal infrastructure."
targets:
  - "Healthcare & Health Commissions (卫生健康委员会)"
  - "Municipal Portals & Government Administration"
  - "Enterprise Java / Spring Cloud Backends"
firstSeen: "2026-05"
lastSeen: "2026-08"
tools:
  - "Cobalt Strike 4.9.1 (TeamServer)"
  - "CrossC2 (genCrossC2.Linux)"
  - "Adaptix C2 Framework"
  - "RRR_C2 Custom Mod (v1.2)"
  - "Rogue MySQL Server (Arbitrary File Read)"
  - "JNDIExploit / Marshalsec"
  - "ENScan_GO Enterprise Recon"
  - "Impacket SMB Server"
ttps:
  - "T1190 - Exploit Public-Facing Application (Fastjson/JNDI/Log4j)"
  - "T1552.001 - Credentials in Files (Rogue MySQL application-dev.yml extraction)"
  - "T1059.004 - Unix Shell"
  - "T1562.001 - Disable or Modify Tools (Tencent Cloud YunJing EDR uninstallation)"
  - "T1071.001 - Web Protocols (Adaptix/Cobalt Strike HTTPS C2)"
  - "T1596 - Search Open Technical Databases (ENScan_GO)"
  - "T1090.003 - Multi-hop Proxy (Automated Proxy Pool)"
tags:
  - "cobalt-strike"
  - "adaptix-c2"
  - "rogue-mysql"
  - "jndi"
  - "threat-actor"
timeline:
  - date: "2026-05-12"
    title: "VPS Provisioning & EDR Neutralization"
    summary: "Host 101[.]42[.]255[.]92 provisioned on Tencent Cloud; attacker systematically executed uninstallers to terminate YunJing/YDEdr security monitoring."
  - date: "2026-06-04"
    title: "Adaptix & Cobalt Strike 4.9.1 TeamServer Deployment"
    summary: "Operator compiled and established persistent systemd daemons for AdaptixC2 and launched Cobalt Strike 4.9.1 TeamServer with CrossC2 payload generation."
  - date: "2026-07-15"
    title: "Healthcare Reconnaissance Campaign"
    summary: "Execution of ENScan_GO enterprise asset scanners against regional Health Commissions (卫生健康委员会) and municipal service portals."
  - date: "2026-08-16"
    title: "Rogue MySQL Server & JNDI Exploitation"
    summary: "Active exploitation using Rogue MySQL to weaponize JDBC client file-read capabilities against Java spring backends, retrieving application-dev.yml configs."
references:
  - title: "Dissecting Exposed Adaptix C2 and Rogue MySQL Exploitation Infrastructure"
    url: "https://xelessaway.me/blog/dissecting-exposed-adaptix-c2-and-rogue-mysql-exploitation-infrastructure/"
    publisher: "Ahmed Elessaway Threat Research"
relatedPosts:
  - "dissecting-exposed-adaptix-c2-and-rogue-mysql-exploitation-infrastructure"
featured: true
---

### Key Operational Findings

* **Infrastructure Staging**: Host `101[.]42[.]255[.]92` operates as a centralized Command & Control hub and offensive staging node hosted on Tencent Cloud.
* **Dual C2 Backbone**: Runs Cobalt Strike 4.9.1 on port `8081` alongside the modern **AdaptixC2** and customized `RRR_C2_v1.2` frameworks.
* **Specialized Protocol Attack**: The cluster leverages **Rogue MySQL Server (port 3306)** to abuse MySQL's `LOCAL INFILE` protocol feature, forcing connected Java/Spring clients to exfiltrate arbitrary files (`application-dev.yml`, internal `.jar` packages).
* **Targeting Vertical**: Direct reconnaissance against municipal and public health administration infrastructure (`卫生健康委员会`).

---

### Technical Telemetry & Indicators

| Indicator Type | Defanged Value | Operational Role |
|---|---|---|
| **IPv4 Address** | `101[.]42[.]255[.]92` | Staging, Cobalt Strike & Adaptix C2 Node |
| **Port / Service** | `101[.]42[.]255[.]92:8081` | Cobalt Strike TeamServer Listener |
| **Port / Service** | `101[.]42[.]255[.]92:3306` | Rogue MySQL Arbitrary File Exfiltration Listener |
| **Port / Service** | `101[.]42[.]255[.]92:8555` | JNDI / HTTP Payload Delivery |
| **Port / Service** | `101[.]42[.]255[.]92:8857` | Interactive Reverse Shell Listener |
| **Tool Artifact** | `genCrossC2.Linux` | Cross-platform Linux ELF Cobalt Strike Beacon Compiler |
| **Tool Artifact** | `rogue_mysql_server` | JDBC Protocol Arbitrary Client File Extraction Tool |

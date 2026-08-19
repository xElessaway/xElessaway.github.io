---
name: "Threat Cluster 47[.]109[.]196[.]181"
aliases: []
status: "tracking"
origin: "Unknown / observed staging infrastructure"
motivation: "Dual-vector threat staging operation distributing Android accessibility spyware and remote access trojans (harvesting victim screen telemetry, keystrokes, and accessibility events) alongside weaponized Linux local privilege escalation exploits (Dirty COW / efull) and PHP upload webshells."
targets: ["Mobile Endpoints (Android Device Users & Mobile Banking/Messaging Portals)","Enterprise Linux Web Servers & Staging Infrastructure"]
firstSeen: "2026-08-19"
lastSeen: "2026-08-19"
tools: ["HTML Smuggling / In-memory file synthesis","Linux Kernel Privilege Escalation / Local Root Exploits","Android Accessibility Service (无障碍) Abuse & Telemetry Exfiltration","Automated Screenshot Capture & Exfiltration"]
ttps: ["T1027.006 - HTML Smuggling","T1068 - Exploitation for Privilege Escalation","T1627 - Android Telemetry Abuse","T1113 - Screen Capture","T1552.001 - Credentials In Files"]
tags: ["threat-intelligence","dfir","malware-analysis"]
relatedPosts: ["investigation-47-109-196-181"]
featured: true
---

# Threat Cluster 47[.]109[.]196[.]181

> This dossier is generated from static acquisition and recursive analysis. Suspicious artifacts are preserved in **per-investigation encrypted quarantine** with a unique data key and are **not executed** by the pipeline.

### Evidence Coverage

| Metric | Value |
|---|---:|
| Acquired artifacts | 37 |
| Text artifacts | 18 |
| Binary/container artifacts | 19 |
| Unique acquired/decoded layers analyzed | 180 |
| Maximum recursive depth reached | 2 |
| Archive/disk-image entries extracted | 313 |
| PE candidates statically identified | 0 |
| Credential/key/token findings | 1 |
| Recursive queue exhausted within configured limits | Yes |

## Motivation & Objectives

### Strategic Motivation
Dual-vector threat staging operation distributing Android accessibility spyware and remote access trojans (harvesting victim screen telemetry, keystrokes, and accessibility events) alongside weaponized Linux local privilege escalation exploits (Dirty COW / efull) and PHP upload webshells.

### Operational Objectives
- **Mobile Spyware Distribution**: Hosting and updating Android APK and Dalvik (.dex) implants equipped with accessibility service (无障碍) logging and automated screenshot exfiltration.
- **Host Privilege Escalation**: Staging weaponized Linux kernel root exploits (Dirty COW, efull, dcrun) and audit scripts to elevate privileges and defend staging infrastructure.
- **Web Infrastructure Staging**: Operationalizing PHP webshells and upload handlers for dynamic remote payload staging and command execution.
- **Defense Evasion**: Impairing telemetry monitoring and antivirus/EDR real-time scanning.
- **Credential Access**: Harvesting plaintext passwords, API keys, and environment tokens from exposed files.

### Inferred Target Profile
- Mobile Endpoints (Android Device Users & Mobile Banking/Messaging Portals)
- Enterprise Linux Web Servers & Staging Infrastructure

### Key Operational Findings

- HTML Smuggling / In-memory file synthesis
- Linux Kernel Privilege Escalation / Local Root Exploits
- Android Accessibility Service (无障碍) Abuse & Telemetry Exfiltration
- Automated Screenshot Capture & Exfiltration

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
|---|---|---|---|
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `qdw.apk` / L1 (zip-entry:assets/modules/npm/cheerio.js) |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
|---|---|---|---|
| **Investigated Host** | `47[.]109[.]196[.]181` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `47[.]109[.]196[.]181:80` | User-supplied investigated HTTP(S) service | High (observed) |
| **SHA-256 Hash** | `d8dd09b01eb4e363d88ff53c0aace04c39dbea822b7adba7a883970abbf72a77` | Acquired artifact: 855c3273-85d3-4db0-a04b-a164dcf8b613_sp=r (Linux ELF Binary) | High (computed) |
| **SHA-256 Hash** | `1f325cef63653aae070e74e84b7896796d7513c640639b6e2a2c2942e4116a42` | Acquired artifact: dc1 (Linux ELF Binary) | High (computed) |
| **SHA-256 Hash** | `34966d1db7c916440b4c3b6f74c1237cb0de55818309dfca9052290cb15df4fd` | Acquired artifact: efull (Linux ELF Binary) | High (computed) |
| **SHA-256 Hash** | `8d26e7b51cfcb45330c22d8ddc3092423d573f6f6dacc99fa948c3e28a814c1a` | Acquired artifact: exploit.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `12c2d06affb4aec5d20321af3fbbea7c4c68dfeb8be6dae606def63559dede94` | Acquired artifact: fh.dex (Android Dalvik Executable (DEX)) | High (computed) |
| **SHA-256 Hash** | `8dcef4460a4ac5e774b2c50cf5f72921f3ce3d1a10f115be40455ae26bc7c469` | Acquired artifact: fhhotversion.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2e2d5a551250572a2117a4ef477acb5c5318e6886208ed814acff287328c4a33` | Acquired artifact: linux-exploit-suggester.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `563a2aaa61e13684690be7e75d54a478bbc619f3aec3fda77094da13f6ca4cbc` | Acquired artifact: qdw.apk (ZIP-compatible Archive) | High (computed) |
| **SHA-256 Hash** | `8700462941d46269f54459fdd6be3a75ee3ba89f42ff5b22837e08fcec47b73f` | Acquired artifact: qdwdex.dex (Android Dalvik Executable (DEX)) | High (computed) |
| **SHA-256 Hash** | `db38455f4d6fc73c8135322369c1b49c50eb1c1d3a2d2fef95048ca37308ebe3` | Acquired artifact: qdwdex.sha256 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2788952ebe85f64faab393233d024d3403c502f9bb4974f39e16b1f2e70f3a0f` | Acquired artifact: qdwhotversion.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `59854984853104df5c353e2f681a15fc7924742f9a2e468c29af248dce45ce03` | Acquired artifact: qdwversion.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `00a1fb2812f96b1c951e67bf3e2d56ec2617fa0a32b53ce94fb2e83fb2d7f419` | Acquired artifact: screenshot_1779509068742_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `7e57ff860acec75bb45c4f68f102da125397ca5648653313446fdceba0f24362` | Acquired artifact: screenshot_1779509082560_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `56c0a46ce12cdadc6e5f2805dffd11a34109282cf694890eacf8a3e564a4a80e` | Acquired artifact: screenshot_1779509847953_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `291d1e82991ae95e371a23b379c737d6e755683fc03d9b06994538438f7cb40d` | Acquired artifact: screenshot_1779509865344_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `b694a50adb81ca880c47a6919454f8c5b98fc4d083c8124d1f0a92988785a1a4` | Acquired artifact: screenshot_1779509942356_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `54927582ae30c80bf5147e3ba803415079e1c94c810dd520c9cfd35d69480e77` | Acquired artifact: screenshot_1779534039610_upload.jpg (JPEG Image) | High (computed) |
| **SHA-256 Hash** | `adffc9cfa36d3927dbd2d11046a6d3eb3f434bfbd4a17d6a0355e4f12c259e48` | Acquired artifact: shell.php (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `397c8f12e7340fedf35a8d20907762de0ccdbf971d0447585a03e945ae92f9d4` | Acquired artifact: update (Linux ELF Binary) | High (computed) |
| **SHA-256 Hash** | `12079d77cb3633c6a22c4c8722fb82146dd78072d99a4fa60bdb0dc6205d2680` | Acquired artifact: upload.php (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `11e2f85f9eecd2472eb37290defaeacbbf3b6837edd07d4d7219df368fe8d60c` | Acquired artifact: wuzhangai_1779509068742.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b79f374cd9c50c966214fdc0bdecc61af76ca7b75fd2c30a86bf22097bce36a1` | Acquired artifact: wuzhangai_1779509082560.txt (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `994c5d059318355ea815cdd5cc70aec9bac6d70c96fa1504aa5589bc03244ed7` | Acquired artifact: wuzhangai_1779509847953.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `20fb8690c0fa5b01143f3664634aae73cc62530e75d602b079372a6818787f0a` | Acquired artifact: wuzhangai_1779509865344.txt (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `22a2caa348308c401049d67dc21b7e5c93da167495db2c467b387843ca8c5d52` | Acquired artifact: wuzhangai_1779509942356.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2ace47f2b47e6cad2b2d8883c318561199031faf951d948f9794197915ea08eb` | Acquired artifact: wuzhangai_1779534039610.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d99a7b458c51243bd2e554272f413a3d368525b04de505ebca98843b35fb63e3` | Acquired artifact: yh.apk (ZIP-compatible Archive) | High (computed) |
| **SHA-256 Hash** | `e9bdd0010b8ad74b752f1240bbd05f648768ed98fdcb670d3377f7d04f9b3509` | Acquired artifact: yhdex.dex (Android Dalvik Executable (DEX)) | High (computed) |
| **SHA-256 Hash** | `f69ee8d3f2c741ce497327143af238581421573c4cf387ccbb633918033cae51` | Acquired artifact: yhdex.sha256 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `28cb8f1299bee499c8fd2b3b88e3fbae260a2b86b7310329fec85cf834954b8f` | Acquired artifact: yhhotversion.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `92521fc3cbd964bdc9f584a991b89fddaa5754ed1cc96d6d42445338669c1305` | Acquired artifact: yhversion.txt (Plain/Textual Content) | High (computed) |
| **URL** | `hxxps://github.com/xeloxa` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]kernel[.]org/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/mzet-` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://isec[.]pl/vulnerabilities/isec-0021-uselib.txt` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20111103042904/hxxp://tarantula[.]by[.]ru/localroot/2.6.x/elflbl` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20111103042904/hxxp://tarantula[.]by[.]ru/localroot/2.6.x/h00lyshit` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://xorl[.]wordpress[.]com/2009/07/16/cve-2009-1895-linux-kernel-per_clear_on_setid-personality-bypass/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/9435.tgz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/9436.tgz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/9641.tar.gz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/9574.tgz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://blog[.]cr0[.]org/2009/08/cve-2009-2698-udpsendmsg-vulnerability.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack/raw/master/2009/CVE-2009-2698/katon.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20111103042904/hxxp://tarantula[.]by[.]ru/localroot/2.6.x/kmod2` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20111103042904/hxxp://tarantula[.]by[.]ru/localroot/2.6.x/ptrace-kmod` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192641/hxxps://www[.]kernel-exploits[.]com/media/ptrace_kmod2-64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://jon[.]oberheide[.]org/blog/2010/04/10/reiserfs-reiserfs_priv-vulnerability/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://jon[.]oberheide[.]org/files/team-edward.py` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192641/hxxps://www[.]kernel-exploits[.]com/media/can_bcm` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]securityfocus[.]com/archive/1/514379` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://web[.]archive[.]org/web/20101020044048/hxxp://www[.]vsecurity[.]com/download/tools/linux-rds-exploit.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192641/hxxps://www[.]kernel-exploits[.]com/media/rds` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192641/hxxps://www[.]kernel-exploits[.]com/media/rds64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/half-nelson3` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://git[.]zx2c4[.]com/CVE-2012-0056/about/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://git[.]zx2c4[.]com/CVE-2012-0056/plain/mempodipper.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/memodipper` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/memodipper64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://vulnfactory[.]org/exploits/full-nelson.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/full-nelson` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/full-nelson64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://stealth[.]openwall[.]net/xSports/clown-newuser.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://lwn[.]net/Articles/543273/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://timetobleed[.]com/a-closer-look-at-a-recent-privilege-escalation-bug-in-linux-cve-2013-2094/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/perf_swevent` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/perf_swevent64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cyseclabs[.]com/exploits/vnik_v1.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2013/04/29/1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://blog[.]includesecurity[.]com/2014/03/exploit-CVE-2014-0038-x32-recvmmsg-kernel-vulnerablity.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/timeoutpwn64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://blog[.]includesecurity[.]com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cyseclabs[.]com/page?n=02012016` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2014/06/10/4` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2014/07/08/16` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cyseclabs[.]com/page?n=01102015` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://labs[.]bromium[.]com/2015/02/02/exploiting-badiret-vulnerability-cve-2014-9322-linux-kernel-privilege-escalation/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://site.pi3[.]com[.]pl/exp/p_cve-2014-9322.tar.gz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2015/08/04/8` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://seclists[.]org/oss-sec/2015/q2/717` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/ofs_32` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://web[.]archive[.]org/web/20160602192631/hxxps://www[.]kernel-exploits[.]com/media/ofs_64` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]halfdog[.]net/Security/2015/UserNamespaceOverlayfsSetuidWriteExec/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://perception-point[.]io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cyseclabs[.]com/blog/cve-2016-0728-poc-not-working` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://xairy[.]github[.]io/blog/2016/cve-2016-2384` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/40053.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://bugs[.]chromium[.]org/p/project-zero/issues/detail?id=808` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://access[.]redhat[.]com/sites/default/files/rh-cve-2016-5195_5.sh` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]exploit-db[.]com/download/40847` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2016/12/06/1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/rapid7/metasploit-framework/master/data/exploits/CVE-2016-8655/chocobo_root` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2017/02/22/3` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://googleprojectzero[.]blogspot[.]com/2017/05/exploiting-linux-kernel-via-packet.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/rapid7/metasploit-framework/master/data/exploits/cve-2017-7308/exploit` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://ricklarabee[.]blogspot[.]com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/rapid7/metasploit-framework/master/data/exploits/cve-2017-16995/exploit.out` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]openwall[.]com/lists/oss-security/2017/08/13/1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/rapid7/metasploit-framework/master/data/exploits/cve-2017-1000112/exploit.out` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]qualys[.]com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]qualys[.]com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gist[.]githubusercontent[.]com/wbowling/9d32492bd96d9e7c3bf52e23a0ac30a4/raw/959325819c78248a6437102bb289bb8578a135cd/cve-2018-5333-poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/kernel-exploits/master/CVE-2018-5333/cve-2018-5333.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]qualys[.]com/2018/09/25/cve-2018-14634/mutagen-astronomy-integer-overflow-linux-create_elf_tables-cve-2018-14634.txt` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://bugs[.]chromium[.]org/p/project-zero/issues/detail?id=1712` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://bugs[.]chromium[.]org/p/project-zero/issues/detail?id=1903` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/47133.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://duasynt[.]com/blog/ubuntu-centos-redhat-privesc` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/duasynt/xfrm_poc/raw/master/lucky0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://blog[.]grimm-co[.]com/2021/03/new-old-bugs-in-linux-kernel.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]graplsecurity[.]com/post/kernel-pwning-with-ebpf-a-love-story` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://ssd-disclosure[.]com/ssd-advisory-overlayfs-pe/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/briskets/CVE-2021-3493/refs/heads/main/exploit.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://google[.]github[.]io/security-research/pocs/linux/cve-2021-22555/writeup.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://dirtypipe[.]cm4all[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://haxx[.]in/files/dirtypipez.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/The-Z-Labs/bof-launcher/refs/heads/main/bofs/src/dirtypipe.zig` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/Bonfee/CVE-2022-0995` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/Bonfee/CVE-2022-0995/archive/refs/heads/main.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]openwall[.]com/lists/oss-security/2022/08/29/5` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]openwall[.]com/lists/oss-security/2022/08/29/5/1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://research[.]nccgroup[.]com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://blog[.]theori[.]io/research/CVE-2022-32250-linux-kernel-lpe-2022/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/theori-io/CVE-2022-32250-exploit/main/exp.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://securitylabs[.]datadoghq[.]com/articles/overlayfs-cve-2023-0386/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/xkaneiki/CVE-2023-0386/archive/refs/heads/main.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://pwning[.]tech/nftables/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/Notselwyn/CVE-2024-1086/archive/refs/heads/main.zip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]openwall[.]com/lists/oss-security/2011/08/13/2` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://raw[.]githubusercontent[.]com/bcoles/local-exploits/master/CVE-2011-2921/ktsuss-lpe.sh` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://seclists[.]org/fulldisclosure/2012/Jan/att-590/advisory_sudo.txt` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://seclists[.]org/oss-sec/2014/q2/430` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://googleprojectzero[.]blogspot[.]com/2014/08/the-poisoned-nul-byte-2014-edition.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gitlab[.]com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/34421.tar.gz` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://openwall[.]com/lists/oss-security/2015/04/14/4` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gist[.]githubusercontent[.]com/taviso/0f02c255c13c5c113406/raw/eafac78dce51329b03bea7167f1271718bee4dcc/newpid.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://seclists[.]org/oss-sec/2015/q2/130` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gist[.]githubusercontent[.]com/taviso/fe359006836d6cd1091e/raw/32fe8481c434f8cad5bcf8529789231627e5074c/raceabrt.c` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]JSON[.]org/js.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://javascript[.]crockford[.]com/jsmin.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://en[.]wikipedia[.]org/wiki/ANSI_escape_code#graphics` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://msdn[.]microsoft[.]com/en-us/library/ie/dww52sbt(v=vs.94` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://bluebirdjs[.]com/docs/api-reference.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://goo[.]gl/MqrFmX\u000a` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://goo[.]gl/rRqMUw` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://goo[.]gl/MqrFmX\u000a\u000a` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/tj/co` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/petkaantonov/bluebird` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://bluebirdjs[.]com/docs/api/promise.coroutine.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://bluebirdjs[.]com/docs/api/promise.coroutine.addyieldhandler.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://babeljs[.]io/docs/plugins/transform-async-to-module-method/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/novacrazy/bluebird-co/tree/master/benchmark` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://docs[.]npmjs[.]com/files/package.json#peerdependencies` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/tj/co/blob/master/Readme.md#examples` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://developer[.]mozilla[.]org/en-US/docs/Web/JavaScript/Reference/Global_Objects/GeneratorFunction` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://developer[.]mozilla[.]org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Generator` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/pkaminski` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://img[.]shields[.]io/npm/v/bluebird-co.svg?style=flat` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://npmjs[.]org/package/bluebird-co` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://img[.]shields[.]io/npm/dm/bluebird-co.svg?style=flat` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://travis-ci[.]org/novacrazy/bluebird-co.svg?branch=master` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://travis-ci[.]org/novacrazy/bluebird-co` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://img[.]shields[.]io/npm/l/bluebird-co.svg?style=flat` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://developer[.]mozilla[.]org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/from` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/tj/co/issues/180` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/novacrazy/bluebird-co` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/novacrazy/bluebird-co/issues` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://en[.]wikipedia[.]org/wiki/Base64#URL_applications` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/beatgammit/base64-js/issues/42` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://feross[.]org` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://bugzilla[.]mozilla[.]org/show_bug.cgi?id=695438` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/feross/buffer/pull/148` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/feross/buffer/issues/154` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://stackoverflow[.]com/a/22747272/680742,` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/feross/buffer/issues/166` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/feross/buffer/issues/219` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://feross[.]org/opensource` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/removeAttr/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/hasClass/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/addClass/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/removeClass/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/toggleClass/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/css/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/jquery/jquery/blob/2.1.3/src/manipulation/var/rcheckableType.js` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/jquery/jquery/blob/2.1.3/src/serialize.js` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/serialize/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/serializeArray/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/appendTo/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/prependTo/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/append/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/prepend/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/wrap/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/wrapInner/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/unwrap/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/wrapAll/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/after/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/insertAfter/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/before/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/insertBefore/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/remove/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/replaceWith/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/empty/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/clone/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/find/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/parent/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/parents/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/parentsUntil/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/closest/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/next/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/nextAll/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/nextUntil/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/prev/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/prevAll/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/prevUntil/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/siblings/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/children/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/contents/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/each/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/map/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/is/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/not/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/has/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/first/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/last/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/eq/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/index/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/slice/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/end/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/add/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/addBack/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/TypeStrong/typedoc/issues/1616` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cheerio[.]js[.]org#loading` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/jQuery.contains/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]jquery[.]com/jQuery.merge/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/slevithan/xregexp/blob/95eeebeb8fac8754d54eafe2b4743661ac1cf028/src/xregexp.js#L794` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/semantics-other.html#case-sensitivity-of-selectors` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/fb55/css-select/pull/43#issuecomment-225414692` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/scripting.html#disabled-elements` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/form-elements.html#concept-option-selectedness` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/jquery/sizzle/blob/master/src/sizzle.js#L152` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/parsing.html#parsing-main-inforeign` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://dom.spec[.]whatwg[.]org` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://dom.spec[.]whatwg[.]org/#dom-node-comparedocumentposition` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://developer[.]mozilla[.]org/en-US/docs/Web/API/Node/textContent` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://developer[.]mozilla[.]org/en-US/docs/Web/API/Node/innerText` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/parsing.html#named-character-reference-state` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/mathiasbynens/he/blob/36afe179392226cf1b6ccdb16ebbb7a5a844d93a/src/he.js#L106-L134` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mathiasbynens[.]be/notes/javascript-encoding#surrogate-formulae` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/parsing.html#escapingString` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/fb55/boolbase` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]ibm[.]com/data/dtd/v11/ibmxhtml1-transitional.dtd` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://dom.spec[.]whatwg[.]org/#concept-document-limited-quirks` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html.spec[.]whatwg[.]org/multipage/parsing.html#clear-the-list-of-active-formatting-elements-up-to-the-last-marker` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]whatwg[.]org/specs/web-apps/current-work/multipage/tree-construction.html#adoptionAgency` | Observed in acquired/decoded evidence | High (string evidence) |
| **IPv4** | `1[.]1[.]1[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `255[.]255[.]255[.]255` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `127.0.0.2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `10[.]99[.]0[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `12[.]3[.]1[.]6` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `12[.]3[.]1[.]8` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `2[.]6[.]33[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `2[.]6[.]33[.]9` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `5[.]13[.]0[.]37` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `13[.]3[.]3[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `proton.me` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `github.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.kernel.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `logging.INFO` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `log.info` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `web.archive.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `tarantula.by.ru` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `xorl.wordpress.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `gitlab.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `blog.cr0.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.kernel-exploits.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `jon.oberheide.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.securityfocus.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.vsecurity.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `git.zx2c4.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `vulnfactory.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `stealth.openwall.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `lwn.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `timetobleed.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `cyseclabs.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.openwall.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `blog.includesecurity.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `labs.bromium.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `site.pi3.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `seclists.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.halfdog.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `perception-point.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `xairy.github.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `raw.githubusercontent.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `bugs.chromium.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `dirtycow.github.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `access.redhat.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.exploit-db.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `googleprojectzero.blogspot.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ricklarabee.blogspot.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.qualys.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `gist.githubusercontent.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `duasynt.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `blog.grimm-co.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `codeload.github.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.graplsecurity.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ssd-disclosure.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `google.github.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `dirtypipe.cm4all.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `research.nccgroup.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `blog.theori.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `theori.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `securitylabs.datadoghq.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `pwning.tech` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `openwall.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `Tt.cC` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `java.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `Packages.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `runtime.app` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `android.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `options.cc` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `com.stardust.app` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `console.info` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `rtConsole.info` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `runtime.info` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `comparators.top` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.JSON.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `javascript.crockford.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `en.wikipedia.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `msdn.microsoft.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `bluebirdjs.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `babeljs.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `docs.npmjs.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `developer.mozilla.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `img.shields.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `npmjs.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `travis-ci.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `co.co` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `exports.co` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `gmail.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `feross.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `bugzilla.mozilla.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `stackoverflow.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `api.jquery.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `cheerio.js.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `html.spec.whatwg.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `dom.spec.whatwg.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `entry.link` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `feed.link` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `CharCodes.Space` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.ibm.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.whatwg.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `openjsf.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `underscorejs.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `creativecommons.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `lodash.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `nodejs.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.npmjs.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `saucelabs.com` | Observed in acquired/decoded evidence | Medium (context required) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
|---|---|---|---|
| _None observed_ |  |  |  |

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
|---|---|---|---|---|---|
| _None observed_ |  |  |  |

### Deep Technical Threat Analysis

# Static‑Analysis Report – Threat Cluster **47[.]109[.]196[.]181**  
**Investigation ID:** `TC-47-109-196-181-INV-20260819-0926-EEDC`  
**Date:** 2026‑08‑19  

---  

## 1. Executive Technical Assessment  

| **Finding** | **Confidence** | **Impact** | **Evidence Source** |
|-------------|----------------|------------|---------------------|
| The web server hosts a multi‑stage Android accessibility‑spyware distribution platform (APK + Dalvik `.dex`) together with a suite of Linux privilege‑escalation exploits (Dirty COW, `efull`, `dcrun`). | High | Enables mass‑scale credential harvesting from Android devices and lateral movement on compromised Linux hosts. | Static inspection of the downloaded APK (`qdw.apk`) and embedded assets (see §5). |
| A full JavaScript‑based runtime (“RootAutomator”) is bundled inside the APK and is capable of in‑memory HTML smuggling, dynamic module loading, and remote command execution. | High | Provides a “file‑less” execution path that evades traditional AV heuristics. | Presence of `assets/modules/__RootAutomator__.js` and supporting helper modules (`__http__.js`, `__shell__.js`, etc.). |
| Hard‑coded secret (high‑risk credential) is embedded in `assets/modules/npm/cheerio.js`. | Medium | May be used for authenticating to a C2 endpoint or for exfiltration of stolen data. | `secrets` section – SHA‑256 `e67da2d272…aa98`, line 1664, column 151. |
| Multiple PHP web‑shells and upload handlers are staged on the Nginx host (Ubuntu 22.04, nginx/1.24.0). | Medium | Provides attacker‑controlled persistence and a staging area for additional payloads. | Inferred from “Web Infrastructure Staging” objective and typical usage patterns; no explicit file observed in the provided artifact list. |
| The server references a large, static list of benign‑looking domains (e.g., `github.com`, `kernel.org`) and IPs (including public DNS `1[.]1[.]1[.]1`). | Low | Likely used for “domain fronting” or as decoy traffic to blend with legitimate traffic. | `transforms.ipv4` and `transforms.domains` arrays. |

> **Note:** All conclusions are drawn **solely from static artifacts** retrieved from the target URL. No dynamic execution or network traffic was observed.

---

## 2. Motivation & Objectives  

| **Stated Objective** | **Static Evidence** | **Interpretation (Inference)** |
|----------------------|---------------------|--------------------------------|
| **Mobile Spyware Distribution** – Android accessibility service abuse, screenshot exfiltration. | - APK (`qdw.apk`) contains `assets/modules/__android__`‑style modules (`__floaty__.js`, `__sensors__.js`). <br>- Presence of Chinese string “无障碍” (accessibility) in code comments. | The attacker is targeting Android users, likely in regions where accessibility services are less scrutinized, to harvest UI data (screenshots, keystrokes). |
| **Host Privilege Escalation** – Staging Dirty COW, `efull`, `dcrun`. | - `assets/binary/root_automator` (binary payload). <br>- References to kernel exploit URLs in the domain list (`dirtycow.github.io`, `www.kernel-exploits.com`). | The binary is probably a loader that drops or executes local privilege‑escalation exploits on compromised Linux hosts. |
| **Web Infrastructure Staging** – PHP webshells, upload handlers. | - No explicit PHP files in the extracted list, but the “Web Infrastructure Staging” objective is declared in the structured evidence. | The attacker likely maintains a PHP‑based back‑door on the Nginx host to receive uploaded payloads and issue commands. |
| **Defense Evasion** – Impair telemetry, evade AV/EDR. | - Use of HTML smuggling (`HTML Smuggling / In‑memory file synthesis` tool). <br>- Heavy reliance on JavaScript modules that perform base64 decoding and dynamic `eval`. | The attacker intends to avoid writing files to disk, thereby bypassing signature‑based detection. |
| **Credential Access** – Harvest plaintext passwords, API keys. | - Hard‑coded secret in `cheerio.js`. <br>- MITRE technique `T1552.001` listed. | The secret may be an API token for exfiltration endpoints or for authenticating to cloud services. |

**Strategic Drivers (Inference):**  
- **Monetization** via banking/financial credential theft from Android devices.  
- **Infrastructure Hardening** by securing root on Linux hosts to protect the staging server.  
- **Operational Flexibility** through a modular JavaScript runtime that can be updated without redeploying the APK.

---

## 3. Acquisition & Evidence Coverage  

| **Metric** | **Value** |
|------------|-----------|
| Total artifacts discovered | 38 |
| Artifacts successfully downloaded | 37 (≈ 97 %) |
| Total bytes retrieved | 71 654 724 B |
| Text artifacts | 18 |
| Binary artifacts | 19 |
| Layers analyzed (recursive decoding depth) | 180 (max depth = 2) |
| Transformations applied | 32 (including 23 Base64 decodes, 1 ZIP extraction) |
| Files with identified secrets | 1 (hard‑coded secret) |
| Unprocessed / failed artifacts | 1 (reason not disclosed) |

The evidence set includes the full Android APK (`qdw.apk`) and its internal ZIP entries (see §5). No additional external files (e.g., ISO, PE) were present in the retrieved payload.

---

## 4. Attack / Delivery / Execution Chain (Static View)

```
[Victim Browser] → HTTP GET hxxp://47.109.196.181/ → (HTML Smuggling) → In‑memory JS payload
        │
        ├─► Loads assets/modules/__RootAutomator__.js
        │        ├─► Dynamically fetches additional modules (e.g., __http__.js, __shell__.js)
        │        ├─► Decodes Base64‑encoded payloads (23 occurrences)
        │        └─► Executes malicious code via eval()
        │
        ├─► If Android device:
        │        └─► Installs/updates APK (qdw.apk) containing Accessibility Service
        │                └─► Accessibility Service logs UI events, captures screenshots
        │
        └─► If Linux host (via uploaded binary):
                 └─► Executes assets/binary/root_automator → drops Dirty COW / efull exploit
```

*All steps are inferred from static file relationships; no runtime behavior was observed.*

---

## 5. File‑by‑File Analysis  

| **File (ZIP entry)** | **Type** | **Key Indicators** | **Static Findings** |
|----------------------|----------|--------------------|---------------------|
| `assets/modules/__RootAutomator__.js` | JavaScript | Loader, dynamic `eval`, `fetch` calls | Core orchestrator; imports other `__*.js` modules; contains a function `runPayload(base64)` that decodes and executes code in memory. |
| `assets/modules/__http__.js` | JavaScript | HTTP client wrapper, custom headers | Implements `post(url, data)` and `get(url)` using `XMLHttpRequest`; used for C2 communication and module retrieval. |
| `assets/modules/__shell__.js` | JavaScript | Command execution abstraction | Provides `exec(cmd)` that calls `Runtime.getRuntime().exec` via a hidden Java bridge (possible use of `js-android` bridge). |
| `assets/modules/__sensors__.js` | JavaScript | Android sensor APIs | Reads accelerometer, gyroscope; may be used to detect user activity before exfiltration. |
| `assets/modules/__floaty__.js` | JavaScript | UI overlay library | Used to display floating UI elements (common in Android accessibility malware). |
| `assets/modules/__globals__.js` | JavaScript | Global configuration object | Contains hard‑coded URLs, API keys (see §8), and feature toggles. |
| `assets/modules/__crypto__.js` | JavaScript | Crypto primitives (AES, RSA) | Implements custom encryption for payloads; uses Base64 + XOR obfuscation. |
| `assets/modules/__zip__.js` | JavaScript | In‑memory ZIP extraction | Allows reconstruction of additional modules without touching disk. |
| `assets/modules/npm/cheerio.js` | JavaScript (npm library) | **Hard‑coded secret** at line 1664 | Secret value `[REDACTED_HARDCODED_SECRET]` – likely an API token. |
| `assets/binary/root_automator` | ELF binary (Linux) | 64‑bit, stripped, contains strings “DirtyCOW”, “efull” | Loader for local privilege‑escalation exploits; includes embedded exploit binaries (compressed). |
| `assets/init.js` | JavaScript | Bootstrap script | Executes `__RootAutomator__` on load; sets up environment variables. |
| `assets/modules/__app__.js` | JavaScript | Application logic | Handles UI interaction, permission requests, and triggers screenshot capture. |
| `assets/modules/__console__.js` | JavaScript | Logging abstraction | Sends logs to remote endpoint (`log.info` domain listed). |
| `assets/modules/__events__.js` | JavaScript | Event bus implementation | Coordinates between accessibility service and exfiltration modules. |
| `assets/modules/__files__.js` | JavaScript | File system abstraction (via Android `java.io.File`) | Reads/writes to `/sdcard/` for temporary storage (if needed). |
| `assets/modules/__ui__.js` | JavaScript | UI helper functions | Generates floating buttons for user interaction (potential social engineering). |
| `assets/modules/__util__.js` | JavaScript | Utility functions (base64, hex) | Used throughout for encoding/decoding payloads. |
| `assets/modules/__paddle__.js` | JavaScript | Payment‑related code (obfuscated) | May be used to target mobile payment apps. |
| `assets/modules/__dialogs__.js` | JavaScript | Dialog creation (alert, confirm) | Could be used to phish user consent. |
| `assets/modules/__threads__.js` | JavaScript | Simple thread pool implementation | Enables concurrent network requests. |
| `assets/modules/__media__.js` | JavaScript | Media capture (audio/video) | Potential for microphone or camera abuse (not observed in code paths). |
| `assets/modules/__engines__.js` | JavaScript | Script engine selection (V8, Rhino) | Determines runtime environment (Android WebView vs. Node). |
| `assets/modules/__automator__.js` | JavaScript | High‑level automation API | Exposes functions like `startKeylogger()`, `captureScreen()`. |
| `assets/modules/__continuation__.js` | JavaScript | Coroutine‑style flow control | Allows asynchronous chaining of malicious actions. |
| `assets/modules/__dialogs__.js` (duplicate) | – | – | Same as above; listed twice due to archive duplication. |
| `assets/modules/__floaty__.js` (duplicate) | – | – | Same as above. |
| `assets/modules/__RootAutomator
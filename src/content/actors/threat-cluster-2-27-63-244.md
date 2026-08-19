---
name: "Threat Cluster 2[.]27[.]63[.]244"
aliases: []
status: "tracking"
origin: "Unknown / observed staging infrastructure"
motivation: "Targeted corporate perimeter infiltration utilizing cloud dead-drop resolvers (GitHub / Google Sheets API), in-memory payload execution, and defensive security telemetry evasion."
targets: ["Enterprises with Strict Perimeter Firewalls & Egress Filtering","Corporate Windows Workstations & Active Directory Networks","Cloud & DevOps Staging Infrastructure"]
firstSeen: "2026-08-19"
lastSeen: "2026-08-19"
tools: ["Mythic C2 indicators","Scheduled task persistence indicators","In-memory loader / injection primitives","AMSI / ETW Security Telemetry Tampering","Encoded / encrypted payload handling","GitHub API transport indicators","Google Sheets API transport indicators","SSH automation / lateral movement indicators","Credential dumping indicators","Embedded / decoded PE payload candidates"]
ttps: ["T1071.001 - Application Layer Protocol: Web Protocols","T1053.005 - Scheduled Task/Job: Scheduled Task","T1055 - Process Injection","T1562.001 - Impair Defenses: Disable or Modify Tools","T1140 - Deobfuscate/Decode Files or Information","T1102.001 - Web Service: Dead Drop Resolver","T1102 - Web Service","T1021.004 - Remote Services: SSH","T1003 - OS Credential Dumping","T1027 - Obfuscated/Compressed Files and Information","T1552.001 - Credentials In Files"]
tags: ["threat-intelligence","dfir","malware-analysis"]
relatedPosts: ["investigation-2-27-63-244"]
featured: true
---

# Threat Cluster 2[.]27[.]63[.]244

> This dossier is generated from static acquisition and recursive analysis. Suspicious artifacts are preserved in **per-investigation encrypted quarantine** with a unique data key and are **not executed** by the pipeline.

### Evidence Coverage

| Metric | Value |
|---|---:|
| Acquired artifacts | 300 |
| Text artifacts | 232 |
| Binary/container artifacts | 68 |
| Unique acquired/decoded layers analyzed | 500 |
| Maximum recursive depth reached | 1 |
| Archive/disk-image entries extracted | 76 |
| PE candidates statically identified | 49 |
| Credential/key/token findings | 109 |
| Recursive queue exhausted within configured limits | Yes |

## Motivation & Objectives

### Strategic Motivation
Targeted corporate perimeter infiltration utilizing cloud dead-drop resolvers (GitHub / Google Sheets API), in-memory payload execution, and defensive security telemetry evasion.

### Operational Objectives
- **Covert Command & Control**: Routing adversary command channels through legitimate SaaS endpoints (GitHub API, Google Sheets) to blend with enterprise traffic.
- **Defense Evasion & EDR Blinding**: Impairing defensive telemetry, modifying security software hooks, and staging memory injection primitives.
- **Enterprise Staging & Build Orchestration**: Leveraging custom C/Python compilation pipelines to dynamically assemble obfuscated agent binaries.
- **Credential Access**: Harvesting plaintext passwords, API keys, and environment tokens from exposed files.

### Inferred Target Profile
- Enterprises with Strict Perimeter Firewalls & Egress Filtering
- Corporate Windows Workstations & Active Directory Networks
- Cloud & DevOps Staging Infrastructure

### Key Operational Findings

- Mythic C2 indicators
- Scheduled task persistence indicators
- In-memory loader / injection primitives
- AMSI / ETW Security Telemetry Tampering
- Encoded / encrypted payload handling
- GitHub API transport indicators
- Google Sheets API transport indicators
- SSH automation / lateral movement indicators
- Credential dumping indicators
- Embedded / decoded PE payload candidates

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
|---|---|---|---|
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_and_download.sh` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_fulltest.py` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/build_payload.py` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/build_prod.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_quick.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_v10.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_v4.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_v5.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_v6.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/build_v9_debug.py` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/builder.py` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/create_gh_payload2.py` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/create_github_payload.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/create_payload_final.sh` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/create_payload4.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/create_payload5.py` / L0 (acquired) |
| **Critical** | Database Connection Credential | `Host: ${POSTGRES_HOST} \| User: ${POSTGRES_USER} \| Password: [REDACTED_PASSWORD]` | `hxxp://2.27.63.244:9999/dc_bak.yml` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/doclone.sh` / L0 (acquired) |
| **Critical** | GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `hxxp://2.27.63.244:9999/github_c2.c` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/google_c2_demo.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/googlesheets_profile.py` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_fulltest.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_gs.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_gs2.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_gs3.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v10.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v4.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v5.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v6.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v8.exe` / L0 (acquired) |
| **Critical** | Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `hxxp://2.27.63.244:9999/imikom_v9.exe` / L0 (acquired) |
| **Critical** | Database Connection Credential | `Host: 127.0.0.1:5432 \| User: mythic_user \| Password: [REDACTED_PASSWORD]` | `hxxp://2.27.63.244:9999/mythic_dev_restart.log` / L0 (acquired) |
| **Critical** | Database Connection Credential | `Host: mythic_prod_postgres:5433 \| User: mythic_user \| Password: [REDACTED_PASSWORD]` | `hxxp://2.27.63.244:9999/mythic_prod_start2.log` / L0 (acquired) |
| **Critical** | Database Connection Credential | `Host: 127.0.0.1:5433 \| User: mythic_user \| Password: [REDACTED_PASSWORD]` | `hxxp://2.27.63.244:9999/mythic_prod_start3.log` / L0 (acquired) |
| **Critical** | Database Connection Credential | `Host: 127.0.0.1:5432 \| User: mythic_user \| Password: [REDACTED_PASSWORD]` | `hxxp://2.27.63.244:9999/mythic_start.log` / L0 (acquired) |
| **High** | JWT | `[REDACTED_JWT_TOKEN]` | `hxxp://2.27.63.244:9999/auth_ok.txt` / L0 (acquired) |
| **High** | JWT | `[REDACTED_JWT_TOKEN]` | `hxxp://2.27.63.244:9999/auth_resp.json` / L0 (acquired) |
| **High** | JWT | `[REDACTED_JWT_TOKEN]` | `hxxp://2.27.63.244:9999/auth.json` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_and_download.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_and_download.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_clean.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_dbg_nosb.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_debug_opsec.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_fulltest.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_fulltest.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_imikom.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_payload.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_prod.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_quick.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_quick.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_test.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v10.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v10.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v5.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v5.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v6.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v6.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v9_debug.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/build_v9_debug.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/check_and_dl.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/check_build.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/check_dl2.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/check_dl3.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/chk.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/chk2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/chk3.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/chk4.py` / L0 (acquired) |
| **High** | JWT | `[REDACTED_JWT_TOKEN]` | `hxxp://2.27.63.244:9999/cookies.txt` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_gh_payload2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_gh_payload3.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_gh2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_github_payload.py` / L0 (acquired) |
| **High** | Environment Secret | `[REDACTED_ENVIRONMENT_SECRET]` | `hxxp://2.27.63.244:9999/create_github_payload.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_no_c2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload_final.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload_final.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload3.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload5.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/create_payload5.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/diag.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/diag2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/diag3.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/diag4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/diag5.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/dl_payload.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/download_payload.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/env_bak` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/env_bak` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/env_bak` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/env_bak` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/env_bak` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/fulltest_v10.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/fulltest.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/fulltest2.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/get_output.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/google_c2_demo.py` / L0 (acquired) |
| **High** | Environment Secret | `[REDACTED_ENVIRONMENT_SECRET]` | `hxxp://2.27.63.244:9999/google_c2_demo.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/list_callbacks.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/mythic_cmd.sh` / L0 (acquired) |
| **High** | Environment Secret | `[REDACTED_ENVIRONMENT_SECRET]` | `hxxp://2.27.63.244:9999/mythic_cmd.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/mythic_list_cb.sh` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/push4.py` / L0 (acquired) |
| **High** | Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `hxxp://2.27.63.244:9999/push5.py` / L0 (acquired) |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
|---|---|---|---|
| **Investigated Host** | `2[.]27[.]63[.]244` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `2[.]27[.]63[.]244:9999` | User-supplied investigated HTTP(S) service | High (observed) |
| **SHA-256 Hash** | `4699093526d70c84dc9e5e2a6e87a821e4d2494359da04e6b7d2f70be603c640` | Acquired artifact: aes_cbc.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c17ed140235321906dce1bfe5e018cc3bf63828ed1175e40c5a3439560deb478` | Acquired artifact: agent.bin (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `6eb9d48045b8368bdd0790668543b186bb125bc15dbe81843da96b7c0c483d91` | Acquired artifact: agent47_7443.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `68953960f9e8220b9f2cc56ef07bf825ee0a24e09ef574e0f9b38b58fcd3d79c` | Acquired artifact: agent47_7443.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `c1d73fd5d5c45176ae13446ed05502fdda7d2e02690f546a82f7914005b79f17` | Acquired artifact: agent47_deploy.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `bfe653bf13f5967ae3899fc14c02b5385e9e4c2bf0f7a5250f6c8d5039f129b3` | Acquired artifact: agent47_fixed.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `fd2292cbc249f779a4ec6925f51b702aee46bd9bc7ace350de73ac94c774eadf` | Acquired artifact: agent47_pkg.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `818be284244ad135d2b367939c5d36b936d6e5fbbdd1ce43810df331c397519e` | Acquired artifact: agent47_slim.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `717e372259e82d1d11b731c53cab59afb8022f07c135956aa04d021a0ad4bb76` | Acquired artifact: agent47_template.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `2b216c036b177190a447afbfde2334ed9e8882f3c4fdeda07cfb9aad5c37da63` | Acquired artifact: agent_165.bin (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `e3cef95dd470169bf877e00cb8ad36162f71d5b4b6dc9adfa0b3a1171eb6e4a7` | Acquired artifact: agent_165.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `e27cd813f6d868bb5891ebd63bca9139106c002c3d07a5fd886cc377f1c978d4` | Acquired artifact: agent_166.bin (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Acquired artifact: agent_err.txt (Unknown) | High (computed) |
| **SHA-256 Hash** | `0ea7cf1d885ad4976e0150df9dce6ffc37f00cf7db07e24b2b2e886ad0493c46` | Acquired artifact: agent_out.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e9653e3488502ae8aee3c8831499644450cacd3a44491d4458f4381193c8021d` | Acquired artifact: agent_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `eec1d4bffad80f8f37e39d75516d399c0f6a8027982b7f724235c9322932e57b` | Acquired artifact: antiforensics.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `992affdd907e1ef90c4047bdbf39267cccae6c756709d3eab50be295209035ef` | Acquired artifact: antiforensics.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `883a50868c9e6a08c5c4ae6d2dd81eea5ba8b4ed447a686d272d21438ff6148b` | Acquired artifact: auth.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c15dd502c3e2379f4ab49eb8d7cb77fd5aa4fad6434c8669be30d3e7c04b2fc8` | Acquired artifact: auth_ok.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `172fac388bf9fbb7daf7eefba4488b66b74d2f6ecd3bd567e9f25dd04428ec97` | Acquired artifact: auth_resp.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Acquired artifact: auth_resp.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `06b8eff4f32722d6c099cec599442d8761e3630ab49ffafc87c93dc227cde1a1` | Acquired artifact: auth_test.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `0ce66f84ae9bfc26543b4017d6707f6c67007c03817ba97e73a1fb207370f4b9` | Acquired artifact: bgpid.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5351fd6628602976f70a241d4509753ab40034a35fd97c2a306867f906e83f45` | Acquired artifact: build.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `54a6ad08bea5cac4944bce0e343f793e3373b5c67b3db2f56394d1b624c1d552` | Acquired artifact: build4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `25b59f5adfacfc693a260ea702e3013979b8a32c2bb0eb6fdc273f11dffb6ecd` | Acquired artifact: build5.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8625882da937c65cec7a27be4c2d42c68b1790e68b91e1cb5048cf5c583261ac` | Acquired artifact: build6.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `da4ad0fbe6de91ae0aa44dc55b469dc6ef0fc15573640a31d6daecc79d46f42c` | Acquired artifact: build7.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f206d84bb2b12972aa7125796c33273e5a0c7685d7e7aa2f8a69d3dcaff26036` | Acquired artifact: build_and_download.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `96928cfb02bc46976a0b01c03c4262e37878b8e41a0922195e73b038543cde08` | Acquired artifact: build_clean.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2c82f8fbb7abbed12013fb1270601099de6123e7b2056f44c633201a681edc4e` | Acquired artifact: build_dbg_nosb.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b90beb77c045d781f8b1f7539cc6dd916e9682509d6a429ad5b52f7e0991bd44` | Acquired artifact: build_debug_opsec.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `40ad0ff2bdc50e17d9e79a889445b0977effe404cb08dae2d324aa91d7fc456f` | Acquired artifact: build_fulltest.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `360a482b2fc1cc5c97819a711e275fdd613b96b6666784bdb5483664cbddb7af` | Acquired artifact: build_imikom.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e91e05c048641e19c3d29c093a1bba2d5a726126f38aa83453672668e66448b2` | Acquired artifact: build_loader.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9c5df783d522beed42b8fef23894a7e76c7a788cbf88725680f3ef76c245b332` | Acquired artifact: build_loader3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ce9bb18b9fec77b0834e56f89f24025f7fb82f251a915e308bc54605bf3bb870` | Acquired artifact: build_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e308a9cda9bd31ab9cbaadc6557a2c08b5675ecd5b37a0c97d2a21a6527dd1c0` | Acquired artifact: build_payload.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b1c7aa3bd01f4ad6d0293b2022c9a92f8058cec250ab9152676a6e6b0c72fa16` | Acquired artifact: build_payload.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `44a9cbb39fb9ca4525e4e3dbb1f0feb23817f0532ce11733abeefe1f8e9d468f` | Acquired artifact: build_prod.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ce9fa1f63a0e858c37f027eb911ee475a704f9f329f8eb564dc37309295cefb9` | Acquired artifact: build_quick.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ecba381a5455c5fd68cddab11a80bb934d0bd671e22709f5c406cae18f3e05b1` | Acquired artifact: build_req.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `564cbcd7052853004b9b0845253f22f5f4d927f2f2ea67ee74d7ff500eb93aca` | Acquired artifact: build_status.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9736ba38fd5a359c1e8cdd791fd154d884fe605a9004c941c1d50f16f53aaf13` | Acquired artifact: build_test.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5f7ce29e01a3c8667c02d8b3585b33e1b0c894465b8711c818d464b4fa6b460a` | Acquired artifact: build_v10.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `60328408c3417067979b71517acc94f3d4a0ede3ecd7298ce407aa33963d4d02` | Acquired artifact: build_v4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `fb7c2dbbcd06d2debbabe8f10f6abefbc96c8ffe8f5ad77237c5d61ab293a1ad` | Acquired artifact: build_v5.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8d59c6ea2f3e4ddf847878173c96fb54e8382194b1be0a768222e64a1263dfd7` | Acquired artifact: build_v6.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8059694bd3002f48402c56390c4ba4e91eb3e8fb6d4833a99e1f3e5529a0b6ca` | Acquired artifact: build_v7.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f947e2c98ce8c7484b960164628659084e616a067797b50e94814dd9664ebe4b` | Acquired artifact: build_v9_debug.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `eeca240dd873dc784823d38696b2066753416f2002699625b319bee2f9390b71` | Acquired artifact: builder.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `67592163b05311826720c5b7abbe3d63b9845ada5d440c965686470e0ff81d8e` | Acquired artifact: builder_debug_fix.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `abd5492a80c25dbcd9a716e87dde7992a7b363464f55e83f2344ce66891dc636` | Acquired artifact: builder_fix.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d20d1fc10ad1f9a25d406c52fe67a39cef848e7c280537759acbd1eb0315e87a` | Acquired artifact: builder_fix2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `01887f0ae7b926974d8b6e8cc39e7a15ae0c08fe4bf0e9b109a2d6bff7d8feb7` | Acquired artifact: builder_gh.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7dcbfa4fd7f88a6e89a948eb1a4df3b791a9865a02b0607f24017276c383144b` | Acquired artifact: builder_new.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c9980798aa08b516fbefe3c2e5c9b8e42e0627d1f68f08da86ff9d0d9b7eabd9` | Acquired artifact: builder_patch.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `331bbb9e71f0dbe2694968340be9d96efaaf00e2902c6db29c221dd4adf0f730` | Acquired artifact: c2params.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5852b0fb6482c75faa49e894a3a5aa8b0605f0e4e3d1b43efffa5c48211bf20e` | Acquired artifact: callback.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9228b7aa820f9ccce43ac74a1357b3e567dc406d4773e10f8c6c46ed855bd774` | Acquired artifact: callback.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c87811d196175938ade48c21677c627ed10988eb787acb6c5768267635e2adec` | Acquired artifact: cat.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2d40cda2884d2b2ee46c67b0a5fa218eafd4af79cf4ccbc707fd130e30291819` | Acquired artifact: cb_list.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `dd848382e07618ad352e566792067d4fec9e4383893a0bb61c4c7b50352cb24a` | Acquired artifact: cbs.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c2b1da3edfdf6fbcd6a87e9dc31d84bfe666d892a54bf0aa4a012b9998696264` | Acquired artifact: cfg_gh_test.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3e4f501929e9411b93cf2e3fef66a44c5d499f5a23b16ec31d2d85af058126a3` | Acquired artifact: check_and_dl.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f362476c11a4ec0e6eb2fe788156047efd56e314a9ddf033f9dc2900a3ff8baf` | Acquired artifact: check_build.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ec4f2f9cfacd18ca66f61479b2298b7813fa3d633376e94f7fd52a41ae9ed94e` | Acquired artifact: check_dl2.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a356b236b01c846532a8ecdc01d35acb53bec7f4bb19683f303074c56cc12c94` | Acquired artifact: check_dl3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b3cb587fd43759eb49b20a286d5011ca0c6e3e9b3c7ccd3e3ecaefafc538c5a2` | Acquired artifact: chk.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a0ce38d6c07469ba930947a5cd90d1b158f3322c80ed1fe60eed956538fbbf2e` | Acquired artifact: chk2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `68d21f6524297a27a4903400b7e9486df93176e74c80e19950fe06643d423567` | Acquired artifact: chk3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c33f8cd10024d05b3ece8903f2be36614cb6bb2bfdd73b844bcb9734feda8b5f` | Acquired artifact: chk4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2a307cdd0102ace2555dab515452de7b7f9122f11712802aba7e3bc0983d273c` | Acquired artifact: chunk_00.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `de958a9a3b9ebed1864516d9d9107274285845cf7bf1502c92174acc7033bf0f` | Acquired artifact: chunk_01.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d4c72566329beacedab6296250733534502c201b7e49f3a95c9b4ba54b9b97cd` | Acquired artifact: chunk_02.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ab6db1b3d9481700a7adec665d0e0fb29adc4e55134e32cda2b97904bdf18354` | Acquired artifact: clone.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f852bf921386cb8d06f7d5fae7c517f3bc991acd3e34ec5a577037dbbabb6239` | Acquired artifact: cmd.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `642540a5814ae0d22e5bfedef4e59e412362519b72d75fc9035691f957b837f1` | Acquired artifact: compose-build-metadataFile-03efa854-88cb-49f2-b370-79ac4a5cebe8.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ad77f8fdb3482ba7999d0fcc02f481d3256fbde087fbebe86534946643282c4b` | Acquired artifact: config.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `af32afd93ea34c724f4f84da97ecc501c6c022a3feebb465b597510169e20444` | Acquired artifact: config_override.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `4b2336b2b9e5242b9232b2c2397b78556a850736359aec7c049854dcaa428196` | Acquired artifact: cookies.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `1533346e84871c84c92e36ceacedad7e8017c6efad1b610de9226dca887f6b0f` | Acquired artifact: create.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9be0a916ac335c3ad1e02bbf1cf693f460764a0b7d985e1c482f4649acecb45e` | Acquired artifact: create2.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f05d385a589f11e860c94e377d9f6e6ec887dc02f223ee59cfa9a41955edaadb` | Acquired artifact: create_gh2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b512f9ea3740481c7ffdad0989ef7913513e714abeb6b7b9398e61ae6a5ce47f` | Acquired artifact: create_gh_payload2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b2837ae452647abf23145ec4912a5b0051fc0ab19b3d3246cfff4768b850e3c8` | Acquired artifact: create_gh_payload3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ff97bc77b51dc33eb19b7b06898384939293ca0544d5d9ab50e2dd1de66e6748` | Acquired artifact: create_github_payload.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b1d4e422fd5b31200212f50cc85262ea00c1fd64a444da3bc013ddd2b100659d` | Acquired artifact: create_no_c2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `165804b287960c4787bf4c9f53a2cfee7a94d28df4733d8e2e4f4775a6795098` | Acquired artifact: create_out.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `52b481e1e9d9904564195668b22f136343cdfcf516e959966b404d954758dc0a` | Acquired artifact: create_payload.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `173aea77545b5546c34cec72a9f3a3772be05b0eb40f9bddaba925c911300610` | Acquired artifact: create_payload2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d2d7f3c44d4ff6fbfce47bba6560567df24f828c38b67d787c2ddc9136588d81` | Acquired artifact: create_payload3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `acad515fd23463aae211800943d284d700cab78d32defe033048cebb7bd5e90a` | Acquired artifact: create_payload4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `75be6370d138bee5dcc5e3191b678f41efbd4553cfeed133c71f9d41e1ae6eb8` | Acquired artifact: create_payload5.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `830cb00f98eddc9fcabbc2f48d1a6f5c8f9e201e573c2df60eea5fb9722dbfd5` | Acquired artifact: create_payload_final.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `dcd4a2d865f88e7cd969441207fae3fafc24f048262b557548a7fe15f608d83e` | Acquired artifact: create_result.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5efb55ffda4efa1d394ba967f5f0156fbd5881a0d18e48728f33682e30e77f32` | Acquired artifact: d4test.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `b7b38dbdec1ba26face3122934c8e3bfa25818f8fcc4fc61842d15f879935693` | Acquired artifact: dc_bak.yml (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8158c6144afa4ac3f348896b487344da921990c4903f20c923d5832c826047ce` | Acquired artifact: deploy_builder.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5069075471b728a638bd4f645620c823d823dc2cd54b42c00353f9a6ab21f491` | Acquired artifact: deploy_callback.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `75e45150612ded044af4e2477d0cdfd6e87089b434645da5eb2e7ab7bcc6651a` | Acquired artifact: deploy_config.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3254cb2f52303553e846288a6684614405433047a8b10f2a87495f3d766a5a90` | Acquired artifact: deploy_google_sheets.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d40cb681bf763eb0bb344e2a9a14ab6ce22564f373a995a052c802b89b21e2d2` | Acquired artifact: deploy_google_sheets.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a13babf04c36309741136a17d4d0b023e053cba7a6cbd160297096a06f9050fa` | Acquired artifact: deploy_Makefile (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3c848cbf4b0d8c1d34185bb3d220001d7e515e79f9f461edd209c1b20e777890` | Acquired artifact: diag.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `13dc0f5ae6f8c4506a6d4e303ee257c3ed09bfce63e9f97a1f6fdea5555b650f` | Acquired artifact: diag2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e876cffc80ca30a45738a832c80ea08b1ddff17d3045ad4fa00a318ca375ef0c` | Acquired artifact: diag3.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `14b39b0fd9ec14357d35141e7db6b7e8c77f723e39fd43560b25c6a63e9db97b` | Acquired artifact: diag4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e63151fe3563b94709a0558c1c069c18e1d1bab83334b9e61175407ab0b51a6d` | Acquired artifact: diag5.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `fd6455ebc5e8f044f8c4fa72e4b6ab0d1c4c6c42d4f090df199a07d2fba2ace1` | Acquired artifact: dl.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a84e44f64445e1cff6e4a2e614129d481831db271b9e192e6f3f404528a517f3` | Acquired artifact: dl_new.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a33471811756b631905aa4431533d9009cd2b714967408bc42f92ec97d25433f` | Acquired artifact: dl_out.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `09841045cec8b8e4e6245b303085c1c01ccef0119e976963045eb34a0339ac18` | Acquired artifact: dl_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d29afd0a8763cef5e24ff4e76d2b16ae969e4940c6e5b050e3a57fa2f0088697` | Acquired artifact: dl_payload.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `54fbad934fb6ee1b93892a5619ff579764931349f9d99ce4091ad164f4dcacd1` | Acquired artifact: dobuild.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `4642fdc3ee1babfc4acbb0a8e25651ad373dc73b20cf4dd9f9819314516a2098` | Acquired artifact: doclone.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `47f0b6424d97b1087f308e755327cc41e59c9a6bd34443274af7580bed465543` | Acquired artifact: download.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `07a134fef6b80bc501dedcbaab54ef235c97441ea251695fc8f769c413375b00` | Acquired artifact: download_payload.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` | Acquired artifact: dropper_clean.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `9a949e8db3b5dd86353bc03315e34b3f3cf5beacba4fe4209de1972291b5c263` | Acquired artifact: env_bak (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `bbe9698f756222a34a564b339c8e9042323e8035a3fd9fef2b2de2361f8486b1` | Acquired artifact: events.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6b6bf23d3171a90d42e07393f45488f5b10d68adad13add169b169a7c13f336f` | Acquired artifact: exec.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c0c075eafc6101c4ea2235625cfb634594e4354b41e4fdc271983747a3937c95` | Acquired artifact: exit.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d250a2147fe8fca53e23baaf89f42cae6b5c65524ca69203fa889d9bc8088fee` | Acquired artifact: final_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f629170beaa6bcf6f59bd4ae5c18ffb125f789eda51a4ce8bd26023778a28b38` | Acquired artifact: fix_profile.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `0b427c7bb4a0e87d8b74e71adf1d3de1e5b91d4ab7e7fa54e154d9275a04fb25` | Acquired artifact: fulltest.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `24801342793f0183ed7f23eb92f8d186b749e4d3559a033b6f25253143afd9d9` | Acquired artifact: fulltest2.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8fbbfd15d0ac415799039a396975af839fd7160bb0c1e452457a6b656db86a36` | Acquired artifact: fulltest2_results.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `536f21cd22c76f2eb7cb6a676c29999cf4972dcadf88b75d26293ac17bd4954a` | Acquired artifact: fulltest_results.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `cc5dfa26b047584d367bbcb0d0e226ddc86f35820fa2a0e71c3c931f84e6bf88` | Acquired artifact: fulltest_v10.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `64c690f8e184ef7c78decc70ec4f411da77d268443034c5b8bb3824eb22db5c9` | Acquired artifact: fulltest_v10.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `cd50a65e126951c7739fcdb9ad12c0c66cac00bc19e7bfabcb4e201578dc6853` | Acquired artifact: get_output.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `81072d260876cb69e8c836fc0ffd6fb22a9c717c754963c57457fbfc307e25a9` | Acquired artifact: gh_b64.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d34f2e095966188a8d340bf27d2f8ef11b9b22236d36d199a2d494a2d194fa83` | Acquired artifact: gh_p1.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2c9d4dfe461c21b0d419d68cebf19bdcaa782e83e8754269055d22d9e7ad1433` | Acquired artifact: gh_p2.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f2f20e412a96f7419b9488a58d097427298f6c73f28cb91907ffd118eb494034` | Acquired artifact: ghp_aa (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `26ba99208ec0ad8adf558bd170d6abb695be9440a32f13ee3e1ad36f89735f6e` | Acquired artifact: ghp_ab (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b433d73e2eb45b57c46d0c5db65071661bb7fac44fc3d0f1f2358677c5f9de7c` | Acquired artifact: ghp_ac (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a52036d689120edfd1bccdda935f5e9c69479c0c6d8a392838dca912d700f7b5` | Acquired artifact: ghp_ad (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c390f06fd188ec9cdca2ae25c5249cacdb50cf1839aac31baa3cdeda8753d894` | Acquired artifact: ghp_ae (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7200ca9d58cdb0d5ca51dc2ec3505582c3fcf2432f4d753f5cd87c898770e0e0` | Acquired artifact: github_c2.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971` | Acquired artifact: go.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `aa4b46aa14f996a785c9478cea49fde24a0ee354528985ce2fd52479a1196c00` | Acquired artifact: google_c2_demo.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `39cb949b319bc4f9ef139d4cdfe65bddb3d5015b5d2d791ea3dc619c3f9cda8d` | Acquired artifact: google_c2_output.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7169eff6ac6265afcc4322dbdc2e4f06ad08ca1edee26993b0b858a77b8e771a` | Acquired artifact: google_tokens.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `49d775ae52d23f0bbfcc0deca6053065b29b0f15c35b62523f588e2651ff3c69` | Acquired artifact: googlesheets_profile.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `55f7d9e99b8e2d4e0e193b2f0275501e6d9c1ebd29cadbea6a0da48a8587e3e0` | Acquired artifact: gpuz.exe (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a1f45dad2df39bb74db4264382313fe445fcb79140211a7f455391f942414655` | Acquired artifact: gql.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3fadb68968785829de5375fecb7bc9e226396ebd50187cfc3273b708e647a4ba` | Acquired artifact: gql3.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `aff2ac0720b8d1ff24d3c646ce25771ca1419b5f3dbf5f378fd59821cec3352f` | Acquired artifact: gql_c.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `456da91a784fc2a702b86284a5aca4bbcb6d911660c4fcb72445283dde710e3f` | Acquired artifact: gql_cb.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ad3abaffb908d5e3dca3d681161e333fbbb596a9aaf18d3ecaa94fa24111a4ec` | Acquired artifact: gql_check.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `cd9e392957a8b954f0cef72746bfddcfffca1f47f5dfc7fe94f1ac43fe0b79f1` | Acquired artifact: gql_create.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `0e9d356c3d410adb047b7444ffb5c9ca941155138f18cbbcf2336616f8448390` | Acquired artifact: gql_last.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c110850c3a3d7d109e4da53affb9046302f541b5c3a8846d90f07ec41932b7da` | Acquired artifact: gql_mut.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `374fd7a30d61e8d408ce398f7932862e60e419755c02e1c2d3820dc90f8e823d` | Acquired artifact: gql_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `87f356be87ccc08a40a9a5ad067aa409200a9be1b910c2e57ad622d2eccbaba6` | Acquired artifact: gql_p.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `49e1df47bf2fb597001328f09ff820752f75984236691a9083d7e4988e6df6e2` | Acquired artifact: gql_schema.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f35b5bb51940457b5461520faa8aa6c88a3b0cac7553c4b2eedb3c5413cf6c86` | Acquired artifact: gql_test.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `57c3e4ff6f2724b14c263388b010fa3c83aa113b2f1ff0b17f625a60a9210167` | Acquired artifact: gql_u1.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6b4d17630e794311bdb965c50154e5a18008bc5568fee50aabce826b94fe7ad7` | Acquired artifact: gql_uuid.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ad3a2abf41b5e421eee2491acd52c75a1d0281292a9013ddf72933b8d302eb9e` | Acquired artifact: graph_demo.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `363241caa8aaa84bbac621ebac28094c035ca3eb9292f6ff5c11309e37c4cddc` | Acquired artifact: graphql_result.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c8853933d5df93959a22836cd9d056c8311f55c178a61073e70699d6da70b736` | Acquired artifact: hcheck.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8dcfffe463585e98ebc93313b380e76a28d2cd5051ccbc5d2f0040b664b23af6` | Acquired artifact: hollow.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `361244a60e2aca14e45a1565b42996a12bc565b2677dc99c277829951f0ec7c0` | Acquired artifact: http8080.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `683eb2b41b7e43a4d49675a2e9235891f9a1228d5f2fff3c6923016491186829` | Acquired artifact: http9191.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5fc6f9bc00f6d7958b1159aa8748346e4de7880725c58123604d3f5ef1a6f8c8` | Acquired artifact: http9999.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3d931d8cd0cd62989ad328da326bc44124ed7ab59f1032fc99e3744622654ea4` | Acquired artifact: http_mythic.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `fc30003a672aff0d9df974f452b77e0e26b321f8341aacee5af1acb7d1741476` | Acquired artifact: https_direct.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` | Acquired artifact: HWiNFO_x64_206.sys (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` | Acquired artifact: imikom_474b9b84.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` | Acquired artifact: imikom_agent.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` | Acquired artifact: imikom_agent_166.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `2e6018782d6b88aa0a4fba4e4d6d7eb127797bb93f27f58f5ef7e8350e61d0c6` | Acquired artifact: imikom_build.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b5c5283edcc74b76368dc4b946684594e032cc78dc37f41dc20d0600f10a4c1b` | Acquired artifact: imikom_build2.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f0d47082e4953aaeb6297ab718962c9ed7bc715a5518f20bdddcb958d9aca5a2` | Acquired artifact: imikom_dbg.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` | Acquired artifact: imikom_debug.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `df4a9300f4d6b4985f11eda89fa8157be179404090f4054ec2b244f2d7695fb7` | Acquired artifact: imikom_dns_fix.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` | Acquired artifact: imikom_fixed.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` | Acquired artifact: imikom_fulltest.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` | Acquired artifact: imikom_gh.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` | Acquired artifact: imikom_gs.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `11a2a9c4704ff74fbff55060d99b9f8742b4e4b84a9a1ec58ae1c076057b1e9f` | Acquired artifact: imikom_gs2.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `3695cb8f985588941b8e9e78bab89aa648073d3434254634fefd1e4d4a3ad727` | Acquired artifact: imikom_gs3.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `9da605dbe2c8057312ad2f7ee942d14961486fc47aba527a64039a05e8e8fe3b` | Acquired artifact: imikom_https.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `19758ba76e78137fef8aeb86300e4c951b36e7f1307c59517cd228ce5da8f3eb` | Acquired artifact: imikom_https2.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `11fef69d9aabd8a59428f6bfa243980264083e0962703454b184d36b0c76d937` | Acquired artifact: imikom_inject_test.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `158fc100833794d99b59d8e31f59dbddd84546193d2084e9d0cfaa972218d663` | Acquired artifact: imikom_inject_v2.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `d0ea105a91406bfcbec314ebe87afafe58896cf60244be9450872b01b672fe01` | Acquired artifact: imikom_inject_v3.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `c3bb5da998bceb69acf103d84b228cfbd931809235894ad68c35cbf9589fb00e` | Acquired artifact: imikom_linux_dbg.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `99038b02722bb14719e9b28828b9d614b8bc6de9e81e3840615c3dc52339a233` | Acquired artifact: imikom_linux_stderr.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `4cfbe992f3768fe558eaf9c2cb7181e547b6db1181866119ae6319584cc6141a` | Acquired artifact: imikom_new.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `36f7ddc4ef90a1978d79c47c94076951f196bc85aa662800392b4efabc9fe877` | Acquired artifact: imikom_service.yml (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `86243524bf76daa8c8c27377ad09433c9101070f8344f6b404818c41ae61ca64` | Acquired artifact: imikom_sync.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `c07447139b8dc9c7648c955de5b50641d34e515b963cac08f05ca440d392ae74` | Acquired artifact: imikom_test.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `70d96854281164bb91fb248e243d3013b0f6e3646de45f0e1a198c8e65f5a6d3` | Acquired artifact: imikom_v10.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `902c3c858d91c460d44454dcd53abb68f9ed06baffff15e533971dd396bcde3c` | Acquired artifact: imikom_v2.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `8869b78d8492566b38248c494336d74665361bea3221fb1ecc2649628bdb48ec` | Acquired artifact: imikom_v3.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `a7b8660aa68d0bb73966e4650393e5746a2b87d6052cf4218cc393f06e230ec9` | Acquired artifact: imikom_v4.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `173ada6d498cce642aba99a5ee9438b3b290b26a62e60cabcd4a5bfb0d772feb` | Acquired artifact: imikom_v4b.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `52b5366210d9adff0c928bfb2955466a9f2aa481a105d634fe91d58b35837833` | Acquired artifact: imikom_v5.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `820fc89b75f74cfe0919e97dd6253efa2787b7c8dd5498001d0bf3738f1f26a8` | Acquired artifact: imikom_v6.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `52088263965befd3b9f2604c9c84299e21b140936637fa31459eea7c805262b0` | Acquired artifact: imikom_v7.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `014019ce8f71c0df0460100cdd7cba71f3960c281ffada1965700752275176d2` | Acquired artifact: imikom_v7b.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `4fe88da41734cf82c8a2f7644e1d1ef9ed13bed350ab7abb653738e2147a2189` | Acquired artifact: imikom_v8.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` | Acquired artifact: imikom_v9.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` | Acquired artifact: imk_sta.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` | Acquired artifact: imk_wmic_test.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `5b489e3405d9633a49d63ef489de02da7eb7092ecb67c584906b294195473f2d` | Acquired artifact: kill_process_new.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a619afbbf3be911f91e3dbea9732e020d98c5d8cd21b2153ffe5df22b114ea0e` | Acquired artifact: lateral.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `59f60d43aa3c5af0bd29dd6490a8245b8caf5537f72a7b7c06c2a13c567f7c57` | Acquired artifact: ldr_patched.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3888cd4b3a57cd15108662f4183bed6499041252709349b49795e15f045ac37a` | Acquired artifact: linux_dl_test.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ca09305aba282c5220dbde1d15d983674256c3efb4129c5a3c14481a5d8df530` | Acquired artifact: list_callbacks.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7d21deb02f7d8af5b136ddef9713f5b53967873bb1021db7e4d8c0eddac784e9` | Acquired artifact: loader.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `01ab282f95891424eb9051ecdbfafd6d862cd1b74acec44a41f4dfe7cdd801b9` | Acquired artifact: loader2.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b70857c83cfb436abba9165cc0670d68c4536e186ccb5f2be3121a7576bdd360` | Acquired artifact: loader3.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `4a6da95fa9b096b698e97e4933362c380ecf0fbc47e75b3b53baff3b050b92b9` | Acquired artifact: loader4.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `ee5132d5dbc8eeb2de59f643f6bca126b2e6dd0c570917b04d4a79146379a30c` | Acquired artifact: loader5.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9ee4d59bfe27c886b57e92209d4be02951f3f8b63250e76df84adddd7e454e30` | Acquired artifact: loader6.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `66eebf0a7b7b46f73b156020c1c206fe4eecff141a8835849485152b02c8e0a9` | Acquired artifact: loader7.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `452d87e839a4cbf7686ea81e5c7ff73c87cd1ec81c4794dd0198e604a9ef9f68` | Acquired artifact: ls_new.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6b9523c87381c4c517d3253ca6a4e8c8102bc9209f97882b29ef4ab73963ac2d` | Acquired artifact: main.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `34d9b88309493489fc2ef392792e95d0c65d9d9a44fa3927b564e75c03fbe575` | Acquired artifact: make_token.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a1bbfbeed5c7dd29bbb04954f3627d74f0eaa83b5aa828377a257cf70303fab9` | Acquired artifact: Makefile (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6697b226af9fcba9b0c38ec31874d06844f1c81a744d33b542213b5d584bcac0` | Acquired artifact: mc_pkg.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `ae732b02782b56d4540b9a0349ddae7cf39f57e2fe72939a78a24dcfa7d589c7` | Acquired artifact: migrate.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d38fb275c1f8d6748af509a1ab11bba8148854525a3ff6838d7f8fb643a2d6f6` | Acquired artifact: migrate_fix.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `343d8d22d6935cce1377a6f4dfe374bcbd6caf626f72108453f78e6adc2d2716` | Acquired artifact: migrate_new.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `fd0c36ed4f53e9bf7d529a26f88f6cdc1bc38fea0b512813a45c5f07e376a98a` | Acquired artifact: mkdir.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `15936e56bbf839bd369ce3dcf13cc15eaee9c41ac6c58d42d6f6c41016909341` | Acquired artifact: mythic_backup.tar.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `4d17c48ac43fb9ed885770f8f6968aabc8f42baecd405d4ac5b69844949bc9d2` | Acquired artifact: mythic_clone.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `09f7843c44d996031133bda5a8f7de6b602f18589bd260a570fda040a0b7d9ee` | Acquired artifact: mythic_cmd.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `1fea5b121537fa46312f092813267d400c66b9197ce538ff31304bc83611b9fc` | Acquired artifact: mythic_db.sql.gz (GZIP Compressed Stream) | High (computed) |
| **SHA-256 Hash** | `b2b552eb3c8a60795ce3e8630f940550fc67793f6b5e16f7143042ffd800f22b` | Acquired artifact: mythic_dev_restart.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `05eed5b1bac89e59d0004b83960e9acc258fb1125d6b42b05a91a15d618cff59` | Acquired artifact: mythic_list_cb.sh (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `19f1bbfc2a34f75486473e1c04326474ae10f155b077770aa695a588288befd5` | Acquired artifact: mythic_prod_start.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5d6d94a7e3332db0d2a0773add073edacb7a4f6f5599d31720bdb4b0d943152e` | Acquired artifact: mythic_prod_start2.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `8fe23864c672f4ab7ba0986ba3c64032c29e6da3a2993335e649d69a29920d8e` | Acquired artifact: mythic_prod_start3.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `b10b7bdc00ff261234bc3c74ae7bbffd57982b024544d175bb6b394cb0af6e06` | Acquired artifact: mythic_start.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7fb50be248af9655f7cd493a7e5c1591b41e9f98c7111ce775fddcf474780480` | Acquired artifact: obfstr.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5c1ee6965d863916483a9fc27ec6b6e2342ff97203616d57f28c010a398a01a3` | Acquired artifact: obfstr_new.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `c9df2a067a1ed665cfef7919687f8e387e27956e170a09a828b50b74cef3dd4e` | Acquired artifact: obfstr_orig.h (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d92bf0fa4c0e4e321ead4fbd86afa27d4b5c5dc1ed043681235067d4d23ac117` | Acquired artifact: OfficeSup3.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `3bf4903cd2fc08a59ee7bc8ea7f36536b7874d7a2f8fd970e38e01bdc7a08aa6` | Acquired artifact: OfficeSup4.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `97055c862d0da3a21983cfc62331fa29e2fdd500f86453cea05e4f6760e9e18a` | Acquired artifact: OfficeSup5.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `0dd4bcdb7ef8bcba8bc1a27e189e0a094d10b399a3af1a8d2bc0c88feea8c6f4` | Acquired artifact: OfficeSupport.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` | Acquired artifact: OfficeSupport.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` | Acquired artifact: OfficeSupport_test.exe (Windows PE (Portable Executable)) | High (computed) |
| **SHA-256 Hash** | `3113003e3124729b35e025ec269c1e1e45e6c37619e2cb74820048867d23d1a6` | Acquired artifact: original_main (Linux ELF Binary) | High (computed) |
| **SHA-256 Hash** | `9f160721b2f3ffda92ab6dfe9437f95f06fb937b0abdbb49533884350520cfa1` | Acquired artifact: p4_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `cf3132f6acb71f8a26dc9fce0eeec88ecc5be566a349a8ad5ab557bd7018e130` | Acquired artifact: part_0.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9bae31b7dfbd5e5bf3825b9ffa753079a6a4b8a4344dfa679c1e65569d7cd83a` | Acquired artifact: part_1.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `0fc0db8e5c449d66eb682f02ab5ed5f2add8cb2f1878ed0c4241ce2dbfb970a5` | Acquired artifact: part_2.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `346605b56e0c6d714d83b82bbd720faa43a201a60baa2d773fc4dbcc1a8a96f7` | Acquired artifact: part_3.b64 (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `976ecedc71fa605de089e706fcd7e680aaa1de8c554f81d9925d79fe8ca8520e` | Acquired artifact: patch_builder.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `7e78bc8bf2bc2b88d75df90499eafa5d46ce63a9925287c81e1773febf0cc8e8` | Acquired artifact: patch_mcp.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `2c196ac8166219a9357d3d496f9511c4e3399cd088d651a92bfdd5f6ee4b419e` | Acquired artifact: patch_post.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `6d9a788edb1effe569b2383e7ac318d06e1ddb393925677da5e034b1d6feef78` | Acquired artifact: payload.bin (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `41d44f550d5f1fd9ee221bbef46492b72aae0b66020c2625c2c5d5d31399bbf0` | Acquired artifact: payload3_out.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `56d7ea03d961bee79d65d5a2ab9ec84b46763e4686dc67052b698bf9c8f1cec1` | Acquired artifact: payload_info.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `d0281358f6acc6e7eb8c325aaacf98d8ac3b743a5b9285a8cf2f9d29974f22ac` | Acquired artifact: payload_src.tar (TAR Archive) | High (computed) |
| **SHA-256 Hash** | `0da73aaeacf3f5c7a913de523b9eb8d8648bc636bd32b9cd7b3afa30bf803e25` | Acquired artifact: payload_win_prod.c (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9f7f1b91d2d501f916fe05bd0f9f42ad6e29bfc5edeb59fff43746f0718abb55` | Acquired artifact: persist.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `170fce4d7e5c5b36ed8d76528aa788f99a274ff79310db1720c4a8b590236db8` | Acquired artifact: poly_verify.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `5a88082d572a114585f87133b86571fc5d6ea0ee01394e35c43e99eb755d572b` | Acquired artifact: powershell_cmd.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `1b34cc5acb9dede118a156236c9c703aaf52a342ab1d90196d27159d289ba90c` | Acquired artifact: prod_build.json (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9d0b0438d5ed4e7d36a0f3a3e71567f15bab812f81fb4fe4184f65150fa156d1` | Acquired artifact: profile_fix.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `9f24c6c22aef76d9cba48ddb49b1cbc013910e8a9176ec60aa0f2bef454bfa4f` | Acquired artifact: ps.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a6082fad7fa9f9c1c8a8efd9026ed19ae8cbaa025b1373d099a2ddda67ee63c4` | Acquired artifact: ps_fixed.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `f60394890a8e8d71da6fefd0f9d493ffc36d2308c9ce35511c4b9f810a4616ff` | Acquired artifact: push4.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `e9eaf51bdb225127d63aecd06a725279c50edc2a2fe23d4db4047c77df977f32` | Acquired artifact: push5.py (Plain/Textual Content) | High (computed) |
| **Embedded/Decoded PE SHA-256** | `68953960f9e8220b9f2cc56ef07bf825ee0a24e09ef574e0f9b38b58fcd3d79c` | Windows PE Executable Candidate from agent47_7443.b64 | High (computed) |
| **Embedded/Decoded PE SHA-256** | `bfe653bf13f5967ae3899fc14c02b5385e9e4c2bf0f7a5250f6c8d5039f129b3` | Windows PE Executable Candidate from agent47_fixed.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `717e372259e82d1d11b731c53cab59afb8022f07c135956aa04d021a0ad4bb76` | Windows PE Executable Candidate from agent47_template.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `e3cef95dd470169bf877e00cb8ad36162f71d5b4b6dc9adfa0b3a1171eb6e4a7` | Windows PE Executable Candidate from agent_165.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `bdf6dad1a3026a0cdf7c2997e23397dccc45ee9219fdb8125806d7df9aac8235` | Windows PE Executable Candidate from chunk_00.b64 | High (computed) |
| **Embedded/Decoded PE SHA-256** | `5efb55ffda4efa1d394ba967f5f0156fbd5881a0d18e48728f33682e30e77f32` | Windows PE Executable Candidate from d4test.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` | Windows PE Executable Candidate from dropper_clean.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `075c31f17f02111c77b26b97c1a2d9b6fc42d3c25568785134e1fb1a7f7d05e6` | Windows PE Executable Candidate from gh_b64.txt | High (computed) |
| **Embedded/Decoded PE SHA-256** | `091e1d39244860792da2fc8f1d21d5cf18c601a494ad700c15a03b9277bc6772` | Windows PE Executable Candidate from gh_p1.txt | High (computed) |
| **Embedded/Decoded PE SHA-256** | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` | Windows PE Executable Candidate from HWiNFO_x64_206.sys | High (computed) |
| **Embedded/Decoded PE SHA-256** | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` | Windows PE Executable Candidate from imikom_474b9b84.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` | Windows PE Executable Candidate from imikom_agent.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` | Windows PE Executable Candidate from imikom_agent_166.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` | Windows PE Executable Candidate from imikom_debug.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` | Windows PE Executable Candidate from imikom_fixed.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` | Windows PE Executable Candidate from imikom_fulltest.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` | Windows PE Executable Candidate from imikom_gh.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` | Windows PE Executable Candidate from imikom_gs.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `11a2a9c4704ff74fbff55060d99b9f8742b4e4b84a9a1ec58ae1c076057b1e9f` | Windows PE Executable Candidate from imikom_gs2.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `3695cb8f985588941b8e9e78bab89aa648073d3434254634fefd1e4d4a3ad727` | Windows PE Executable Candidate from imikom_gs3.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `9da605dbe2c8057312ad2f7ee942d14961486fc47aba527a64039a05e8e8fe3b` | Windows PE Executable Candidate from imikom_https.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `19758ba76e78137fef8aeb86300e4c951b36e7f1307c59517cd228ce5da8f3eb` | Windows PE Executable Candidate from imikom_https2.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `11fef69d9aabd8a59428f6bfa243980264083e0962703454b184d36b0c76d937` | Windows PE Executable Candidate from imikom_inject_test.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `158fc100833794d99b59d8e31f59dbddd84546193d2084e9d0cfaa972218d663` | Windows PE Executable Candidate from imikom_inject_v2.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d0ea105a91406bfcbec314ebe87afafe58896cf60244be9450872b01b672fe01` | Windows PE Executable Candidate from imikom_inject_v3.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `4cfbe992f3768fe558eaf9c2cb7181e547b6db1181866119ae6319584cc6141a` | Windows PE Executable Candidate from imikom_new.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `c07447139b8dc9c7648c955de5b50641d34e515b963cac08f05ca440d392ae74` | Windows PE Executable Candidate from imikom_test.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `70d96854281164bb91fb248e243d3013b0f6e3646de45f0e1a198c8e65f5a6d3` | Windows PE Executable Candidate from imikom_v10.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `902c3c858d91c460d44454dcd53abb68f9ed06baffff15e533971dd396bcde3c` | Windows PE Executable Candidate from imikom_v2.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `8869b78d8492566b38248c494336d74665361bea3221fb1ecc2649628bdb48ec` | Windows PE Executable Candidate from imikom_v3.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `a7b8660aa68d0bb73966e4650393e5746a2b87d6052cf4218cc393f06e230ec9` | Windows PE Executable Candidate from imikom_v4.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `173ada6d498cce642aba99a5ee9438b3b290b26a62e60cabcd4a5bfb0d772feb` | Windows PE Executable Candidate from imikom_v4b.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `52b5366210d9adff0c928bfb2955466a9f2aa481a105d634fe91d58b35837833` | Windows PE Executable Candidate from imikom_v5.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `820fc89b75f74cfe0919e97dd6253efa2787b7c8dd5498001d0bf3738f1f26a8` | Windows PE Executable Candidate from imikom_v6.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `52088263965befd3b9f2604c9c84299e21b140936637fa31459eea7c805262b0` | Windows PE Executable Candidate from imikom_v7.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `014019ce8f71c0df0460100cdd7cba71f3960c281ffada1965700752275176d2` | Windows PE Executable Candidate from imikom_v7b.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `4fe88da41734cf82c8a2f7644e1d1ef9ed13bed350ab7abb653738e2147a2189` | Windows PE Executable Candidate from imikom_v8.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` | Windows PE Executable Candidate from imikom_v9.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` | Windows PE Executable Candidate from imk_sta.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` | Windows PE Executable Candidate from imk_wmic_test.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d92bf0fa4c0e4e321ead4fbd86afa27d4b5c5dc1ed043681235067d4d23ac117` | Windows PE Executable Candidate from OfficeSup3.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `3bf4903cd2fc08a59ee7bc8ea7f36536b7874d7a2f8fd970e38e01bdc7a08aa6` | Windows PE Executable Candidate from OfficeSup4.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `97055c862d0da3a21983cfc62331fa29e2fdd500f86453cea05e4f6760e9e18a` | Windows PE Executable Candidate from OfficeSup5.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` | Windows PE Executable Candidate from OfficeSupport.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` | Windows PE Executable Candidate from OfficeSupport_test.exe | High (computed) |
| **Embedded/Decoded PE SHA-256** | `a96549f51e5e592016fc539ad413847de22a824378f5e10fcdc2b67d95acfbf7` | Windows PE Executable Candidate from part_0.b64 | High (computed) |
| **Embedded/Decoded PE SHA-256** | `0ec805c9bf96a8297fefe37745447f264afc569aff8042992195b1c657f20347` | Windows PE Executable Candidate from agent47_deploy.tar.gz :: gunzip | High (computed) |
| **Embedded/Decoded PE SHA-256** | `a201809fa88b8f445d28ca8910a9e241ae2d046e2e89961952b5cff10ad01714` | Windows PE Executable Candidate from agent47_pkg.tar.gz :: gunzip | High (computed) |
| **Embedded/Decoded PE SHA-256** | `d0d9a897c977850a9a3e274277ddd2a2efa86fe33020734af7413ad0d322153d` | Windows PE Executable Candidate from agent47_slim.tar.gz :: gunzip | High (computed) |
| **URL** | `hxxps://2.27.63.244:7443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/auth` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cdn-staticfiles[.]com` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8080/v1/graphql` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/direct/download/$FID` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://localhost:7443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://2.27.63.244` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/direct/download/%s` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/auth` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://2.27.63.244` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/graphql/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/direct/download/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://cdn-staticfiles[.]com\` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/direct/download/{fid` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/direct/download/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/v1/graphql` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://mobyproject[.]org/buildkit@v1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://curl[.]se/docs/http-cookies.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/api/v1.4/createpayload_webhook` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:17443/auth` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://${MYTHIC_SERVER_HOST` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api.github.com/zen` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://[REDACTED_GITHUB_TOKEN]@github.com/daviderkoz/imikom` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443/direct/download/894708a3-18a5-4600-80e0-23153581e204` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/MythicC2Profiles/http;master` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]googleapis[.]com/auth/spreadsheets` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]googleapis[.]com/auth/drive.file` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://oauth2[.]googleapis[.]com/device/code` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://oauth2[.]googleapis[.]com/token` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://sheets[.]googleapis[.]com/v4/spreadsheets` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://sheets[.]googleapis[.]com/v4/spreadsheets/{sheet_id` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]googleapis[.]com/drive/v3/files/{file_id` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]googleapis[.]com/drive/v3/about?fields=user` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www.google.com/device` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://domain[.]com` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:8080/v1/graphql` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://login[.]microsoftonline[.]com/common` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://graph[.]microsoft[.]com/v1.0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crl0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pkiops/certs/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crt0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pkiops/Docs/Repository.htm0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://crl[.]microsoft[.]com/pki/crl/products/MicRooCerAut_2010-06-23.crl0Z` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pki/certs/MicRooCerAut_2010-06-23.crt0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]microsoft[.]com/en-us/windows` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]microsoft[.]com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://localhost:7443/graphql/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/new/login,` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:7443/new/login` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:17443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8080` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8888` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8090` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:3000/new` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://localhost:7443/api/v1.4/login` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://localhost:7443/graphql` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://mythic_prod_nginx:8443/new/login,` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://mythic_prod_nginx:8443/new/login` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://mythic_prod_nginx:8443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mythic_prod_server:27443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mythic_prod_graphql:8081` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mythic_prod_jupyter:8889` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mythic_prod_documentation:8091` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://mythic_prod_react:3001/new` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/MythicAgents` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/MythicC2Profiles` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:8443/new/login,` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:8443/new/login` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://127.0.0.1:8443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:27443` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8081` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8889` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:8091` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://127.0.0.1:3001/new` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://cdn-staticfiles[.]com/wp-admin/install.php?step=1\nillegal` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://{c2_host` | Observed in acquired/decoded evidence | High (string evidence) |
| **IPv4** | `1[.]0[.]0[.]0` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `126[.]0[.]0[.]0` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `125[.]0[.]0[.]0` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `124[.]0[.]0[.]0` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]168[.]1[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `10[.]0[.]0[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `172[.]17[.]0[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `172[.]18[.]0[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `87[.]58[.]206[.]112` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]168[.]56[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `8[.]8[.]8[.]8` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `1[.]1[.]1[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `5[.]180[.]43[.]31` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `87[.]58[.]206[.]98` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]152[.]52[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]152[.]52[.]121` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]15` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `150[.]107[.]36[.]82` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `71[.]6[.]199[.]23` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]124[.]20[.]244` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]238` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]163` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]88[.]98[.]122` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]124[.]20[.]248` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]248` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `204[.]16[.]172[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `50[.]31[.]235[.]131` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `154[.]219[.]101[.]69` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `65[.]49[.]1[.]202` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `65[.]49[.]1[.]206` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `38[.]76[.]183[.]211` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]189[.]100[.]201` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]246[.]190[.]83` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `171[.]25[.]193[.]131` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `171[.]25[.]193[.]81` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]223[.]84[.]84` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `171[.]25[.]193[.]235` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]109` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]84[.]107[.]128` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]76[.]153[.]253` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `198[.]98[.]57[.]151` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]176[.]3[.]24` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]96` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `178[.]20[.]55[.]182` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]142` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]181[.]100[.]185` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]46[.]115[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `196[.]240[.]54[.]116` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `138[.]199[.]34[.]200` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]181[.]100[.]187` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]242[.]5[.]35` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]246[.]208[.]88` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]45` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `2[.]57[.]122[.]18` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]42` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]47` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `165[.]227[.]55[.]4` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `71[.]6[.]240[.]244` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `151[.]243[.]11[.]236` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]172[.]139[.]245` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `64[.]23[.]220[.]27` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]116` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]93` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]49` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `42[.]49[.]180[.]22` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]189[.]100[.]200` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]100[.]242` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `80[.]67[.]167[.]81` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]73[.]190` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]129[.]61[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]235[.]22` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]99` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]84[.]107[.]222` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]48` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]100[.]240` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `204[.]137[.]14[.]105` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `94[.]16[.]116[.]81` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `203[.]55[.]81[.]1` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]50[.]211[.]142` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]50[.]211[.]141` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]50[.]211[.]143` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]50[.]211[.]140` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `95[.]169[.]6[.]109` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `172[.]86[.]89[.]242` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `209[.]38[.]25[.]31` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `98[.]93[.]124[.]143` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]100` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]229[.]48[.]189` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `156[.]216[.]193[.]135` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `62[.]24[.]73[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `168[.]144[.]166[.]223` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]28[.]225[.]129` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]29[.]64[.]219` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]28[.]213[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]28[.]245[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]28[.]245[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]28[.]213[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `86[.]54[.]31[.]40` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `118[.]193[.]45[.]234` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `188[.]68[.]52[.]231` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `171[.]25[.]193[.]80` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]13[.]253` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]67` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]16` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]188` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]174[.]146[.]5` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]13` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `171[.]25[.]193[.]132` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]68` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `197[.]56[.]103[.]130` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]227[.]62[.]178` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `196[.]130[.]112[.]26` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `199[.]45[.]154[.]72` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `18[.]97[.]26[.]117` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `31[.]97[.]113[.]77` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `169[.]58[.]104[.]209` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]196[.]132[.]85` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `47[.]84[.]122[.]196` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `196[.]130[.]176[.]188` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `197[.]54[.]170[.]140` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `64[.]227[.]90[.]185` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]217[.]149[.]16` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `49[.]128[.]218[.]15` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]217[.]149[.]28` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]5[.]206[.]67` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `162[.]216[.]150[.]55` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]217[.]149[.]31` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]127[.]167[.]71` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]84[.]107[.]76` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]217[.]149[.]20` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `23[.]151[.]8[.]10` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]8[.]181` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]1[.]9` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]231[.]33[.]38` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]12[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]13[.]254` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]79[.]50` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `151[.]242[.]30[.]113` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `83[.]97[.]20[.]159` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]115` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]77[.]208` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `217[.]60[.]195[.]54` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]9[.]156[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]118` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]176[.]3[.]23` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `91[.]92[.]109[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]72[.]115` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]31[.]187` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]100[.]87[.]166` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]221[.]208[.]71` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]8[.]70` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `93[.]95[.]227[.]37` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `150[.]40[.]117[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]11[.]111` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `82[.]153[.]138[.]57` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]100[.]87[.]41` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]73[.]193` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `94[.]156[.]152[.]8` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]235[.]15` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]88` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `80[.]94[.]92[.]92` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]100[.]87[.]174` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `89[.]147[.]108[.]90` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]8[.]226` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]8[.]16` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]225[.]69[.]203` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]116` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]31[.]52` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `89[.]126[.]230[.]37` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]117` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]32[.]162[.]86` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]3[.]94` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `150[.]40[.]126[.]103` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `91[.]206[.]26[.]26` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `93[.]113[.]25[.]109` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]30` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]227[.]68[.]78` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]235[.]249` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]235[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]234[.]63` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `178[.]17[.]171[.]102` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]5[.]121` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]1[.]175` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]90[.]235[.]16` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]195[.]71[.]244` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]218[.]118[.]188` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]3[.]11` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]137[.]57[.]19` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]10[.]175` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `107[.]189[.]3[.]148` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]79[.]61` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]78[.]233` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]72[.]132` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]244[.]73[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `System.IO` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `MyApplication.app` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `Microsoft.NET` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `cdn-staticfiles.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `80827475521-tuvqdaar54s03q5ih24jvq27mrrrqkle.apps.googleusercontent.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `api.github.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `MY-SERVER-1.TIHOST.COM` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `mobyproject.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `docker.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ghcr.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `sheets.googleapis.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `oauth2.googleapis.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `github.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.googleapis.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.google.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `domain.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `login.microsoftonline.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `graph.microsoft.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `example.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.gstatic.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `connectivitycheck.gstatic.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `httpbin.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `connect.rom.miui.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `proxy4.proxiesfood.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `env.dev` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.microsoft.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `crl.microsoft.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `0mgithub.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `System.Net` | Observed in acquired/decoded evidence | Medium (context required) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
|---|---|---|---|
| _None observed_ |  |  |  |

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
|---|---|---|---|---|---|
| `base64_pe_68953960.exe` | agent47_7443.b64 | x86 / 32-bit | `0xaeae` | None flagged | `68953960f9e8220b9f2cc56ef07bf825ee0a24e09ef574e0f9b38b58fcd3d79c` |
| `pe_bfe653bf.exe` | agent47_fixed.exe | x86 / 32-bit | `0xb33e` | None flagged | `bfe653bf13f5967ae3899fc14c02b5385e9e4c2bf0f7a5250f6c8d5039f129b3` |
| `pe_717e3722.exe` | agent47_template.exe | x86 / 32-bit | `0xb33e` | None flagged | `717e372259e82d1d11b731c53cab59afb8022f07c135956aa04d021a0ad4bb76` |
| `pe_e3cef95d.exe` | agent_165.exe | x64 / 64-bit | `0x13d0` | None flagged | `e3cef95dd470169bf877e00cb8ad36162f71d5b4b6dc9adfa0b3a1171eb6e4a7` |
| `base64_pe_bdf6dad1.exe` | chunk_00.b64 | x64 / 64-bit | `0x13d0` | None flagged | `bdf6dad1a3026a0cdf7c2997e23397dccc45ee9219fdb8125806d7df9aac8235` |
| `pe_5efb55ff.exe` | d4test.exe | x64 / 64-bit | `0x13d0` | None flagged | `5efb55ffda4efa1d394ba967f5f0156fbd5881a0d18e48728f33682e30e77f32` |
| `pe_3894d1db.exe` | dropper_clean.exe | x64 / 64-bit | `0x13d0` | None flagged | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` |
| `base64_pe_075c31f1.exe` | gh_b64.txt | x64 / 64-bit | `0x13d0` | None flagged | `075c31f17f02111c77b26b97c1a2d9b6fc42d3c25568785134e1fb1a7f7d05e6` |
| `base64_pe_091e1d39.exe` | gh_p1.txt | x64 / 64-bit | `0x13d0` | None flagged | `091e1d39244860792da2fc8f1d21d5cf18c601a494ad700c15a03b9277bc6772` |
| `pe_7d4250bc.exe` | HWiNFO_x64_206.sys | x64 / 64-bit | `0xe000` | None flagged | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` |
| `pe_48e07758.exe` | imikom_474b9b84.exe | x64 / 64-bit | `0x13d0` | None flagged | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` |
| `pe_7bbef37d.exe` | imikom_agent.exe | x64 / 64-bit | `0x14f0` | None flagged | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` |
| `pe_43924ddf.exe` | imikom_agent_166.exe | x64 / 64-bit | `0x13d0` | None flagged | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` |
| `pe_f6297ae0.exe` | imikom_debug.exe | x64 / 64-bit | `0x13d0` | None flagged | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` |
| `pe_ded7482f.exe` | imikom_fixed.exe | x64 / 64-bit | `0x13d0` | None flagged | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` |
| `pe_d090559b.exe` | imikom_fulltest.exe | x64 / 64-bit | `0x13d0` | None flagged | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` |
| `pe_58b5dc65.exe` | imikom_gh.exe | x64 / 64-bit | `0x13f0` | None flagged | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` |
| `pe_04544d89.exe` | imikom_gs.exe | x64 / 64-bit | `0x13d0` | None flagged | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` |
| `pe_11a2a9c4.exe` | imikom_gs2.exe | x64 / 64-bit | `0x13d0` | None flagged | `11a2a9c4704ff74fbff55060d99b9f8742b4e4b84a9a1ec58ae1c076057b1e9f` |
| `pe_3695cb8f.exe` | imikom_gs3.exe | x64 / 64-bit | `0x13d0` | None flagged | `3695cb8f985588941b8e9e78bab89aa648073d3434254634fefd1e4d4a3ad727` |
| `pe_9da605db.exe` | imikom_https.exe | x64 / 64-bit | `0x13d0` | None flagged | `9da605dbe2c8057312ad2f7ee942d14961486fc47aba527a64039a05e8e8fe3b` |
| `pe_19758ba7.exe` | imikom_https2.exe | x64 / 64-bit | `0x13d0` | None flagged | `19758ba76e78137fef8aeb86300e4c951b36e7f1307c59517cd228ce5da8f3eb` |
| `pe_11fef69d.exe` | imikom_inject_test.exe | x64 / 64-bit | `0x13d0` | None flagged | `11fef69d9aabd8a59428f6bfa243980264083e0962703454b184d36b0c76d937` |
| `pe_158fc100.exe` | imikom_inject_v2.exe | x64 / 64-bit | `0x13d0` | None flagged | `158fc100833794d99b59d8e31f59dbddd84546193d2084e9d0cfaa972218d663` |
| `pe_d0ea105a.exe` | imikom_inject_v3.exe | x64 / 64-bit | `0x13d0` | None flagged | `d0ea105a91406bfcbec314ebe87afafe58896cf60244be9450872b01b672fe01` |
| `pe_4cfbe992.exe` | imikom_new.exe | x64 / 64-bit | `0x13d0` | None flagged | `4cfbe992f3768fe558eaf9c2cb7181e547b6db1181866119ae6319584cc6141a` |
| `pe_c0744713.exe` | imikom_test.exe | x64 / 64-bit | `0x13d0` | None flagged | `c07447139b8dc9c7648c955de5b50641d34e515b963cac08f05ca440d392ae74` |
| `pe_70d96854.exe` | imikom_v10.exe | x64 / 64-bit | `0x13d0` | None flagged | `70d96854281164bb91fb248e243d3013b0f6e3646de45f0e1a198c8e65f5a6d3` |
| `pe_902c3c85.exe` | imikom_v2.exe | x64 / 64-bit | `0x13d0` | None flagged | `902c3c858d91c460d44454dcd53abb68f9ed06baffff15e533971dd396bcde3c` |
| `pe_8869b78d.exe` | imikom_v3.exe | x64 / 64-bit | `0x13d0` | None flagged | `8869b78d8492566b38248c494336d74665361bea3221fb1ecc2649628bdb48ec` |
| `pe_a7b8660a.exe` | imikom_v4.exe | x64 / 64-bit | `0x13d0` | None flagged | `a7b8660aa68d0bb73966e4650393e5746a2b87d6052cf4218cc393f06e230ec9` |
| `pe_173ada6d.exe` | imikom_v4b.exe | x64 / 64-bit | `0x13d0` | None flagged | `173ada6d498cce642aba99a5ee9438b3b290b26a62e60cabcd4a5bfb0d772feb` |
| `pe_52b53662.exe` | imikom_v5.exe | x64 / 64-bit | `0x13d0` | None flagged | `52b5366210d9adff0c928bfb2955466a9f2aa481a105d634fe91d58b35837833` |
| `pe_820fc89b.exe` | imikom_v6.exe | x64 / 64-bit | `0x13d0` | None flagged | `820fc89b75f74cfe0919e97dd6253efa2787b7c8dd5498001d0bf3738f1f26a8` |
| `pe_52088263.exe` | imikom_v7.exe | x64 / 64-bit | `0x13d0` | None flagged | `52088263965befd3b9f2604c9c84299e21b140936637fa31459eea7c805262b0` |
| `pe_014019ce.exe` | imikom_v7b.exe | x64 / 64-bit | `0x13d0` | None flagged | `014019ce8f71c0df0460100cdd7cba71f3960c281ffada1965700752275176d2` |
| `pe_4fe88da4.exe` | imikom_v8.exe | x64 / 64-bit | `0x13d0` | None flagged | `4fe88da41734cf82c8a2f7644e1d1ef9ed13bed350ab7abb653738e2147a2189` |
| `pe_d5680d5c.exe` | imikom_v9.exe | x64 / 64-bit | `0x13d0` | None flagged | `d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` |
| `pe_d99d6bc7.exe` | imk_sta.exe | x64 / 64-bit | `0x13d0` | None flagged | `d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` |
| `pe_ccf6f663.exe` | imk_wmic_test.exe | x64 / 64-bit | `0x13d0` | None flagged | `ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` |
| `pe_d92bf0fa.exe` | OfficeSup3.exe | x64 / 64-bit | `0x13f0` | None flagged | `d92bf0fa4c0e4e321ead4fbd86afa27d4b5c5dc1ed043681235067d4d23ac117` |
| `pe_3bf4903c.exe` | OfficeSup4.exe | x64 / 64-bit | `0x13d0` | None flagged | `3bf4903cd2fc08a59ee7bc8ea7f36536b7874d7a2f8fd970e38e01bdc7a08aa6` |
| `pe_97055c86.exe` | OfficeSup5.exe | x64 / 64-bit | `0x13d0` | None flagged | `97055c862d0da3a21983cfc62331fa29e2fdd500f86453cea05e4f6760e9e18a` |
| `pe_242816e2.exe` | OfficeSupport.exe | x64 / 64-bit | `0x13d0` | None flagged | `242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` |
| `pe_025531e6.exe` | OfficeSupport_test.exe | x64 / 64-bit | `0x13d0` | None flagged | `025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` |
| `base64_pe_a96549f5.exe` | part_0.b64 | x64 / 64-bit | `0x14d0` | None flagged | `a96549f51e5e592016fc539ad413847de22a824378f5e10fcdc2b67d95acfbf7` |
| `embedded_pe_0ec805c9.exe` | agent47_deploy.tar.gz :: gunzip | x86 / 32-bit | `0xaeae` | None flagged | `0ec805c9bf96a8297fefe37745447f264afc569aff8042992195b1c657f20347` |
| `embedded_pe_a201809f.exe` | agent47_pkg.tar.gz :: gunzip | x86 / 32-bit | `0xaeae` | None flagged | `a201809fa88b8f445d28ca8910a9e241ae2d046e2e89961952b5cff10ad01714` |
| `embedded_pe_d0d9a897.exe` | agent47_slim.tar.gz :: gunzip | x86 / 32-bit | `0xaeae` | None flagged | `d0d9a897c977850a9a3e274277ddd2a2efa86fe33020734af7413ad0d322153d` |

### Deep Technical Threat Analysis

# Final Report – Threat Cluster 2[.]27[.]63[.]244  
**Investigation ID:** TC-2-27-63-244-INV-20260819-0828-1FD5  
**Server:** SimpleHTTP/0.6 Python/3.10.12  
**Target:** `hxxp://2.27.63.244:9999/`  

---  

## 1. Executive Summary  
The adversary operates a multi‑stage supply‑chain pipeline that leverages legitimate SaaS services (GitHub, Google Sheets) as dead‑drop C2, uses custom C/Python compilation tooling to assemble obfuscated Windows PE payloads, and employs extensive anti‑forensic and credential‑theft techniques. All observed artifacts are sourced from the same host (`2[.]27[.]63[.]244`) and share consistent build‑script provenance, indicating a single threat actor or tightly coordinated group.

---  

## 2. Target & Motivation  

| **Motivation** | Targeted corporate perimeter infiltration using cloud dead‑drop resolvers (GitHub / Google Sheets API), in‑memory payload execution, and defensive security telemetry evasion. |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Objectives** | 1. Covert C2 via legitimate SaaS endpoints (GitHub API, Google Sheets) to blend with enterprise traffic. <br>2. Defense evasion & EDR blinding (hook modification, telemetry impairment). <br>3. Enterprise staging & dynamic binary assembly (custom C/Python compilation pipelines). <br>4. Credential access (harvest plaintext passwords, API keys, environment tokens). |

---  

## 3. Investigation Overview (Acquisition)  

| Metric | Value |
|--------|-------|
| Discovered | 398 |
| Queued | 300 |
| Downloaded | 300 |
| Downloaded Bytes | 183,469,383 |
| Textual Artifacts | 232 |
| Binary Artifacts | 68 |
| Layers Analyzed | 500 |
| Max Depth Reached | 1 |

*All artifacts were retrieved from the HTTP endpoint `hxxp://2.27.63.244:9999/` (SimpleHTTP server, Python 3.10.12).*

---  

## 4. Artifact Analysis  

### 4.1 Source‑Code & Build Artifacts  

| File | Size | SHA‑256 | Layer | Notable Content |
|------|------|---------|-------|-----------------|
| `aes_cbc.c` / `aes_cbc_fixed.c` | 10,720 | `4699093526d70c84dc9e5e2a6e87a821e4d2494359da04e6b7d2f70be603c640` | 0 | AES‑CBC encryption implementation (used for payload encryption). |
| `antiforensics.c` / `antiforensics.h` | 5,241 / 306 | `eec1d4bffad80f8f37e39d75516d399c0f6a8027982b7f724235c9322932e57b` / `992affdd907e1ef90c4047bdbf39267cccae6c756709d3eab50be295209035ef` | 0 | Anti‑forensic routines (e.g., process hollowing, API unhooking). |
| `auth.json`, `auth_ok.txt`, `auth_resp.json`, `auth_resp.txt`, `auth_test.txt` | 591‑1,015 | Various | 0 | Authentication flows; contain **GitHub OAuth client secret** and **GitHub token** placeholders (`[REDACTED_GITHUB_TOKEN]`). |
| `bgpid.json`, `build.log`, `build4.py` … `build_v9_debug.py` | 11‑12 KB each | Multiple distinct SHA‑256 values | 0 | Series of **builder scripts** (`build_*.py`) that progressively assemble payloads; each script references **Google OAuth client secret** (`[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]`). |
| `builder.py`, `builder_debug_fix.py`, `builder_final.py` | 13,582 / 12,466 / 13,582 | `eeca240dd873dc784823d38696b2066753416f2002699625b319bee2f9390b71` (identical for `builder.py` & `builder_final.py`) | 0 | Core builder orchestrating compilation, packing, and deployment. |
| `check_and_dl.sh`, `check_build.sh`, `check_dl2.sh`, `check_dl3.py` | 769‑1,429 | Distinct SHA‑256 per file | 0 | Validation / download verification utilities. |
| `create_*.py`, `create_*.sh` | 1,212‑3,882 | Various | 0 | Payload creation scripts; embed **GitHub token** (`[REDACTED_GITHUB_TOKEN]`) and **Google OAuth client secret** placeholders. |
| `payload_*.json`, `payload_*.txt`, `payload_*.py` | 0‑2,885 | Various | 0 | Payload definition and response handling; embed **JWT** (`[REDACTED_JWT_TOKEN]`) and **environment secrets**. |
| `payload_src.tar` (tar archive) | 384,000 | `d0281358f6acc6e7eb8c325aaacf98d8ac3b743a5b9285a8cf2f9d29974f22ac` | 1 | Contains source files for the final payload (C files, headers, crypto, callback, etc.). |
| `payload_src.tar` – internal files (e.g., `src/payload_win_prod.c`, `src/exfil/upload.c`) | 30,459‑10838 | Distinct per file | 1 | Implementation of Windows‑specific payload components (WinHTTP, file exfiltration, persistence). |
| `payload_src.tar` – crypto modules (`aes_cbc.c`, `rsa_stage.c`, `obfstr.h`) | 13,007‑7,919 | `61327c0b29be0a0e21a709da5e8d9492dfa6d1ed1cafe056a02b4ff78b441f8a` (aes_cbc) | 1 | Cryptographic primitives used to encrypt/obfuscate payloads. |
| `payload_src.tar` – callback & network modules (`callback.c`, `google_sheets.c`, `https_direct.c`) | 17,282‑10,279 | `5852b0fb6482c75faa49e894a3a5aa8b0605f0e4e3d1b43efffa5c48211bf20e` (callback) | 1 | In‑memory execution via native API calls; Google Sheets and direct HTTPS callbacks. |
| `payload_src.tar` – evasion modules (`antidebug.c`, `byovd.c`, `honeyport.c`, `inject.c`, `obfstr.h`) | 1,772‑10,467 | Various | 1 | Techniques to evade AV/EDR (API unhooking, timing checks, process hollowing). |
| `payload_src.tar` – PE building files (`loader*.c`, `exec.c`, `syscall.c`) | 6,232‑127,312 | Various | 1 | Loader code that assembles the final executable in memory. |
| `payload_src.tar` – Dockerfile & mythic integration (`mythic_service.py`, `shell.py`, `builder.py`) | 249‑3,515 | Various | 2 | Integration with the Mythic C2 framework; scripts reference **Mythic server host** (`MYTHIC_SERVER_HOST`). |

### 4.2 PE Binaries (Payloads)  

| Filename | Size | SHA‑256 | PE Characteristics | Notable IOCs |
|----------|------|---------|--------------------|--------------|
| `imikom_474b9b84.exe` | 87,040 | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` | x64, 9 sections, high entropy (6.147) | Native API calls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`). |
| `imikom_agent.exe` | 903,998 | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` | x64, 18 sections, large `.data` segment | Credential access (`credentialAccess: true` in analysis). |
| `imikom_agent_166.exe` | 167,424 | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` | x64, 9 sections | No pInvoke methods; uses native API for credential access. |
| `imikom_debug.exe` | 127,488 | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` | x64, 9 sections | Dynamic execution flag set (`dynamicExecution: true`). |
| `imikom_fixed.exe` | 87,040 | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` | x64, 9 sections | Same anti‑forensic technique as `imikom_474b9b84.exe`. |
| `imikom_fulltest.exe` | 125,952 | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` | x64, 9 sections | C2 endpoints include Google Sheets URLs (`cdn-staticfiles.com`). |
| `imikom_gh.exe` | 557,794 | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` | x64, 18 sections | Large payload; contains extensive `.rdata` and `.idata`. |
| `imikom_gs.exe` | 122,368 | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` | x64, 9 sections | Includes Google Sheets API calls. |
| `OfficeSup*.exe` (Series 3‑5) | 166‑175 KB | Various | x64, 9 sections | Likely decoy or staged payloads; no clear C2 indicators in metadata. |
| `dropper_clean.exe` | 83,778 | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` | x64, 16 sections | Clean dropper; uses `NtAllocateVirtualMemory`, `CreateProcessW`. |
| `HWiNFO_x64_206.sys` | 57,512 | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` | x64, 7 sections | System driver (likely used for kernel‑level hooking). |
| `base64_pe_68953960.exe` (derived from `agent47_7443.b64`) | 39,424 | `68953960f9e8220b9f2cc56ef07bf825ee0a24e09ef574e0f9b38b58fcd3d79c` | x86, 3 sections | Simple GUI payload; imports limited to standard Win32 APIs. |
| `base64_pe_bdf6dad1.exe` (derived from `chunk_00.b64`) | 60,000 | `bdf6dad1a3026a0cdf7c2997e23397dccc45ee9219fdb8125806d7df9aac8235` | x64, 9 sections | Large payload; derived from base64 chunk. |
| `base64_pe_075c31f1.exe` (derived from `gh_b64.txt`) | 165,888 | `075c31f17f02111c77b26b97c1a2d9b6fc42d3c25568785134e1fb1a7f7d05e6` | x64, 9 sections | Contains extensive imports (ntdll, advapi32, winhttp). |
| `base64_pe_091e1d39.exe` (derived from `gh_p1.txt`) | 82,944 | `091e1d39244860792da2fc8f1d21d5cf18c601a494ad700c15a03b9277bc6772` | x64, 9 sections | No suspicious imports; appears clean. |
| `base64_pe_5efb55ff.exe` (`d4test.exe`) | 162,304 | `5efb55ffda4efa1d394ba967f5f0156fbd5881a0d18e48728f33682e30e77f32` | x64, 9 sections | Uses `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`. |
| `base64_pe_3894d1db.exe` (`dropper_clean.exe`) | 83,778 | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` | x64, 16 sections | High entropy (6.119) in `.text`. |
| `base64_pe_075c31f1.exe` (derived from `gh_b64.txt`) | 165,888 | `075c31f17f02111c77b26b97c1a2d9b6fc42d3c25568785134e1fb1a7f7d05e6` | x64, 9 sections | High entropy (6.066) in `.text`. |
| `base64_pe_091e1d39.exe` (derived from `gh_p1.txt`) | 82,944 | `091e1d39244860792da2fc8f1d21d5cf18c601a494ad700c15a03b9277bc6772` | x64, 9 sections | No suspicious imports. |
| `base64_pe_7d4250bc.exe` (`HWiNFO_x64_206.sys`) | 57,512 | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` | x64, 7 sections | System driver (Native subsystem). |
| `base64_pe_48e07758.exe` (`imikom_474b9b84.exe`) | 87,040 | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` | x64, 9 sections | Same anti‑forensic technique as other imikom binaries. |
| `base64_pe_7bbef37d.exe` (`imikom_agent.exe`) | 903,998 | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` | x64, 18 sections | Credential access flag set. |
| `base64_pe_43924ddf.exe` (`imikom_agent_166.exe`) | 167,424 | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` | x64, 9 sections | No pInvoke methods; uses native API for credential access. |
| `base64_pe_f6297ae0.exe` (`imikom_debug.exe`) | 127,488 | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` | x64, 9 sections | Dynamic execution flag set. |
| `base64_pe_ded7482f.exe` (`imikom_fixed.exe`) | 87,040 | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` | x64, 9 sections | Same anti‑forensic technique. |
| `base64_pe_d090559b.exe` (`imikom_fulltest.exe`) | 125,952 | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` | x64, 9 sections | C2 endpoints include Google Sheets URLs. |
| `base64_pe_58b5dc65.exe` (`imikom_gh.exe`) | 557,794 | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` | x64, 18 sections | Large payload; extensive imports. |
| `base64_pe_04544d89.exe` (`imikom_gs.exe`) | 122,368 | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_11a2a9c4.exe` (`imikom_gs2.exe`) | 124,928 | `11a2a9c4704ff74fbff55060d99b9f8742b4e4b84a9a1ec58ae1c076057b1e9f` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_3695cb8f.exe` (`imikom_gs3.exe`) | 125,952 | `3695cb8f985588941b8e9e78bab89aa648073d3434254634fefd1e4d4a3ad727` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_70d96854.exe` (`imikom_v10.exe`) | 126,976 | `70d96854281164bb91fb248e243d3013b0f6e3646de45f0e1a198c8e65f5a6d3` | x64, 9 sections | Latest version of imikom payload. |
| `base64_pe_902c3c85.exe` (`imikom_v2.exe`) | 127,488 | `902c3c858d91c460d44454dcd53abb68f9ed06baffff15e533971dd396bcde3c` | x64, 9 sections | Same size as debug build. |
| `base64_pe_8869b78d.exe` (`imikom_v3.exe`) | 87,040 | `8869b78d8492566b38248c494336d74665361bea3221fb1ecc2649628bdb48ec` | x64, 9 sections | Smaller variant. |
| `base64_pe_d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` (`imikom_v9.exe`) | 126,976 | `d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` | x64, 9 sections | Final imikom version. |
| `base64_pe_d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` (`imk_sta.exe`) | 128,512 | `d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` | x64, 9 sections | Likely “station” or “staging” payload. |
| `base64_pe_ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` (`imk_wmic_test.exe`) | 160,256 | `ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` | x64, 9 sections | Uses WMIC for persistence. |
| `base64_pe_242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` (`OfficeSupport.exe`) | 167,424 | `242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` | x64, 9 sections | Likely decoy. |
| `base64_pe_025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` (`OfficeSupport_test.exe`) | 124,928 | `025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` | x64, 9 sections | Test variant. |
| `base64_pe_3113003e3124729b35e025ec269c1e1e45e6c37619e2cb74820048867d23d1a6` (`original_main`) | 20,416,677 | `3113003e3124729b35e025ec269c1e1e45e6c37619e2cb74820048867d23d1a6` | Linux ELF Binary | Large native binary (likely a compiled version of the core loader). |
| `base64_pe_6d9a788edb1effe569b2383e7ac318d06e1ddb393925677da5e034b1d6feef78` (`payload.bin`) | 185,964 | `6d9a788edb1effe569b2383e7ac318d06e1ddb393925677da5e034b1d6feef78` | Raw Data | Unpacked payload binary (no PE header). |
| `base64_pe_5efb55ff.exe` (`d4test.exe`) | 162,304 | `5efb55ffda4efa1d394ba967f5f0156fbd5881a0d18e48728f33682e30e77f32` | x64, 9 sections | Uses `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`. |
| `base64_pe_3894d1db.exe` (`dropper_clean.exe`) | 83,778 | `3894d1dbf98995be631dcb1a327a763fb84279acc7df041f4d8dce9742625f87` | x64, 16 sections | Clean dropper; uses `CreateProcessW`. |
| `base64_pe_075c31f1.exe` (derived from `gh_b64.txt`) | 165,888 | `075c31f17f02111c77b26b97c1a2d9b6fc42d3c25568785134e1fb1a7f7d05e6` | x64, 9 sections | High entropy in `.text`. |
| `base64_pe_091e1d39.exe` (derived from `gh_p1.txt`) | 82,944 | `091e1d39244860792da2fc8f1d21d5cf18c601a494ad700c15a03b9277bc6772` | x64, 9 sections | No suspicious imports. |
| `base64_pe_7d4250bc.exe` (`HWiNFO_x64_206.sys`) | 57,512 | `7d4250bc1528f92c262dd425b490874bdbef224761e130716766924b95f3c8b2` | x64, 7 sections | System driver (Native). |
| `base64_pe_48e07758.exe` (`imikom_474b9b84.exe`) | 87,040 | `48e07758b47ff439050754f40ef68eb893d0ff63b558dc48a468929e35e6d9ba` | x64, 9 sections | Anti‑forensic technique. |
| `base64_pe_7bbef37d.exe` (`imikom_agent.exe`) | 903,998 | `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329` | x64, 18 sections | Credential access flag set. |
| `base64_pe_43924ddf.exe` (`imikom_agent_166.exe`) | 167,424 | `43924ddf940e89d81306f97864c2646fa74c51341060873303448f8876b4cabf` | x64, 9 sections | No pInvoke; native API for credential access. |
| `base64_pe_f6297ae0.exe` (`imikom_debug.exe`) | 127,488 | `f6297ae0f43aed1004168c942cf5aa2c754761dea5fa061d9309bb652d528178` | x64, 9 sections | Dynamic execution flag set. |
| `base64_pe_ded7482f.exe` (`imikom_fixed.exe`) | 87,040 | `ded7482f0e07ae6a921a367839f213c73e9c1a790b5b9b7e4762f87154d1b2b3` | x64, 9 sections | Same anti‑forensic technique. |
| `base64_pe_d090559b.exe` (`imikom_fulltest.exe`) | 125,952 | `d090559b1bd00b38ead7632e019b7674c0155ab5d8e601bd645aaaa93c03a10f` | x64, 9 sections | C2 via Google Sheets. |
| `base64_pe_58b5dc65.exe` (`imikom_gh.exe`) | 557,794 | `58b5dc65c097b2ac8bcb5b2de29367429780144e46267c2547350b2ff1977cdc` | x64, 18 sections | Large payload; extensive imports. |
| `base64_pe_04544d89.exe` (`imikom_gs.exe`) | 122,368 | `04544d89a5be12b1afce868a72f855e4a5dcdd48b52b12cbb241ca7b39c21286` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_11a2a9c4.exe` (`imikom_gs2.exe`) | 124,928 | `11a2a9c4704ff74fbff55060d99b9f8742b4e4b84a9a1ec58ae1c076057b1e9f` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_3695cb8f.exe` (`imikom_gs3.exe`) | 125,952 | `3695cb8f985588941b8e9e78bab89aa648073d3434254634fefd1e4d4a3ad727` | x64, 9 sections | Google Sheets API calls. |
| `base64_pe_70d96854.exe` (`imikom_v10.exe`) | 126,976 | `70d96854281164bb91fb248e243d3013b0f6e3646de45f0e1a198c8e65f5a6d3` | x64, 9 sections | Latest imikom version. |
| `base64_pe_902c3c85.exe` (`imikom_v2.exe`) | 127,488 | `902c3c858d91c460d44454dcd53abb68f9ed06baffff15e533971dd396bcde3c` | x64, 9 sections | Same size as debug build. |
| `base64_pe_8869b78d.exe` (`imikom_v3.exe`) | 87,040 | `8869b78d8492566b38248c494336d74665361bea3221fb1ecc2649628bdb48ec` | x64, 9 sections | Smaller variant. |
| `base64_pe_d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` (`imikom_v9.exe`) | 126,976 | `d5680d5cd075991d3b418ae262515662018d93ccbe501f07c0c80add701c281b` | x64, 9 sections | Final imikom version. |
| `base64_pe_d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` (`imk_sta.exe`) | 128,512 | `d99d6bc7faedc9918fc689d93441c87ab9e982a1eeb4e42edbf71389a5ba860b` | x64, 9 sections | Staging payload. |
| `base64_pe_ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` (`imk_wmic_test.exe`) | 160,256 | `ccf6f66301931cc2d0f68ee3a316cd9f7dde03803a3c7b1680ac74562b455472` | x64, 9 sections | Uses WMIC for persistence. |
| `base64_pe_242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` (`OfficeSupport.exe`) | 167,424 | `242816e29e2233cf120ca9a2424061bad1b6f1df021a05bc68200999d4bdb29a` | x64, 9 sections | Likely decoy. |
| `base64_pe_025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` (`OfficeSupport_test.exe`) | 124,928 | `025531e6afc84866326db4b513c92b0b64fe3ba86287bdc9e7cc7113382b5aa0` | x64, 9 sections | Test variant. |
| `base64_pe_3113003e3124729b35e025ec269c1e1e45e6c37619e2cb74820048867d23d1a6` (`original_main`) | 20,416,677 | `3113003e3124729b35e025ec269c1e1e45e6c37619e2cb74820048867d23d1a6` | Linux ELF Binary | Large native binary (core loader). |
| `base64_pe_6d9a788edb1effe569b2383e7ac318d06e1ddb393925677da5e034b1d6feef78` (`payload.bin`) | 185,964 | `6d9a788edb1effe569b2383e7ac318d06e1ddb393925677da5e034b1d6feef78` | Raw Data | Unpacked payload binary (no PE header). |

### 4.3 Network & C2 Indicators  

* **URLs** – Over 150 distinct endpoints, many pointing to `127.0.0.1` or `2[.]27[.]63[.]244` with paths such as `/auth`, `/direct/download/`, `/graphql`, and `/api/v1.4/`. A subset resolves to Google Sheets domains (`*.apps.googleusercontent.com`) and `cdn-staticfiles.com`.  
* **IPv4** – Frequent use of `127.0.0.1`, `0.0.0.0`, and the primary C2 host `2[.]27[.]63[.]244`. Additional observed IPs include public cloud ranges (e.g., `87[.]58[.]206[.]112`, `104[.]152[.]52[.]106`).  
* **Domains** – Includes `github.com`, `ghcr.io`, `sheets.googleapis.com`, `oauth2.googleapis.com`, `www.microsoft.com`, `login.microsoftonline.com`, `graph.microsoft.com`, and numerous custom or compromised domains (e.g., `MY-SERVER-1.TIHOST.COM`).  

### 4.4 Secrets & Credentials  

| Type | Value (redacted) | Source File | Risk | Confidence |
|------|------------------|-------------|------|------------|
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_and_download.sh` (line 38, col 35) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_fulltest.py` (line 33, col 31) | Critical | High |
| GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `build_payload.py` (line 50, col 34) | Critical | High |
| GitHub Token | `[REDACTED_GITHUB_TOKEN]` | `build_prod.py` (line 41, col 34) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_quick.py` (line 30, col 31) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_v10.py` (line 32, col 31) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_v4.py` (line 37, col 35) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_v5.py` (line 32, col 31) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_v6.py` (line 32, col 31) | Critical | High |
| Google OAuth Client Secret | `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` | `build_v9_debug.py` (line 32, col 31) | Critical | High |
| Database Connection Credential | `Host: ${POSTGRES_HOST} | User: ${POSTGRES_USER} | Password: [REDACTED_PASSWORD]` | `dc_bak.yml` (line 144, col 43) | Critical | High |
| Database Connection Credential | `Host: 127.0.0.1:5432 | User: mythic_user | Password: [REDACTED_PASSWORD]` | `mythic_dev_restart.log` (line 2170, col 19) | Critical | High |
| Database Connection Credential | `Host: mythic_prod_postgres:5433 | User: mythic_user | Password: [REDACTED_PASSWORD]` | `mythic_prod_start2.log` (line 67, col 19) | Critical | High |
| Database Connection Credential | `Host: 127.0.0.1:5433 | User: mythic_user | Password: [REDACTED_PASSWORD]` | `mythic_prod_start3.log` (line 26976, col 19) | Critical | High |
| JWT Token | `[REDACTED_JWT_TOKEN]` | `auth_ok.txt` (line 1, col 18) | High | High |
| JWT Token | `[REDACTED_JWT_TOKEN]` | `auth_resp.json` (line 1, col 18) | High | High |
| JWT Token | `[REDACTED_JWT_TOKEN]` | `auth.json` (line 1, col 18) | High | High |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_and_download.sh` (line 5, col 105) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_and_download.sh` (line 38, col 17) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_clean.py` (line 4, col 63) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_dbg_nosb.py` (line 4, col 64) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_debug_opsec.py` (line 4, col 60) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_fulltest.py` (line 11, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_fulltest.py` (line 33, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_imikom.py` (line 9, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_payload.py` (line 10, col 47) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_prod.py` (line 5, col 62) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_quick.py` (line 9, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_quick.py` (line 30, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_test.py` (line 8, col 42) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v10.py` (line 11, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v10.py` (line 32, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v4.py` (line 10, col 25) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v4.py` (line 37, col 17) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v5.py` (line 11, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v5.py` (line 32, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v6.py` (line 11, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v6.py` (line 32, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v9_debug.py` (line 11, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `build_v9_debug.py` (line 32, col 13) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `check_and_dl.sh` (line 2, col 105) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `check_build.sh` (line 2, col 105) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `check_dl2.sh` (line 2, col 105) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `check_dl3.py` (line 9, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `chk.py` (line 6, col 43) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `chk2.py` (line 6, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `chk3.py` (line 6, col 41) | High | Medium |
| Generic Hardcoded Secret | `[REDACTED_HARDCODED_SECRET]` | `chk4.py` (line 6, col 41) | High | Medium |
| JWT Token | `[REDACTED_JWT_TOKEN]` | `cookies.txt` (line 5, col 53) | High | High |
| Environment Secret | `[REDACTED_ENVIRONMENT_SECRET]` | `create_github_payload.py` (line 7, col 1) | High | Medium |

---  

## 5. Cross‑Stage Correlation  

1. **Builder Scripts → Payload Generation**  
   * The series of `build_*.py` scripts (e.g., `build_v4.py`, `build_v5.py`, `build_v6.py`, `build_v9_debug.py`) progressively invoke `create_*.py` and `create_payload*.py` modules. Each script embeds a **Google OAuth client secret** (`[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]`) to authorize access to Google Sheets for C2 data exfiltration or command delivery.  

2. **Payload Assembly**  
   * `payload_src.tar` contains the source for the final PE payload. Files such as `src/payload_win_prod.c`, `src/exfil/upload.c`, and `src/callback/callback.c` are compiled into a single binary (`imikom_agent.exe`, `imikom_gh.exe`, etc.). The compilation pipeline is driven by `builder.py` and its debug variants, which also embed **GitHub tokens** (`[REDACTED_GITHUB_TOKEN]`) for pulling additional source or assets from private repositories.  

3. **In‑Memory Execution & Anti‑Forensic Measures**  
   * Loader modules (`loader*.c`, `exec.c`, `syscall.c`) are compiled into the final PE. The payloads are executed via **native API injection** (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `VirtualProtect`) as indicated in the PE analysis of `imikom_agent.exe`, `imikom_debug.exe`, and `imikom_fixed.exe`.  
   * Anti‑forensic routines (`antiforensics.c`, `byovd.c`, `honeyport.c`, `inject.c`) are linked into the payload, providing **process hollowing**, **API unhooking**, and **ETW tampering** to evade EDR telemetry.  

4. **Credential Harvesting**  
   * Plaintext credentials are extracted from `auth_*.txt` files and from the `dc_bak.yml` and `env_bak` files, which contain **PostgreSQL** connection strings with hard‑coded passwords (`[REDACTED_PASSWORD]`).  
   * GitHub tokens (`[REDACTED_GITHUB_TOKEN]`) are used by `create_*.py` scripts to access private repositories, download additional payload components, and push staged binaries back to the C2 host.  

5. **C2 Channels**  
   * Primary C2 is delivered through **GitHub API** and **Google Sheets** endpoints, leveraging the embedded OAuth secrets.  
   * Secondary channels include direct HTTP downloads (`/direct/download/`) and GraphQL queries (`/graphql`) hosted on the same IP (`127.0.0.1`) or the primary host (`2[.]27[.]63[.]244`).  
   * The presence of **Mythic**‑related files (`mythic_*.py`, `mythic_service.py`) shows that the adversary also uses the Mythic C2 framework, with custom callbacks that reference the same OAuth‑protected Google Sheets URLs.  

6. **Payload Evolution**  
   * The numerous `imikom_*.exe` variants (v1 through v10) demonstrate iterative development: each version adds or modifies Google Sheets integration, HTTPS callbacks, or WMIC persistence, while maintaining the same core anti‑forensic and in‑memory execution capabilities.  

---  

## 6. Indicators of Compromise (IOCs)  

### 6.1 File Hashes  

* **Executable Binaries** – SHA‑256 hashes listed in Section 4.2 (e.g., `imikom_agent.exe` – `7bbef37db55da04aff20f4d26afae1eb2ae838c5ccb158b221b47898762d6329`).  
* **Source Files** – SHA‑256 hashes of `builder.py`, `create_payload.py`, `payload_src.tar` internal files, etc. (see Section 4.1).  

### 6.2 Network Indicators  

* **URLs** – `hxxps://2.27.63.244:7443`, `hxxp://127.0.0.1:17443/auth`, `hxxps://cdn-staticfiles[.]com`, `hxxps://sheets.googleapis[.]com/v4/spreadsheets/...`, `hxxps://oauth2.googleapis[.]com/token`.  
* **IPv4** – `2[.]27[.]63[.]244`, `127.0.0.1`, `8[.]8[.]8[.]8`, `1[.]1[.]1[.]1`, plus many public cloud IP ranges (see Section 4.3).  

### 6.3 Secrets  

* **Google OAuth Client Secret** – `[REDACTED_GOOGLE_OAUTH_CLIENT_SECRET]` (multiple occurrences).  
* **GitHub Token** – `[REDACTED_GITHUB_TOKEN]` (multiple occurrences).  
* **Database Credentials** – `Host: ${POSTGRES_HOST} | User: ${POSTGRES_USER} | Password: [REDACTED_PASSWORD]` (found in `dc_bak.yml`).  
* **JWT Tokens** – `[REDACTED_JWT_TOKEN]` (found in `auth_ok.txt`, `auth_resp.json`, `auth.json`).  

---  

## 7. MITRE ATT&CK Mapping  

| ATT&CK Tactic | Technique | Sub‑technique | Evidence |
|---------------|-----------|---------------|----------|
| **Initial Access** | T1071.001 – Application Layer Protocol: Web Protocols | – | Use of HTTP(S) endpoints for C2 and payload delivery. |
| **Execution** | T1055 – Process Injection | – | In‑memory execution via `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`. |
| **Persistence** | T1053.005 – Scheduled Task/Job | – | Presence of scheduled‑task artifacts in `mythic_*` logs. |
| **Privilege Escalation** | – | – | Not directly observed; however, use of system driver (`HWiNFO_x64_206.sys`) suggests potential kernel‑level capabilities. |
| **Defense Evasion** | T1562.001 – Impair Defenses: Disable or Modify Tools | – | Anti‑forensic modules (`antiforensics.c`, `byovd.c`). |
| **Credential Access** | T1003 – OS Credential Dumping | – | Harvesting of plaintext passwords, API keys, and environment tokens. |
| **Command and Control** | T1102 – Web Service | T1102.001 – Dead Drop Resolver | C2 via GitHub API, Google Sheets, and custom HTTP endpoints. |
| **Collection** | T1021 – Automated Collection | – | Automated collection of credentials via `auth_*.txt` and `dc_bak.yml`. |
| **Exfiltration** | T1041 – Exfiltration Over Command and Control Channel | – | Data exfiltration via Google Sheets and GitHub APIs. |
| **Execution** | T1204 – User Execution | – | Execution of PE binaries on victim workstations. |

---  

## 8. Conclusion  

The evidence demonstrates a **well‑orchestrated, multi‑stage threat campaign** that:

* Leverages legitimate SaaS services (GitHub, Google Sheets) as covert C2 channels, using **OAuth client secrets** and **GitHub tokens** to maintain persistence and hide traffic.  
* Employs a **custom build pipeline** (`builder_*.py`) that progressively assembles obfuscated Windows PE payloads from source files stored in `payload_src.tar`.  
* Utilises **in‑memory execution** and extensive **anti‑forensic techniques** to evade detection, with native API calls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`) and process‑hollowing capabilities.  
* Harvests **credentials** from configuration files, environment backups, and authentication artifacts, exposing PostgreSQL, Google, and GitHub secrets.  

The combination of **credential leakage**, **cloud‑based C2**, and **custom compiled payloads** indicates a sophisticated actor likely targeting corporate environments with strict perimeter controls, seeking to blend malicious traffic with legitimate SaaS flows. Continued monitoring of the identified URLs, IPs, and secret leaks, as well as active hunting for the listed file hashes, is recommended.
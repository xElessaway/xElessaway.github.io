---
title: "Technical Teardown of Staging Infrastructure at 2[.]27[.]63[.]244"
description: "Forensic analysis of exposed malware staging and C2 infrastructure identified at 2[.]27[.]63[.]244."
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

Analysis of exposed operational directory telemetry at `2[.]27[.]63[.]244:9999` identified active staging artifacts and offensive tooling.

### 1. Observed Tooling & Capabilities
* **Cobalt Strike 4.9.1**
* **Mythic C2 Framework**
* **MSHTA Script Dropper**
* **Malicious ISO / LNK Phishing Lures**
* **In-Memory Shellcode Injector (P/Invoke)**
* **Multi-Byte XOR Shellcode Decryptor**
* **GitHub Contents API C2 Transport**
* **Google Sheets API C2 Transport**
* **BYOVD Vulnerable Signed Drivers (Kernel Blinding)**
* **JNDI / Marshalsec Deserialization RCE**
* **Process Hollowing Injector**

### 2. Verified High-Fidelity Indicators (IOCs)

| IOC Type | Indicator / Hash | Role & Context | Confidence |
|---|---|---|---|
| **Staging Host IPv4** | `2[.]27[.]63[.]244` | Primary Adversary Staging Node | High (100%) |
| **Service Port** | `2[.]27[.]63[.]244:9999` | Exposed Staging Directory | High (100%) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:7443` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:17443` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:8080` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:2027` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:12339` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:13235` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:9888` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:8712` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:2000` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:7000` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:3000` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:2022` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:3599` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:60479` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:5872` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:13464` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:13568` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:20095` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:19782` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:7256` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:20194` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:14224` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:10448` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:7244` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:20482` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:13400` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:4892` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:20494` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:20478` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:15148` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:12697` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:12032` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:17853` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:6424` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:1751` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:1007` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:55355` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:2770` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:2026` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:8090` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:8888` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **Observed Listener Port** | `2[.]27[.]63[.]244:1234` | Discovered Backend Listener Endpoint | High (Code Verified) |
| **SHA-256 Hash** | `4699093526d70c84dc9e5e2a6e87a821e4d2494359da04e6b7d2f70be603c640` | Artifact: aes_cbc.c | High (100%) |
| **SHA-256 Hash** | `4699093526d70c84dc9e5e2a6e87a821e4d2494359da04e6b7d2f70be603c640` | Artifact: aes_cbc_fixed.c | High (100%) |
| **SHA-256 Hash** | `20d8e0e9a1f755f8bfc59caf8c3929ed3f5d29d5638c007ab821c880a9250011` | Artifact: agent.bin | High (100%) |
| **SHA-256 Hash** | `6eb9d48045b8368bdd0790668543b186bb125bc15dbe81843da96b7c0c483d91` | Artifact: agent47_7443.b64 | High (100%) |
| **SHA-256 Hash** | `795877965ea9b9c51b0aae25da5cfeff0e641db3596221af688afeb8b0f93248` | Artifact: agent47_7443.exe | High (100%) |
| **SHA-256 Hash** | `3bf9764dec01f7b8656c126c325290239101a332b7043e0d7173b2a3a21bd165` | Artifact: agent47_fixed.exe | High (100%) |
| **SHA-256 Hash** | `b753bc3758ef2e0aa4604ae9e199d58bdfdcedc1ab30ec8986f91af940c6d21e` | Artifact: agent47_template.exe | High (100%) |
| **SHA-256 Hash** | `b753bc3758ef2e0aa4604ae9e199d58bdfdcedc1ab30ec8986f91af940c6d21e` | Artifact: agent47_template_real.exe | High (100%) |
| **SHA-256 Hash** | `c215fd67e17b141688c67b1f18a68c63db3dc8adc40260fadc80d2032e3f1770` | Artifact: agent_165.bin | High (100%) |
| **SHA-256 Hash** | `8def9e7f020f0a40390fb021ba6ae761e80cbaf486103e0aecaa0e05a66a5600` | Artifact: agent_165.exe | High (100%) |
| **SHA-256 Hash** | `c239612cf1a089db45b0ebca60498e5eeee97b7f89d06a42d24f88f23ca59a98` | Artifact: agent_166.bin | High (100%) |
| **SHA-256 Hash** | `eec1d4bffad80f8f37e39d75516d399c0f6a8027982b7f724235c9322932e57b` | Artifact: antiforensics.c | High (100%) |
| **SHA-256 Hash** | `992affdd907e1ef90c4047bdbf39267cccae6c756709d3eab50be295209035ef` | Artifact: antiforensics.h | High (100%) |
| **SHA-256 Hash** | `883a50868c9e6a08c5c4ae6d2dd81eea5ba8b4ed447a686d272d21438ff6148b` | Artifact: auth.json | High (100%) |
| **SHA-256 Hash** | `172fac388bf9fbb7daf7eefba4488b66b74d2f6ecd3bd567e9f25dd04428ec97` | Artifact: auth_resp.json | High (100%) |
| **SHA-256 Hash** | `0ce66f84ae9bfc26543b4017d6707f6c67007c03817ba97e73a1fb207370f4b9` | Artifact: bgpid.json | High (100%) |
| **SHA-256 Hash** | `54a6ad08bea5cac4944bce0e343f793e3373b5c67b3db2f56394d1b624c1d552` | Artifact: build4.py | High (100%) |
| **SHA-256 Hash** | `25b59f5adfacfc693a260ea702e3013979b8a32c2bb0eb6fdc273f11dffb6ecd` | Artifact: build5.py | High (100%) |
| **SHA-256 Hash** | `8625882da937c65cec7a27be4c2d42c68b1790e68b91e1cb5048cf5c583261ac` | Artifact: build6.py | High (100%) |
| **SHA-256 Hash** | `da4ad0fbe6de91ae0aa44dc55b469dc6ef0fc15573640a31d6daecc79d46f42c` | Artifact: build7.py | High (100%) |
| **SHA-256 Hash** | `f206d84bb2b12972aa7125796c33273e5a0c7685d7e7aa2f8a69d3dcaff26036` | Artifact: build_and_download.sh | High (100%) |
| **SHA-256 Hash** | `96928cfb02bc46976a0b01c03c4262e37878b8e41a0922195e73b038543cde08` | Artifact: build_clean.py | High (100%) |
| **SHA-256 Hash** | `2c82f8fbb7abbed12013fb1270601099de6123e7b2056f44c633201a681edc4e` | Artifact: build_dbg_nosb.py | High (100%) |
| **SHA-256 Hash** | `b90beb77c045d781f8b1f7539cc6dd916e9682509d6a429ad5b52f7e0991bd44` | Artifact: build_debug_opsec.py | High (100%) |
| **SHA-256 Hash** | `40ad0ff2bdc50e17d9e79a889445b0977effe404cb08dae2d324aa91d7fc456f` | Artifact: build_fulltest.py | High (100%) |
| **SHA-256 Hash** | `360a482b2fc1cc5c97819a711e275fdd613b96b6666784bdb5483664cbddb7af` | Artifact: build_imikom.py | High (100%) |
| **SHA-256 Hash** | `e91e05c048641e19c3d29c093a1bba2d5a726126f38aa83453672668e66448b2` | Artifact: build_loader.py | High (100%) |
| **SHA-256 Hash** | `9c5df783d522beed42b8fef23894a7e76c7a788cbf88725680f3ef76c245b332` | Artifact: build_loader3.py | High (100%) |
| **SHA-256 Hash** | `e308a9cda9bd31ab9cbaadc6557a2c08b5675ecd5b37a0c97d2a21a6527dd1c0` | Artifact: build_payload.json | High (100%) |
| **SHA-256 Hash** | `b1c7aa3bd01f4ad6d0293b2022c9a92f8058cec250ab9152676a6e6b0c72fa16` | Artifact: build_payload.py | High (100%) |
| **SHA-256 Hash** | `44a9cbb39fb9ca4525e4e3dbb1f0feb23817f0532ce11733abeefe1f8e9d468f` | Artifact: build_prod.py | High (100%) |
| **SHA-256 Hash** | `ce9fa1f63a0e858c37f027eb911ee475a704f9f329f8eb564dc37309295cefb9` | Artifact: build_quick.py | High (100%) |
| **SHA-256 Hash** | `ecba381a5455c5fd68cddab11a80bb934d0bd671e22709f5c406cae18f3e05b1` | Artifact: build_req.json | High (100%) |
| **SHA-256 Hash** | `9736ba38fd5a359c1e8cdd791fd154d884fe605a9004c941c1d50f16f53aaf13` | Artifact: build_test.py | High (100%) |
| **SHA-256 Hash** | `5f7ce29e01a3c8667c02d8b3585b33e1b0c894465b8711c818d464b4fa6b460a` | Artifact: build_v10.py | High (100%) |
| **SHA-256 Hash** | `60328408c3417067979b71517acc94f3d4a0ede3ecd7298ce407aa33963d4d02` | Artifact: build_v4.py | High (100%) |
| **SHA-256 Hash** | `fb7c2dbbcd06d2debbabe8f10f6abefbc96c8ffe8f5ad77237c5d61ab293a1ad` | Artifact: build_v5.py | High (100%) |
| **SHA-256 Hash** | `8d59c6ea2f3e4ddf847878173c96fb54e8382194b1be0a768222e64a1263dfd7` | Artifact: build_v6.py | High (100%) |
| **SHA-256 Hash** | `8059694bd3002f48402c56390c4ba4e91eb3e8fb6d4833a99e1f3e5529a0b6ca` | Artifact: build_v7.py | High (100%) |
| **SHA-256 Hash** | `f947e2c98ce8c7484b960164628659084e616a067797b50e94814dd9664ebe4b` | Artifact: build_v9_debug.py | High (100%) |
| **SHA-256 Hash** | `eeca240dd873dc784823d38696b2066753416f2002699625b319bee2f9390b71` | Artifact: builder.py | High (100%) |
| **SHA-256 Hash** | `67592163b05311826720c5b7abbe3d63b9845ada5d440c965686470e0ff81d8e` | Artifact: builder_debug_fix.py | High (100%) |
| **SHA-256 Hash** | `eeca240dd873dc784823d38696b2066753416f2002699625b319bee2f9390b71` | Artifact: builder_final.py | High (100%) |
| **SHA-256 Hash** | `abd5492a80c25dbcd9a716e87dde7992a7b363464f55e83f2344ce66891dc636` | Artifact: builder_fix.py | High (100%) |
| **SHA-256 Hash** | `d20d1fc10ad1f9a25d406c52fe67a39cef848e7c280537759acbd1eb0315e87a` | Artifact: builder_fix2.py | High (100%) |
| **SHA-256 Hash** | `01887f0ae7b926974d8b6e8cc39e7a15ae0c08fe4bf0e9b109a2d6bff7d8feb7` | Artifact: builder_gh.py | High (100%) |
| **SHA-256 Hash** | `7dcbfa4fd7f88a6e89a948eb1a4df3b791a9865a02b0607f24017276c383144b` | Artifact: builder_new.py | High (100%) |
| **SHA-256 Hash** | `c9980798aa08b516fbefe3c2e5c9b8e42e0627d1f68f08da86ff9d0d9b7eabd9` | Artifact: builder_patch.py | High (100%) |
| **SHA-256 Hash** | `331bbb9e71f0dbe2694968340be9d96efaaf00e2902c6db29c221dd4adf0f730` | Artifact: c2params.json | High (100%) |
| **SHA-256 Hash** | `5852b0fb6482c75faa49e894a3a5aa8b0605f0e4e3d1b43efffa5c48211bf20e` | Artifact: callback.c | High (100%) |
| **SHA-256 Hash** | `9228b7aa820f9ccce43ac74a1357b3e567dc406d4773e10f8c6c46ed855bd774` | Artifact: callback.h | High (100%) |
| **SHA-256 Hash** | `c87811d196175938ade48c21677c627ed10988eb787acb6c5768267635e2adec` | Artifact: cat.py | High (100%) |
| **SHA-256 Hash** | `dd848382e07618ad352e566792067d4fec9e4383893a0bb61c4c7b50352cb24a` | Artifact: cbs.json | High (100%) |
| **SHA-256 Hash** | `c2b1da3edfdf6fbcd6a87e9dc31d84bfe666d892a54bf0aa4a012b9998696264` | Artifact: cfg_gh_test.h | High (100%) |
| **SHA-256 Hash** | `3e4f501929e9411b93cf2e3fef66a44c5d499f5a23b16ec31d2d85af058126a3` | Artifact: check_and_dl.sh | High (100%) |
| **SHA-256 Hash** | `f362476c11a4ec0e6eb2fe788156047efd56e314a9ddf033f9dc2900a3ff8baf` | Artifact: check_build.sh | High (100%) |
| **SHA-256 Hash** | `ec4f2f9cfacd18ca66f61479b2298b7813fa3d633376e94f7fd52a41ae9ed94e` | Artifact: check_dl2.sh | High (100%) |
| **SHA-256 Hash** | `a356b236b01c846532a8ecdc01d35acb53bec7f4bb19683f303074c56cc12c94` | Artifact: check_dl3.py | High (100%) |
| **SHA-256 Hash** | `b3cb587fd43759eb49b20a286d5011ca0c6e3e9b3c7ccd3e3ecaefafc538c5a2` | Artifact: chk.py | High (100%) |
| **SHA-256 Hash** | `a0ce38d6c07469ba930947a5cd90d1b158f3322c80ed1fe60eed956538fbbf2e` | Artifact: chk2.py | High (100%) |
| **SHA-256 Hash** | `68d21f6524297a27a4903400b7e9486df93176e74c80e19950fe06643d423567` | Artifact: chk3.py | High (100%) |
| **SHA-256 Hash** | `c33f8cd10024d05b3ece8903f2be36614cb6bb2bfdd73b844bcb9734feda8b5f` | Artifact: chk4.py | High (100%) |
| **SHA-256 Hash** | `2a307cdd0102ace2555dab515452de7b7f9122f11712802aba7e3bc0983d273c` | Artifact: chunk_00.b64 | High (100%) |
| **SHA-256 Hash** | `de958a9a3b9ebed1864516d9d9107274285845cf7bf1502c92174acc7033bf0f` | Artifact: chunk_01.b64 | High (100%) |
| **SHA-256 Hash** | `d4c72566329beacedab6296250733534502c201b7e49f3a95c9b4ba54b9b97cd` | Artifact: chunk_02.b64 | High (100%) |
| **SHA-256 Hash** | `f852bf921386cb8d06f7d5fae7c517f3bc991acd3e34ec5a577037dbbabb6239` | Artifact: cmd.py | High (100%) |
| **SHA-256 Hash** | `642540a5814ae0d22e5bfedef4e59e412362519b72d75fc9035691f957b837f1` | Artifact: compose-build-metadataFile-03efa854-88cb-49f2-b370-79ac4a5cebe8.json | High (100%) |
| **SHA-256 Hash** | `ad77f8fdb3482ba7999d0fcc02f481d3256fbde087fbebe86534946643282c4b` | Artifact: config.h | High (100%) |
| **SHA-256 Hash** | `af32afd93ea34c724f4f84da97ecc501c6c022a3feebb465b597510169e20444` | Artifact: config_override.h | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: cr.json | High (100%) |
| **SHA-256 Hash** | `1533346e84871c84c92e36ceacedad7e8017c6efad1b610de9226dca887f6b0f` | Artifact: create.json | High (100%) |
| **SHA-256 Hash** | `9be0a916ac335c3ad1e02bbf1cf693f460764a0b7d985e1c482f4649acecb45e` | Artifact: create2.json | High (100%) |
| **SHA-256 Hash** | `f05d385a589f11e860c94e377d9f6e6ec887dc02f223ee59cfa9a41955edaadb` | Artifact: create_gh2.py | High (100%) |
| **SHA-256 Hash** | `b512f9ea3740481c7ffdad0989ef7913513e714abeb6b7b9398e61ae6a5ce47f` | Artifact: create_gh_payload2.py | High (100%) |
| **SHA-256 Hash** | `b2837ae452647abf23145ec4912a5b0051fc0ab19b3d3246cfff4768b850e3c8` | Artifact: create_gh_payload3.py | High (100%) |
| **SHA-256 Hash** | `ff97bc77b51dc33eb19b7b06898384939293ca0544d5d9ab50e2dd1de66e6748` | Artifact: create_github_payload.py | High (100%) |
| **SHA-256 Hash** | `b1d4e422fd5b31200212f50cc85262ea00c1fd64a444da3bc013ddd2b100659d` | Artifact: create_no_c2.py | High (100%) |
| **SHA-256 Hash** | `165804b287960c4787bf4c9f53a2cfee7a94d28df4733d8e2e4f4775a6795098` | Artifact: create_out.json | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: create_payload.json | High (100%) |
| **SHA-256 Hash** | `52b481e1e9d9904564195668b22f136343cdfcf516e959966b404d954758dc0a` | Artifact: create_payload.py | High (100%) |
| **SHA-256 Hash** | `173aea77545b5546c34cec72a9f3a3772be05b0eb40f9bddaba925c911300610` | Artifact: create_payload2.py | High (100%) |
| **SHA-256 Hash** | `d2d7f3c44d4ff6fbfce47bba6560567df24f828c38b67d787c2ddc9136588d81` | Artifact: create_payload3.py | High (100%) |
| **SHA-256 Hash** | `acad515fd23463aae211800943d284d700cab78d32defe033048cebb7bd5e90a` | Artifact: create_payload4.py | High (100%) |
| **SHA-256 Hash** | `75be6370d138bee5dcc5e3191b678f41efbd4553cfeed133c71f9d41e1ae6eb8` | Artifact: create_payload5.py | High (100%) |
| **SHA-256 Hash** | `830cb00f98eddc9fcabbc2f48d1a6f5c8f9e201e573c2df60eea5fb9722dbfd5` | Artifact: create_payload_final.sh | High (100%) |
| **SHA-256 Hash** | `dcd4a2d865f88e7cd969441207fae3fafc24f048262b557548a7fe15f608d83e` | Artifact: create_result.json | High (100%) |
| **SHA-256 Hash** | `a6347831e3ec6da4837265d06b7c2f1281463ebb12fb13abbb925b3ce8eb1452` | Artifact: d4test.exe | High (100%) |
| **SHA-256 Hash** | `b7b38dbdec1ba26face3122934c8e3bfa25818f8fcc4fc61842d15f879935693` | Artifact: dc_bak.yml | High (100%) |
| **SHA-256 Hash** | `8158c6144afa4ac3f348896b487344da921990c4903f20c923d5832c826047ce` | Artifact: deploy_builder.py | High (100%) |
| **SHA-256 Hash** | `5069075471b728a638bd4f645620c823d823dc2cd54b42c00353f9a6ab21f491` | Artifact: deploy_callback.c | High (100%) |
| **SHA-256 Hash** | `75e45150612ded044af4e2477d0cdfd6e87089b434645da5eb2e7ab7bcc6651a` | Artifact: deploy_config.h | High (100%) |
| **SHA-256 Hash** | `3254cb2f52303553e846288a6684614405433047a8b10f2a87495f3d766a5a90` | Artifact: deploy_google_sheets.c | High (100%) |
| **SHA-256 Hash** | `d40cb681bf763eb0bb344e2a9a14ab6ce22564f373a995a052c802b89b21e2d2` | Artifact: deploy_google_sheets.h | High (100%) |
| **SHA-256 Hash** | `a13babf04c36309741136a17d4d0b023e053cba7a6cbd160297096a06f9050fa` | Artifact: deploy_Makefile | High (100%) |
| **SHA-256 Hash** | `3c848cbf4b0d8c1d34185bb3d220001d7e515e79f9f461edd209c1b20e777890` | Artifact: diag.py | High (100%) |
| **SHA-256 Hash** | `13dc0f5ae6f8c4506a6d4e303ee257c3ed09bfce63e9f97a1f6fdea5555b650f` | Artifact: diag2.py | High (100%) |
| **SHA-256 Hash** | `e876cffc80ca30a45738a832c80ea08b1ddff17d3045ad4fa00a318ca375ef0c` | Artifact: diag3.py | High (100%) |
| **SHA-256 Hash** | `14b39b0fd9ec14357d35141e7db6b7e8c77f723e39fd43560b25c6a63e9db97b` | Artifact: diag4.py | High (100%) |
| **SHA-256 Hash** | `e63151fe3563b94709a0558c1c069c18e1d1bab83334b9e61175407ab0b51a6d` | Artifact: diag5.py | High (100%) |
| **SHA-256 Hash** | `fd6455ebc5e8f044f8c4fa72e4b6ab0d1c4c6c42d4f090df199a07d2fba2ace1` | Artifact: dl.json | High (100%) |
| **SHA-256 Hash** | `a84e44f64445e1cff6e4a2e614129d481831db271b9e192e6f3f404528a517f3` | Artifact: dl_new.py | High (100%) |
| **SHA-256 Hash** | `a33471811756b631905aa4431533d9009cd2b714967408bc42f92ec97d25433f` | Artifact: dl_out.json | High (100%) |
| **SHA-256 Hash** | `d29afd0a8763cef5e24ff4e76d2b16ae969e4940c6e5b050e3a57fa2f0088697` | Artifact: dl_payload.py | High (100%) |
| **SHA-256 Hash** | `54fbad934fb6ee1b93892a5619ff579764931349f9d99ce4091ad164f4dcacd1` | Artifact: dobuild.sh | High (100%) |
| **SHA-256 Hash** | `4642fdc3ee1babfc4acbb0a8e25651ad373dc73b20cf4dd9f9819314516a2098` | Artifact: doclone.sh | High (100%) |
| **SHA-256 Hash** | `47f0b6424d97b1087f308e755327cc41e59c9a6bd34443274af7580bed465543` | Artifact: download.py | High (100%) |
| **SHA-256 Hash** | `07a134fef6b80bc501dedcbaab54ef235c97441ea251695fc8f769c413375b00` | Artifact: download_payload.sh | High (100%) |
| **SHA-256 Hash** | `dbdcfca642ab09dbd20ddcfb9ea85097635d74db2162891e185acf929df06f00` | Artifact: dropper_clean.exe | High (100%) |
| **SHA-256 Hash** | `9a949e8db3b5dd86353bc03315e34b3f3cf5beacba4fe4209de1972291b5c263` | Artifact: env_bak | High (100%) |
| **SHA-256 Hash** | `bbe9698f756222a34a564b339c8e9042323e8035a3fd9fef2b2de2361f8486b1` | Artifact: events.json | High (100%) |
| **SHA-256 Hash** | `6b6bf23d3171a90d42e07393f45488f5b10d68adad13add169b169a7c13f336f` | Artifact: exec.c | High (100%) |
| **SHA-256 Hash** | `c0c075eafc6101c4ea2235625cfb634594e4354b41e4fdc271983747a3937c95` | Artifact: exit.json | High (100%) |
| **SHA-256 Hash** | `f629170beaa6bcf6f59bd4ae5c18ffb125f789eda51a4ce8bd26023778a28b38` | Artifact: fix_profile.py | High (100%) |
| **SHA-256 Hash** | `0b427c7bb4a0e87d8b74e71adf1d3de1e5b91d4ab7e7fa54e154d9275a04fb25` | Artifact: fulltest.py | High (100%) |
| **SHA-256 Hash** | `24801342793f0183ed7f23eb92f8d186b749e4d3559a033b6f25253143afd9d9` | Artifact: fulltest2.py | High (100%) |
| **SHA-256 Hash** | `64c690f8e184ef7c78decc70ec4f411da77d268443034c5b8bb3824eb22db5c9` | Artifact: fulltest_v10.py | High (100%) |
| **SHA-256 Hash** | `cd50a65e126951c7739fcdb9ad12c0c66cac00bc19e7bfabcb4e201578dc6853` | Artifact: get_output.py | High (100%) |
| **SHA-256 Hash** | `f2f20e412a96f7419b9488a58d097427298f6c73f28cb91907ffd118eb494034` | Artifact: ghp_aa | High (100%) |
| **SHA-256 Hash** | `26ba99208ec0ad8adf558bd170d6abb695be9440a32f13ee3e1ad36f89735f6e` | Artifact: ghp_ab | High (100%) |
| **SHA-256 Hash** | `b433d73e2eb45b57c46d0c5db65071661bb7fac44fc3d0f1f2358677c5f9de7c` | Artifact: ghp_ac | High (100%) |
| **SHA-256 Hash** | `a52036d689120edfd1bccdda935f5e9c69479c0c6d8a392838dca912d700f7b5` | Artifact: ghp_ad | High (100%) |
| **SHA-256 Hash** | `c390f06fd188ec9cdca2ae25c5249cacdb50cf1839aac31baa3cdeda8753d894` | Artifact: ghp_ae | High (100%) |
| **SHA-256 Hash** | `7200ca9d58cdb0d5ca51dc2ec3505582c3fcf2432f4d753f5cd87c898770e0e0` | Artifact: github_c2.c | High (100%) |
| **SHA-256 Hash** | `aa4b46aa14f996a785c9478cea49fde24a0ee354528985ce2fd52479a1196c00` | Artifact: google_c2_demo.py | High (100%) |
| **SHA-256 Hash** | `7169eff6ac6265afcc4322dbdc2e4f06ad08ca1edee26993b0b858a77b8e771a` | Artifact: google_tokens.json | High (100%) |
| **SHA-256 Hash** | `49d775ae52d23f0bbfcc0deca6053065b29b0f15c35b62523f588e2651ff3c69` | Artifact: googlesheets_profile.py | High (100%) |
| **SHA-256 Hash** | `55f7d9e99b8e2d4e0e193b2f0275501e6d9c1ebd29cadbea6a0da48a8587e3e0` | Artifact: gpuz.exe | High (100%) |
| **SHA-256 Hash** | `a1f45dad2df39bb74db4264382313fe445fcb79140211a7f455391f942414655` | Artifact: gql.json | High (100%) |
| **SHA-256 Hash** | `3fadb68968785829de5375fecb7bc9e226396ebd50187cfc3273b708e647a4ba` | Artifact: gql3.json | High (100%) |
| **SHA-256 Hash** | `aff2ac0720b8d1ff24d3c646ce25771ca1419b5f3dbf5f378fd59821cec3352f` | Artifact: gql_c.json | High (100%) |
| **SHA-256 Hash** | `456da91a784fc2a702b86284a5aca4bbcb6d911660c4fcb72445283dde710e3f` | Artifact: gql_cb.json | High (100%) |
| **SHA-256 Hash** | `ad3abaffb908d5e3dca3d681161e333fbbb596a9aaf18d3ecaa94fa24111a4ec` | Artifact: gql_check.json | High (100%) |
| **SHA-256 Hash** | `cd9e392957a8b954f0cef72746bfddcfffca1f47f5dfc7fe94f1ac43fe0b79f1` | Artifact: gql_create.json | High (100%) |
| **SHA-256 Hash** | `0e9d356c3d410adb047b7444ffb5c9ca941155138f18cbbcf2336616f8448390` | Artifact: gql_last.json | High (100%) |
| **SHA-256 Hash** | `c110850c3a3d7d109e4da53affb9046302f541b5c3a8846d90f07ec41932b7da` | Artifact: gql_mut.json | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: gql_out.json | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: gql_out2.json | High (100%) |
| **SHA-256 Hash** | `87f356be87ccc08a40a9a5ad067aa409200a9be1b910c2e57ad622d2eccbaba6` | Artifact: gql_p.json | High (100%) |
| **SHA-256 Hash** | `ad3abaffb908d5e3dca3d681161e333fbbb596a9aaf18d3ecaa94fa24111a4ec` | Artifact: gql_params.json | High (100%) |
| **SHA-256 Hash** | `49e1df47bf2fb597001328f09ff820752f75984236691a9083d7e4988e6df6e2` | Artifact: gql_schema.json | High (100%) |
| **SHA-256 Hash** | `f35b5bb51940457b5461520faa8aa6c88a3b0cac7553c4b2eedb3c5413cf6c86` | Artifact: gql_test.sh | High (100%) |
| **SHA-256 Hash** | `57c3e4ff6f2724b14c263388b010fa3c83aa113b2f1ff0b17f625a60a9210167` | Artifact: gql_u1.json | High (100%) |
| **SHA-256 Hash** | `57c3e4ff6f2724b14c263388b010fa3c83aa113b2f1ff0b17f625a60a9210167` | Artifact: gql_u2.json | High (100%) |
| **SHA-256 Hash** | `57c3e4ff6f2724b14c263388b010fa3c83aa113b2f1ff0b17f625a60a9210167` | Artifact: gql_u3.json | High (100%) |
| **SHA-256 Hash** | `57c3e4ff6f2724b14c263388b010fa3c83aa113b2f1ff0b17f625a60a9210167` | Artifact: gql_u4.json | High (100%) |
| **SHA-256 Hash** | `6b4d17630e794311bdb965c50154e5a18008bc5568fee50aabce826b94fe7ad7` | Artifact: gql_uuid.json | High (100%) |
| **SHA-256 Hash** | `ad3a2abf41b5e421eee2491acd52c75a1d0281292a9013ddf72933b8d302eb9e` | Artifact: graph_demo.py | High (100%) |
| **SHA-256 Hash** | `8dcfffe463585e98ebc93313b380e76a28d2cd5051ccbc5d2f0040b664b23af6` | Artifact: hollow.c | High (100%) |
| **SHA-256 Hash** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Artifact: http_response.bin | High (100%) |
| **SHA-256 Hash** | `fc30003a672aff0d9df974f452b77e0e26b321f8341aacee5af1acb7d1741476` | Artifact: https_direct.c | High (100%) |
| **SHA-256 Hash** | `dbaeca4fe77cde72296ef198309a2097002a86b808a32b5e5156a3f765dad575` | Artifact: HWiNFO_x64_206.sys | High (100%) |
| **SHA-256 Hash** | `d63a9f38661bfb7e77b804257c4e06b19401dace76580bf9e82bb621fa3a3fc6` | Artifact: imikom_474b9b84.exe | High (100%) |
| **SHA-256 Hash** | `e067034e6ec9fdcabe53649dc05afbf3c83c9000e799b881c39b74f92de8914d` | Artifact: imikom_agent.exe | High (100%) |
| **SHA-256 Hash** | `4f166e734bb6a48deedf7d0a1d126c70d8846fbe824418914e47c4e0fc889b6f` | Artifact: imikom_agent_166.exe | High (100%) |
| **SHA-256 Hash** | `3d125f40c9aed07591a9ed344a7d52ab2d99e369b19348155b6d4a5e6b024d65` | Artifact: imikom_debug.exe | High (100%) |
| **SHA-256 Hash** | `b018cd0907658865d6372f13f104029e1ed60666727f284edb68d0dec897bbe8` | Artifact: imikom_dns_fix.tar.gz | High (100%) |
| **SHA-256 Hash** | `f0a4f74d681d95e35c87abd16bf0796160e8cbbc004cc0c5701de23e9972cb8f` | Artifact: imikom_fixed.exe | High (100%) |
| **SHA-256 Hash** | `d0e9302f73aa91a6501aec399f41912f9b609ab0d5f32b49c049850826872443` | Artifact: imikom_fulltest.exe | High (100%) |
| **SHA-256 Hash** | `44873a5d241523d20d8767b762c0a664f8bd3d69391812ab7301696454abd5a2` | Artifact: imikom_gh.exe | High (100%) |
| **SHA-256 Hash** | `a8076816d1d11792606e40b7b78ebaeb933571e6ffac66ef60c23005a5bff6c5` | Artifact: imikom_gs.exe | High (100%) |
| **SHA-256 Hash** | `e5974c773b7436f537a5021ee586c0125405e86dcdd9ac8bd4da4988d0a5e6f7` | Artifact: imikom_gs2.exe | High (100%) |
| **SHA-256 Hash** | `f8b531439b1abc3053b88ebeb76a4c1478bc666cf198f643ef7432da4aaeb9e9` | Artifact: imikom_gs3.exe | High (100%) |
| **SHA-256 Hash** | `d400c43c149927ed7fd218bb072adb5e3f1b02e8ebed275b5966fed43f9e61bf` | Artifact: imikom_https.exe | High (100%) |
| **SHA-256 Hash** | `39a2f33c437260b357c6b5a296400e71a715d8c2d607f29ced4a6d2aebef6910` | Artifact: imikom_https2.exe | High (100%) |
| **SHA-256 Hash** | `e971df605deecf763c6e2e0cba01a390ed09fa851bff0e2cf6b7d947e11b8ab7` | Artifact: imikom_inject_test.exe | High (100%) |
| **SHA-256 Hash** | `89eca8719dbf6a6b6348e54e6430f494fe3eedde4fe49e0c3ed0d38d741439b3` | Artifact: imikom_inject_v2.exe | High (100%) |
| **SHA-256 Hash** | `9fdb9d72bb6cf467bb71a239a8ce4a061edae72a1c110f4757ac8c1e4dcc8c0d` | Artifact: imikom_inject_v3.exe | High (100%) |
| **SHA-256 Hash** | `49971045f09b8bf96462eb939f885b35df60202e1a64148139c5ac34903f5e25` | Artifact: imikom_new.exe | High (100%) |
| **SHA-256 Hash** | `36f7ddc4ef90a1978d79c47c94076951f196bc85aa662800392b4efabc9fe877` | Artifact: imikom_service.yml | High (100%) |
| **SHA-256 Hash** | `bfc6737f17a0f2ae3916ffcbdf0623b219a74bc2b8c37ade4c328dcf6542ad42` | Artifact: imikom_sync.tar.gz | High (100%) |
| **SHA-256 Hash** | `bcbcc9f9871e3d888638dddc3a1b6b6c40e1886deadfe96fdf17464d8fffd2f2` | Artifact: imikom_test.exe | High (100%) |
| **SHA-256 Hash** | `3f92f358ebc76c713f3604eee0d29d26828beb7c55aae3791ef136ba1da3b96d` | Artifact: imikom_v10.exe | High (100%) |
| **SHA-256 Hash** | `81e3482f5525b703d09d7e816c02c3f3d97c2f5c3093cd13a8a2415ad6f29c2a` | Artifact: imikom_v2.exe | High (100%) |
| **SHA-256 Hash** | `e32fc27f29302c43e090de87d75925f4e72e24aac1b8c854430d3512c2a6d8c9` | Artifact: imikom_v3.exe | High (100%) |
| **SHA-256 Hash** | `8d6840c9585a79e9a4e315d4492551f04ce8e724b7c50b3eff2c9e203e304bdc` | Artifact: imikom_v4.exe | High (100%) |
| **SHA-256 Hash** | `92be52975f683120b2e72c5da83cb61dce7fa496416715dc97277f0978585d1f` | Artifact: imikom_v4b.exe | High (100%) |
| **SHA-256 Hash** | `1901945539f4ed74c2d173c2b8c09a193ec101f32bd459a7065f150b3e222bc4` | Artifact: imikom_v5.exe | High (100%) |
| **SHA-256 Hash** | `d459b9b3fea5221a614f690bcbb4acd5ff9dd807574e1ac35bdab99224116995` | Artifact: imikom_v6.exe | High (100%) |
| **SHA-256 Hash** | `12640cdad5d77eba436f856997a49b13c261d4dd726f3b3d4d423d7e65ab0b12` | Artifact: imikom_v7.exe | High (100%) |
| **SHA-256 Hash** | `5f3b1fe35a88af69f1d49fe4da7b3012c1ab2473d4816ff0a0be542a46a516d8` | Artifact: imikom_v7b.exe | High (100%) |
| **SHA-256 Hash** | `ea039606c195fe9b8da34eed3e658262c65fbd8cfbd87cbfb534a768ca7ab647` | Artifact: imikom_v8.exe | High (100%) |
| **SHA-256 Hash** | `6b1326d90c63fa8da7424d8149bf4f801a330eb42097be358b85cb1c7056c5d1` | Artifact: imikom_v9.exe | High (100%) |
| **SHA-256 Hash** | `f236385ffe7ca4dc109112c3c2cd9cbaa1d16f656dd59e8527aa46c39a9d6708` | Artifact: imk_sta.exe | High (100%) |
| **SHA-256 Hash** | `198a42d613e953c75628d29b05ff60af66feb91d020a52ce5e2954281aeda925` | Artifact: imk_wmic_test.exe | High (100%) |
| **SHA-256 Hash** | `5b489e3405d9633a49d63ef489de02da7eb7092ecb67c584906b294195473f2d` | Artifact: kill_process_new.py | High (100%) |
| **SHA-256 Hash** | `a619afbbf3be911f91e3dbea9732e020d98c5d8cd21b2153ffe5df22b114ea0e` | Artifact: lateral.c | High (100%) |
| **SHA-256 Hash** | `59f60d43aa3c5af0bd29dd6490a8245b8caf5537f72a7b7c06c2a13c567f7c57` | Artifact: ldr_patched.c | High (100%) |
| **SHA-256 Hash** | `ca09305aba282c5220dbde1d15d983674256c3efb4129c5a3c14481a5d8df530` | Artifact: list_callbacks.sh | High (100%) |
| **SHA-256 Hash** | `7d21deb02f7d8af5b136ddef9713f5b53967873bb1021db7e4d8c0eddac784e9` | Artifact: loader.c | High (100%) |
| **SHA-256 Hash** | `01ab282f95891424eb9051ecdbfafd6d862cd1b74acec44a41f4dfe7cdd801b9` | Artifact: loader2.c | High (100%) |
| **SHA-256 Hash** | `b70857c83cfb436abba9165cc0670d68c4536e186ccb5f2be3121a7576bdd360` | Artifact: loader3.c | High (100%) |
| **SHA-256 Hash** | `4a6da95fa9b096b698e97e4933362c380ecf0fbc47e75b3b53baff3b050b92b9` | Artifact: loader4.c | High (100%) |
| **SHA-256 Hash** | `ee5132d5dbc8eeb2de59f643f6bca126b2e6dd0c570917b04d4a79146379a30c` | Artifact: loader5.c | High (100%) |
| **SHA-256 Hash** | `9ee4d59bfe27c886b57e92209d4be02951f3f8b63250e76df84adddd7e454e30` | Artifact: loader6.c | High (100%) |
| **SHA-256 Hash** | `66eebf0a7b7b46f73b156020c1c206fe4eecff141a8835849485152b02c8e0a9` | Artifact: loader7.c | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: login.json | High (100%) |
| **SHA-256 Hash** | `452d87e839a4cbf7686ea81e5c7ff73c87cd1ec81c4794dd0198e604a9ef9f68` | Artifact: ls_new.py | High (100%) |
| **SHA-256 Hash** | `6b9523c87381c4c517d3253ca6a4e8c8102bc9209f97882b29ef4ab73963ac2d` | Artifact: main.py | High (100%) |
| **SHA-256 Hash** | `34d9b88309493489fc2ef392792e95d0c65d9d9a44fa3927b564e75c03fbe575` | Artifact: make_token.py | High (100%) |
| **SHA-256 Hash** | `a1bbfbeed5c7dd29bbb04954f3627d74f0eaa83b5aa828377a257cf70303fab9` | Artifact: Makefile | High (100%) |
| **SHA-256 Hash** | `115dde55fa49359ee39576e8e0f65ff421cebd2de75f497cb7ffc35e381fe907` | Artifact: mc_pkg.tar.gz | High (100%) |
| **SHA-256 Hash** | `ae732b02782b56d4540b9a0349ddae7cf39f57e2fe72939a78a24dcfa7d589c7` | Artifact: migrate.py | High (100%) |
| **SHA-256 Hash** | `d38fb275c1f8d6748af509a1ab11bba8148854525a3ff6838d7f8fb643a2d6f6` | Artifact: migrate_fix.py | High (100%) |
| **SHA-256 Hash** | `343d8d22d6935cce1377a6f4dfe374bcbd6caf626f72108453f78e6adc2d2716` | Artifact: migrate_new.py | High (100%) |
| **SHA-256 Hash** | `fd0c36ed4f53e9bf7d529a26f88f6cdc1bc38fea0b512813a45c5f07e376a98a` | Artifact: mkdir.py | High (100%) |
| **SHA-256 Hash** | `9cb5841a4d72edb5d7640a4db4f679635d675532e1b56363a462a6de7500dc76` | Artifact: mythic_backup.tar.gz | High (100%) |
| **SHA-256 Hash** | `09f7843c44d996031133bda5a8f7de6b602f18589bd260a570fda040a0b7d9ee` | Artifact: mythic_cmd.sh | High (100%) |
| **SHA-256 Hash** | `f5b400648e351c78ba43e21d7bd9006ba01cc8ef7777a6b1f4dc29fe1d2f1d2c` | Artifact: mythic_db.sql.gz | High (100%) |
| **SHA-256 Hash** | `05eed5b1bac89e59d0004b83960e9acc258fb1125d6b42b05a91a15d618cff59` | Artifact: mythic_list_cb.sh | High (100%) |
| **SHA-256 Hash** | `7fb50be248af9655f7cd493a7e5c1591b41e9f98c7111ce775fddcf474780480` | Artifact: obfstr.h | High (100%) |
| **SHA-256 Hash** | `5c1ee6965d863916483a9fc27ec6b6e2342ff97203616d57f28c010a398a01a3` | Artifact: obfstr_new.h | High (100%) |
| **SHA-256 Hash** | `c9df2a067a1ed665cfef7919687f8e387e27956e170a09a828b50b74cef3dd4e` | Artifact: obfstr_orig.h | High (100%) |
| **SHA-256 Hash** | `7204dd9518e9a2496308ee27cadb948a05eae0607ba3de10d30f619353baa301` | Artifact: OfficeSup3.exe | High (100%) |
| **SHA-256 Hash** | `6c132e44c7a1387170c11edd5b05f3aba635a9fb0c1601a5f611b3b2f12d74aa` | Artifact: OfficeSup4.exe | High (100%) |
| **SHA-256 Hash** | `987c965e40b2f034f3ecf759f3b379f7359e302af6a4bd34ffa29e1498cf9ef2` | Artifact: OfficeSup5.exe | High (100%) |
| **SHA-256 Hash** | `0dd4bcdb7ef8bcba8bc1a27e189e0a094d10b399a3af1a8d2bc0c88feea8c6f4` | Artifact: OfficeSupport.b64 | High (100%) |
| **SHA-256 Hash** | `1578d839042542d09ec64284c4352fcd4cd224627ef42b2274757b1a67c83a21` | Artifact: OfficeSupport.exe | High (100%) |
| **SHA-256 Hash** | `0aa5cd9a7151bef501d58d40543c0e302ce47e63b95fc65a4367c9777dfb3886` | Artifact: OfficeSupport_test.exe | High (100%) |
| **SHA-256 Hash** | `3e60c83539ee46125246076266a77c234f60808adc5531c6f915e83278c5c9da` | Artifact: original_main | High (100%) |
| **SHA-256 Hash** | `cf3132f6acb71f8a26dc9fce0eeec88ecc5be566a349a8ad5ab557bd7018e130` | Artifact: part_0.b64 | High (100%) |
| **SHA-256 Hash** | `9bae31b7dfbd5e5bf3825b9ffa753079a6a4b8a4344dfa679c1e65569d7cd83a` | Artifact: part_1.b64 | High (100%) |
| **SHA-256 Hash** | `0fc0db8e5c449d66eb682f02ab5ed5f2add8cb2f1878ed0c4241ce2dbfb970a5` | Artifact: part_2.b64 | High (100%) |
| **SHA-256 Hash** | `346605b56e0c6d714d83b82bbd720faa43a201a60baa2d773fc4dbcc1a8a96f7` | Artifact: part_3.b64 | High (100%) |
| **SHA-256 Hash** | `976ecedc71fa605de089e706fcd7e680aaa1de8c554f81d9925d79fe8ca8520e` | Artifact: patch_builder.py | High (100%) |
| **SHA-256 Hash** | `7e78bc8bf2bc2b88d75df90499eafa5d46ce63a9925287c81e1773febf0cc8e8` | Artifact: patch_mcp.py | High (100%) |
| **SHA-256 Hash** | `2c196ac8166219a9357d3d496f9511c4e3399cd088d651a92bfdd5f6ee4b419e` | Artifact: patch_post.py | High (100%) |
| **SHA-256 Hash** | `b01fa873c0523f914ad3404625848ef4f3aef92e0e63d037ef56dfe6ec02c312` | Artifact: payload.bin | High (100%) |
| **SHA-256 Hash** | `56d7ea03d961bee79d65d5a2ab9ec84b46763e4686dc67052b698bf9c8f1cec1` | Artifact: payload_info.json | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: payload_resp.json | High (100%) |
| **SHA-256 Hash** | `d0281358f6acc6e7eb8c325aaacf98d8ac3b743a5b9285a8cf2f9d29974f22ac` | Artifact: payload_src.tar | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: payload_status.json | High (100%) |
| **SHA-256 Hash** | `0da73aaeacf3f5c7a913de523b9eb8d8648bc636bd32b9cd7b3afa30bf803e25` | Artifact: payload_win_prod.c | High (100%) |
| **SHA-256 Hash** | `9f7f1b91d2d501f916fe05bd0f9f42ad6e29bfc5edeb59fff43746f0718abb55` | Artifact: persist.py | High (100%) |
| **SHA-256 Hash** | `170fce4d7e5c5b36ed8d76528aa788f99a274ff79310db1720c4a8b590236db8` | Artifact: poly_verify.py | High (100%) |
| **SHA-256 Hash** | `5a88082d572a114585f87133b86571fc5d6ea0ee01394e35c43e99eb755d572b` | Artifact: powershell_cmd.py | High (100%) |
| **SHA-256 Hash** | `1b34cc5acb9dede118a156236c9c703aaf52a342ab1d90196d27159d289ba90c` | Artifact: prod_build.json | High (100%) |
| **SHA-256 Hash** | `9d0b0438d5ed4e7d36a0f3a3e71567f15bab812f81fb4fe4184f65150fa156d1` | Artifact: profile_fix.py | High (100%) |
| **SHA-256 Hash** | `9f24c6c22aef76d9cba48ddb49b1cbc013910e8a9176ec60aa0f2bef454bfa4f` | Artifact: ps.py | High (100%) |
| **SHA-256 Hash** | `a6082fad7fa9f9c1c8a8efd9026ed19ae8cbaa025b1373d099a2ddda67ee63c4` | Artifact: ps_fixed.py | High (100%) |
| **SHA-256 Hash** | `f60394890a8e8d71da6fefd0f9d493ffc36d2308c9ce35511c4b9f810a4616ff` | Artifact: push4.py | High (100%) |
| **SHA-256 Hash** | `e9eaf51bdb225127d63aecd06a725279c50edc2a2fe23d4db4047c77df977f32` | Artifact: push5.py | High (100%) |
| **SHA-256 Hash** | `a8006d1cbbf91b00f1e3018c2ea60f92879e42f7204fde39579653e2a1cb11e4` | Artifact: push_to_vps.py | High (100%) |
| **SHA-256 Hash** | `ba8ad83df81fd22b7a0f63f81320bebafd5dfb961ba0363bf03072150d37522c` | Artifact: push_vps.py | High (100%) |
| **SHA-256 Hash** | `509b2af74d4c967417bd460fd26cf2ecb33650b719a9cf22566f66647978173f` | Artifact: pwp.c | High (100%) |
| **SHA-256 Hash** | `b90aefaf237bb42ed4895de2df087c43f5e15cc31d46b60eb7487fb2caa7764c` | Artifact: pwp_new.c | High (100%) |
| **SHA-256 Hash** | `adcec5adac5d0738614ccaa37e112060ad612d4efaec94d7d271c4b9d7eecd4b` | Artifact: quick_build.sh | High (100%) |
| **SHA-256 Hash** | `e9ee17ba8d105c7602e77ad551d96e047acef2ba8e7329a21f3965abf03c94b5` | Artifact: results.py | High (100%) |
| **SHA-256 Hash** | `dc2d21ca56fcc2b89fbe7a2f0f3b3b5fd46cbf0f5756a9f8ca3e15f8c15a4602` | Artifact: rev2self.py | High (100%) |
| **SHA-256 Hash** | `869eeba217b0c5d05d3b9c314d17c8274b522115a79cee0dfe16039ee0f47073` | Artifact: rm.py | High (100%) |
| **SHA-256 Hash** | `9a5cb093ec447a00d8e1972b4d5821239076c2f5eed7b00e20b4fcc5eaddba05` | Artifact: rm_new.py | High (100%) |
| **SHA-256 Hash** | `05d342b9b87ba74d74975f1b679b6c73d4bf2d5ece2a76996c9186f480555b2c` | Artifact: schema.json | High (100%) |
| **SHA-256 Hash** | `2af0192d243da27d460154d7409f7300f6d2687d7f28a941ecdbd1a705c0efd5` | Artifact: send_5_tasks.py | High (100%) |
| **SHA-256 Hash** | `98d50241b32565ba9dc704b4c0f12f173abf5337118c66949ba2a65378d0bb2d` | Artifact: serial_test.py | High (100%) |
| **SHA-256 Hash** | `7396d6170612890626006f6c735642c3a4487d82795d0f37b29d8c4fd53a8f98` | Artifact: server.py | High (100%) |
| **SHA-256 Hash** | `daf6934c1317809f6edc896bceff4db8095e7c3cd161fa8f93ec5c59c88d1fe6` | Artifact: services.conf | High (100%) |
| **SHA-256 Hash** | `64698dc4c9c79d3562b60021802372ea43e58c5790fcb286b017c378a054190e` | Artifact: sleep_new.py | High (100%) |
| **SHA-256 Hash** | `aa597084024e117df5a784a2e1f159cd71efb898c531d249aadaf3a09323cd30` | Artifact: sshpass_1.09-1_amd64.deb | High (100%) |
| **SHA-256 Hash** | `6267d2ca7d615d3f669ebb2571234a173747a020b36ceb57d1da39cbc2f85cea` | Artifact: steal_token.py | High (100%) |
| **SHA-256 Hash** | `738da70d85e3d01e129b411a74c582641ce2bccadc11237619ee69f181016ac0` | Artifact: sync_builder.py | High (100%) |
| **SHA-256 Hash** | `8cc7a8a062c89e24f445a9c80919822b2037b68711206fa3eed1e4c51225a27c` | Artifact: sysinfo.py | High (100%) |
| **SHA-256 Hash** | `21722e08d993faa87be5c90df1b3b4dd84b40f31aab8ca8d2bf8342e60992f53` | Artifact: t.py | High (100%) |
| **SHA-256 Hash** | `eaae8bd110dc336e30c062a069f16d9661595a06b500adb62577060937757764` | Artifact: task.py | High (100%) |
| **SHA-256 Hash** | `a4798ee3514585ccd3c8884038102192f0f63591d64403b4d80d1dfc2b2a1b52` | Artifact: task1.json | High (100%) |
| **SHA-256 Hash** | `59437a9035d9203ce0147ca2c757862e052439baafd2b6196f1a9a620732538d` | Artifact: task2.json | High (100%) |
| **SHA-256 Hash** | `44741074de4fe0e24c4df3619ee2790e061f01c1f965b0c648adb7217ec7c05b` | Artifact: task3.json | High (100%) |
| **SHA-256 Hash** | `0fb4f90378ad0e443bee36fd8362fe152e8ebdcabd9a03f34f19e0dcac6dbbdd` | Artifact: task4.json | High (100%) |
| **SHA-256 Hash** | `805c198e8d96afbb19d4ccd4ffe54c4fd13ce900529983e77261d22db9a9c56c` | Artifact: task5.json | High (100%) |
| **SHA-256 Hash** | `00d0182900e3237aac26be5c7a233e84dd47159eec031f3b94b29bdc2dcba2f1` | Artifact: task_output.json | High (100%) |
| **SHA-256 Hash** | `8fd453422015aa502b7e53348a4266f9778cc27ed363ac3d3abcfc6f11d4c712` | Artifact: task_test.py | High (100%) |
| **SHA-256 Hash** | `4ac034bd44b89ea0f44e9b431485fa96ce0a7a377e63c8d78efba6b10842ad19` | Artifact: tasks3.json | High (100%) |
| **SHA-256 Hash** | `bd0ecb4950afcc8d151e4f6531c32541a0e16de2d8145d7fb06d3710bc05807c` | Artifact: tasks4.json | High (100%) |
| **SHA-256 Hash** | `00d0182900e3237aac26be5c7a233e84dd47159eec031f3b94b29bdc2dcba2f1` | Artifact: tasks_out.json | High (100%) |
| **SHA-256 Hash** | `51fac2b24786564216cb437f8b43baad369126293cd8658b658b6b89c5efc76b` | Artifact: tasks_out2.json | High (100%) |
| **SHA-256 Hash** | `17bbd21d40f14b0b9086f0a9e05bd2ac63312eae66f9fc2ad4c3f4fbf8aff3de` | Artifact: test2.py | High (100%) |
| **SHA-256 Hash** | `7e0fb603a3b57d535609b47e26554035bb9f2c25fcc19f73a73a38dcc24f7d22` | Artifact: test_all.py | High (100%) |
| **SHA-256 Hash** | `28c8987066fcf72149c330e43a5d5bfbacea56fa9e18bf4cb09a9fb96433400f` | Artifact: test_dl_ul.py | High (100%) |
| **SHA-256 Hash** | `7ca8aad6b56afdb86af48702603858581d2ad51685ca63fe58a0513cfeb14ec1` | Artifact: test_gql.py | High (100%) |
| **SHA-256 Hash** | `415db8245a63fa201d074bad16532644600fdad38682e63d4a7eaacb6b11b736` | Artifact: test_linux_http | High (100%) |
| **SHA-256 Hash** | `13853da8d970ef8844e235a6c671b0893505bb936851a310cec80deb2a1304fa` | Artifact: test_makefile.mk | High (100%) |
| **SHA-256 Hash** | `8def9e7f020f0a40390fb021ba6ae761e80cbaf486103e0aecaa0e05a66a5600` | Artifact: test_opsec.exe | High (100%) |
| **SHA-256 Hash** | `405fffcb3240d6eaefc6a15f735339655d50efd23bafd9ff8f3fae5273f9254a` | Artifact: test_persist_vault.py | High (100%) |
| **SHA-256 Hash** | `733ff7ef3bdec8ceff36a9a5ac5706b1127c6aacf8bf17e3b329418a485fccea` | Artifact: test_tasks.py | High (100%) |
| **SHA-256 Hash** | `74adeca3e228201320ccdd0911e5b7acd8e7e538a4354a404a82612afb90c2cb` | Artifact: test_vault.py | High (100%) |
| **SHA-256 Hash** | `811b68fb134ff76844d6cac62ea829d6a04662ab6971798ad4c54b98e6c02ed7` | Artifact: test_vault_linux.py | High (100%) |
| **SHA-256 Hash** | `13c9d533f9e71c640630ad8e7f8ba25cc4c335876cd9f763d1def853ed954d61` | Artifact: test_win_github.b64 | High (100%) |
| **SHA-256 Hash** | `422a4d1a99c08cf7984a9ed463fd8fc583124ae95f6116a3a289e567a8bb893d` | Artifact: test_win_github.exe | High (100%) |
| **SHA-256 Hash** | `c2f873a4055d0ecc879c1e1ce5ee3448ecae2f84165db42bc3b0b3cbddc063c8` | Artifact: test_win_github_v2.exe | High (100%) |
| **SHA-256 Hash** | `d299f27ffaf4a16ed1c019bdfe90c1851ce8b27cdfbd498f611c25cfeaf15d4b` | Artifact: test_win_github_v3.exe | High (100%) |
| **SHA-256 Hash** | `022a0c2bbebe581a8c3aca79d0d8fbe8222397917978d3a09e8c4008fd6ed8a3` | Artifact: token.c | High (100%) |
| **SHA-256 Hash** | `8a70a8abe5a2b24c5a6aa6c0473cf65aac0ebdebf0fc22606b278eed02db724d` | Artifact: trigger_build.py | High (100%) |
| **SHA-256 Hash** | `ff83c3efeb8613fc3a73f4160dd287a2627873a2a1bd5e69ec6c0756b5849808` | Artifact: TRIXX.sys | High (100%) |
| **SHA-256 Hash** | `5089b394eefae67c7022a293504a2099358f5f255532496d279ee2442c42fe32` | Artifact: Updater.b64 | High (100%) |
| **SHA-256 Hash** | `b2dbdd8613f894b659b3c608412d2d83d0c9c45c69b62f6c9383782daf0c492b` | Artifact: Updater.exe | High (100%) |
| **SHA-256 Hash** | `fd1762bd85518ae7ba3029bbf902463a9fb4c828b1582d237b768d8de2eafd3d` | Artifact: Updater2.exe | High (100%) |
| **SHA-256 Hash** | `02d0430ce1d580af570e19bd168746b7f83a0825b61403d1cb1c9925ac75d8de` | Artifact: Updater3.exe | High (100%) |
| **SHA-256 Hash** | `ff4ce9190d5db38f71bec632341ee2791c5cc710bdc8293fac8899a86cd25da0` | Artifact: Updater4.exe | High (100%) |
| **SHA-256 Hash** | `980eec465e27607a3e72be6d6a2a19e352efdcea5a442d2973553366f781f2f2` | Artifact: Updater5.exe | High (100%) |
| **SHA-256 Hash** | `92803320f1b84f89a24565f6fb082f2e5f7826f0f56e28cd6fa129e68222530f` | Artifact: Updater6.exe | High (100%) |
| **SHA-256 Hash** | `9635e5f657195bdc90bb255a15d09d7e15d717c28752edc9b8f96c6fa72f9b70` | Artifact: upload.py | High (100%) |
| **SHA-256 Hash** | `e270f5a63ca5cb7f0f1db95b45ef2cadd59545e2234cbcd26b24cc23179e9334` | Artifact: upload_builder.py | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: upload_reg.json | High (100%) |
| **SHA-256 Hash** | `99eb12f2ab3c4866a353e098ffa3cb7a967e617c49b98480394ec5d8ea92b094` | Artifact: upload_resp.json | High (100%) |
| **SHA-256 Hash** | `dc00de6765c3842581f5fd5f45c5b65b225e027c19d0c220fb74e0ed382cc85e` | Artifact: vps.py | High (100%) |
| **SHA-256 Hash** | `07b962f5b3d37ddeddf2e386b9b263ac98d0fd657b44563602fa418b7cb3ce46` | Artifact: vps_find.py | High (100%) |
| **SHA-256 Hash** | `a48ed893bf923e03fb705ec7f62913f88e59c6317d7ca50f7586c7214b6405e0` | Artifact: vps_ops.py | High (100%) |
| **SHA-256 Hash** | `b5b3a843dbd0bdd34753252c71eabb691bf00ec083d11f8947817d97bfb82fec` | Artifact: vps_run.py | High (100%) |
| **SHA-256 Hash** | `1043fd1c5eebeab5170dadb29d5df5c9e4577b3d50fbf1fe8092971dd508b7ce` | Artifact: WindowsTelemetry.exe | High (100%) |
| **SHA-256 Hash** | `58de8eaefc53b62ed5d18c8864fca68cee7a4ff74e883ec86ea3888bde78da77` | Artifact: wmi_exec.py | High (100%) |
| **SHA-256 Hash** | `c0b10047935b3cae6b7751e0b3dda0e4eb4341d9c869e5903851e2108a573b4b` | Artifact: WT_dbg.exe | High (100%) |
| **SHA-256 Hash** | `57ef5dd3e9a7b4ac6f8119a38f003d0ab659749280a18f5e3da680d480b3cb81` | Artifact: WT_diag.exe | High (100%) |
| **SHA-256 Hash** | `03592dcd90ddb23ede679374445baa5ea4044060137f3e523f7af11a23219653` | Artifact: WT_inject.exe | High (100%) |

### 3. MITRE ATT&CK Mapping
* **T1071.001 - Application Layer Protocol: Web Protocols**
* **T1218.005 - System Binary Proxy Execution: Mshta**
* **T1566.001 - Phishing: Spearphishing Attachment**
* **T1204.002 - User Execution: Malicious File**
* **T1055 - Process Injection**
* **T1140 - Deobfuscate/Decode Files or Information**
* **T1102.001 - Web Service: Dead Drop Resolver**
* **T1068 - Exploitation for Privilege Escalation**
* **T1562.001 - Disable or Modify Tools**
* **T1190 - Exploit Public-Facing Application**
* **T1055.012 - Process Hollowing**

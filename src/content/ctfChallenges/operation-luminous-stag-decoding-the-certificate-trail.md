---
collection: "discord-challenges"
title: "Operation Luminous Stag: Decoding the Certificate Trail"
difficulty: "medium"
prompt: "A surge of Lumma Stealer infections has hit cryptocurrency communities. The malware’s latest variant, LummaC2, exfiltrates wallet seeds and browser cookies to a hidden command-and-control (C2) server. Your team intercepts a sample revealing that the C2 domain:\n\nReferences two concepts: one tied to the malware’s Latin-derived name (“light”) and another to a forest creature symbolizing stealth.\n\nWas registered via Cloudflare (AS13335) and first active on January 22, 2025.\n\nUses a TLS certificate logged 24 hours pre-attack across multiple CT providers, with a Sectigo (formerly Comodo) entry showing a 1-second timestamp anomaly.\n\nThe attackers likely rotated certificates rapidly to evade detection. Your mission: Find the critical Sectigo CT log entry tied to this domain to uncover linked infrastructure."
passwordFormat: "0xL4ugh{Log Entry}"
assets: []
hint: "use crt.sh"
answerHashes:
  - "14ac0745e3cd535aa53edeadb393552061b2f36d4568afc67b4431a46fc3e41f"
acceptedAliases:
  - "301446771"
order: 1
slug: "operation-luminous-stag-decoding-the-certificate-trail"
---

Add challenge notes here.

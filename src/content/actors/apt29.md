---
name: "APT29"
aliases:
  - Cozy Bear
  - The Dukes
  - Midnight Blizzard
status: tracking
origin: Russia
motivation: "State-aligned espionage focused on long-duration access, credential abuse, and collection against high-value networks."
targets:
  - Government
  - Foreign policy
  - Cloud environments
  - Technology supply chains
firstSeen: "2008"
lastSeen: "2024+"
tools:
  - Cloud credential theft
  - Web protocols for command and control
  - WMI event subscription persistence
  - PowerShell-based post-compromise activity
ttps:
  - Spearphishing and credential acquisition
  - Long-term cloud and identity access
  - Living-off-the-land collection and movement
  - Multi-stage intrusion chains with quiet persistence
tags:
  - espionage
  - cloud
  - identity
timeline:
  - date: "2020"
    title: "SolarWinds-related operations drive global attention"
    summary: "The group became central to public discussion of supply-chain compromise and deep post-compromise tradecraft."
  - date: "2021"
    title: "Cloud-focused post-compromise behavior becomes a priority for defenders"
    summary: "Public advisories increasingly emphasized identity, federation, and cloud telemetry instead of only on-premise artifacts."
  - date: "2024"
    title: "Official advisories continue to track SVR cloud access tradecraft"
    summary: "Defender guidance remained centered on initial cloud access, persistence, and stealthy follow-on collection."
references:
  - title: "MITRE ATT&CK: APT29"
    url: "https://attack.mitre.org/groups/G0016/"
    publisher: "MITRE ATT&CK"
  - title: "SVR Cyber Actors Adapt Tactics for Initial Cloud Access"
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a"
    publisher: "CISA"
relatedPosts:
  - how-i-structure-actor-dossiers
featured: true
---

APT29 is a useful example of why a dossier should separate stable characteristics from campaign-specific
detail. The broad profile is persistent: a Russian espionage operator associated with long-duration access,
quiet collection, and continued adaptation around cloud identity and post-compromise visibility gaps.

That stable layer matters because it keeps the page useful even when individual campaigns change. The
campaign timeline can expand as new reporting lands, but the top of the dossier should still answer the
faster questions first: who is being tracked, what type of operator this is, where the pressure usually
appears, and what kind of tradecraft defenders should expect to revisit.

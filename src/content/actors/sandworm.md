---
name: "Sandworm Team"
aliases:
  - Seashell Blizzard
  - APT44
  - Voodoo Bear
  - Telebots
status: active
origin: Russia
motivation: "Disruption, strategic coercion, and intelligence collection with a history of destructive and ICS-relevant operations."
targets:
  - Critical infrastructure
  - Energy and ICS environments
  - Government networks
  - Telecommunications and edge devices
firstSeen: "2014"
lastSeen: "2024+"
tools:
  - BlackEnergy
  - Industroyer
  - CaddyWiper
  - Prestige
  - Cyclops Blink
ttps:
  - Spearphishing and staged malware delivery
  - PowerShell, scripts, and Windows command execution
  - Group Policy-based deployment and lateral movement
  - Destructive operations against industrial and enterprise environments
tags:
  - disruption
  - critical infrastructure
  - ics
timeline:
  - date: "2015"
    title: "Ukraine power attack establishes the group's public profile"
    summary: "Operations against Ukraine's power sector made the group's blend of intrusion, disruption, and ICS impact globally recognizable."
  - date: "2016"
    title: "Follow-on electric power attack deepens the ICS association"
    summary: "Public reporting tied the group to another major Ukraine electric power incident and additional ICS-relevant tradecraft."
  - date: "2022"
    title: "New disruptive tooling appears in Ukraine-related activity"
    summary: "Reporting highlighted continued capability to combine enterprise compromise with destructive or service-impacting objectives."
references:
  - title: "MITRE ATT&CK: Sandworm Team"
    url: "https://attack.mitre.org/groups/G0034/"
    publisher: "MITRE ATT&CK"
  - title: "New Sandworm Malware Cyclops Blink Replaces VPNFilter"
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-054a"
    publisher: "CISA"
relatedPosts:
  - how-i-structure-actor-dossiers
featured: true
---

Sandworm remains a strong template for disruption-oriented tracking because the actor profile spans more than
one malware family and more than one campaign style. The durable part of the dossier is the pattern: a group
repeatedly associated with critical infrastructure targeting, destructive outcomes, and operational pressure
that extends beyond straightforward data theft.

A page like this should stay centered on operational implications. For Sandworm, that means keeping the
connection between tooling, scripting, destructive deployment, and infrastructure-sector targeting visible
without forcing every historical campaign into the same section.

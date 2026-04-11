---
collection: osint-1
title: "Rafah"
difficulty: hard
prompt: "Track a Russian cybercriminal who ran a Telegram channel selling personal data and access to hacked devices while extorting victims. Find the MD5 of the decryption script and the creation timestamp of the Telegram channel."
passwordFormat: "MD5_DD-MM-YYYY_HH:MM"
assets:
  - label: "Prompt text"
    url: "/downloads/ctf/osint-1/rafah/prompt.txt"
    kind: text
  - label: "Flag archive"
    url: "/downloads/ctf/osint-1/rafah/flag.rar"
    kind: archive
hint: "You need both the script digest and the timestamp. Treat them as a combined answer."
answerHashes:
  - "822a7c2bfc39c3115c8af33dc10916f36b960d11b891d075198e496128f6d05b"
acceptedAliases: []
order: 9
---

Validate the combined value only after both parts are recovered.

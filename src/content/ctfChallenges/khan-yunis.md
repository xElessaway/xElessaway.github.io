---
collection: osint-1
title: "Khan Yunis"
difficulty: easy
prompt: "I was on a trip to Palestine and ended up in a hospital after a fall. The people were kind, and I still have an image of the hospital. Can you identify the hospital name in English?"
passwordFormat: "Name_Of_The_Hospital_In_English"
assets:
  - label: "Prompt text"
    url: "/downloads/ctf/osint-1/khan-yunis/prompt.txt"
    kind: text
  - label: "Challenge image"
    url: "/media/ctf/osint-1/khan-yunis/image.png"
    kind: image
  - label: "Flag archive"
    url: "/downloads/ctf/osint-1/khan-yunis/flag.rar"
    kind: archive
image: "/media/ctf/osint-1/khan-yunis/image.png"
hint: "Use the photo to identify the hospital and provide the English rendering of the name."
answerHashes:
  - "b58b8e3de705f3ed1559be3bb6cffa76605823a7b21acd9dee8f2374a8e20ea4"
acceptedAliases: []
order: 3
---

The answer validator accepts the normalized hospital name while keeping the original format expectations visible.

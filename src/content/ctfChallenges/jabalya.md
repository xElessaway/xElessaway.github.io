---
collection: osint-1
title: "Jabalya"
difficulty: easy
prompt: "While scrolling on my accounts I found this beautiful image, but the browser crashed before I entered the author's profile. I noticed the date was Dec 2014. Can you find the ID of the post?"
passwordFormat: "Social Media Post/Tweet ID"
assets:
  - label: "Prompt text"
    url: "/downloads/ctf/osint-1/jabalya/prompt.txt"
    kind: text
  - label: "Challenge image"
    url: "/media/ctf/osint-1/jabalya/image.jpg"
    kind: image
  - label: "Flag archive"
    url: "/downloads/ctf/osint-1/jabalya/flag.rar"
    kind: archive
image: "/media/ctf/osint-1/jabalya/image.jpg"
hint: "Work from the image context and the December 2014 timestamp."
answerHashes:
  - "4ebdce3026c8cc8ad262892c5da81e644d32c2bf7584b4177785f828be20890c"
acceptedAliases: []
order: 1
---

Recover the source post identifier and use it directly as the archive password.

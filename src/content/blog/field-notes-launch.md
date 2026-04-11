---
title: "From Single Page to Research Journal"
description: "Why the site moved from a one-page challenge gallery to a publication-ready cyber research desk."
publishedAt: 2026-04-03
tags:
  - site design
  - editorial workflow
  - astro
featured: true
draft: false
---

The old build did one job: list challenges. That worked when the site was mostly a container for a single
collection, but it forced everything else into awkward shapes. Threat intelligence had nowhere to live.
Writing had no dedicated reading space. Challenge browsing depended on one modal opening another layer of
content.

The redesign fixes that by changing the information architecture first, not by repainting the same layout.
The site now has separate routes for journal entries, threat intelligence dossiers, collection indexes, and
challenge pages. That keeps every section linkable, maintainable, and easier to expand.

## What changed

The new layout is editorial on purpose. I want the site to read like a cyber research desk rather than a
generic portfolio or a dashboard clone. The visual system uses paper-toned surfaces, evidence-card spacing,
and a typography stack that makes long-form reading viable.

## Why Astro

Astro is a good fit because the site should stay static and fast while still behaving like a real content
system. Content collections give me enough structure for repeatable metadata without dragging the project
into unnecessary runtime complexity.

## What this enables next

The important result is not the framework. It is the ability to keep adding new blog posts, actor dossiers,
and challenge collections without reworking the site structure every time.

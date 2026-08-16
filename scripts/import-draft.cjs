const fs = require('fs');

const exportFile = 'medium-export-442307ab7daabf134c897419377a1059c479dec1d45cc44c61a70030682a3498/posts/draft_Exposed-QuickDAV-Malware-Distribution-Repository-and-Remcos-RAT-Infrastructure-5d257f3e468d.html';
const html = fs.readFileSync(exportFile, 'utf8');

const titleMatch = html.match(/<h1 class="p-name">([\s\S]*?)<\/h1>/);
const title = titleMatch ? titleMatch[1].trim() : 'Exposed: QuickDAV Malware Distribution Repository and Remcos RAT Infrastructure';

const summaryMatch = html.match(/<section data-field="subtitle" class="p-summary">([\s\S]*?)<\/section>/);
const subtitle = summaryMatch ? summaryMatch[1].trim().replace(/\s+/g, ' ') : 'Target acquired: http://151.241.154.105:8888/ - Passive acquisition review and offline static malware analysis of exposed QuickDAV malware repository and Remcos RAT infrastructure.';

const bodyMatch = html.match(/<section data-field="body" class="e-content">([\s\S]*?)<\/section>\s*<\/section>\s*<footer>/);
let body = bodyMatch ? bodyMatch[1] : '';

// Remove Medium wrapping divs if desired or keep clean HTML
const frontmatter = `---
title: "Exposed: QuickDAV Malware Distribution Repository and Remcos RAT Infrastructure"
description: "Passive acquisition review + offline static analysis of an exposed QuickDAV malware repository and Remcos RAT delivery infrastructure."
publishedAt: 2026-08-13
archiveSection: reports
tags:
  - "malware-analysis"
  - "dfir"
  - "threat-intelligence"
  - "remcos-rat"
  - "quickdav"
  - "powershell"
cover: "https://cdn-images-1.medium.com/max/800/1*Eus_4JH2dFZjksImsQf2LQ.png"
featured: false
draft: true
sourceLabel: "Medium (Draft)"
sourceUrl: "https://medium.com/@xelessaway"
---

`;

const fullDoc = frontmatter + body;
fs.writeFileSync('src/content/blog/exposed-quickdav-malware-distribution-repository-and-remcos-rat-infrastructure.md', fullDoc, 'utf8');
console.log('Successfully created draft post! File size:', fullDoc.length);

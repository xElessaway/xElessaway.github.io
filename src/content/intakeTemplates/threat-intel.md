---
id: threat-intel
label: "Threat Intel"
contentType: actors
targetPathPattern: "src/content/actors/{{slug}}.md"
previewPathPattern: "/threat-intelligence/{{slug}}/"
fieldGroups:
  - label: "Core"
    description: "Identity and headline metadata for the dossier."
    fields:
      - name
      - slug
      - status
      - origin
      - motivation
      - firstSeen
      - lastSeen
  - label: "Collections"
    description: "Lists used across the dossier layout."
    fields:
      - aliases
      - targets
      - tools
      - ttps
      - tags
      - relatedPosts
  - label: "Structured Data"
    description: "Timeline and references rendered as cards in the dossier."
    fields:
      - timeline
      - references
      - featured
  - label: "Executive Summary"
    description: "Markdown summary shown at the top of the dossier."
    fields:
      - executiveSummary
defaultValues:
  status: tracking
  aliases: []
  targets: []
  tools: []
  ttps: []
  tags: []
  timeline: []
  references: []
  relatedPosts: []
  featured: false
  executiveSummary: |
    Add the executive summary here.
frontmatterOrder:
  - name
  - aliases
  - status
  - origin
  - motivation
  - targets
  - firstSeen
  - lastSeen
  - tools
  - ttps
  - tags
  - timeline
  - references
  - relatedPosts
  - featured
fields:
  - name: name
    label: "Actor Name"
    type: text
    required: true
    placeholder: "Threat actor or cluster name"
  - name: slug
    label: "Slug"
    type: text
    required: true
    deriveFrom: name
    placeholder: "actor-slug"
  - name: status
    label: "Status"
    type: select
    required: true
    options:
      - label: "Active"
        value: active
      - label: "Tracking"
        value: tracking
      - label: "Disrupted"
        value: disrupted
      - label: "Historic"
        value: historic
  - name: origin
    label: "Origin"
    type: text
    required: true
    placeholder: "Origin or operating region"
  - name: motivation
    label: "Motivation"
    type: textarea
    required: true
    placeholder: "Short summary for the hero panel"
  - name: firstSeen
    label: "First Seen"
    type: text
    required: true
    placeholder: "2024 or 2024-05"
  - name: lastSeen
    label: "Last Seen"
    type: text
    required: true
    placeholder: "2026 or Present"
  - name: aliases
    label: "Aliases"
    type: stringList
    placeholder: "One alias per line"
  - name: targets
    label: "Targets"
    type: stringList
    placeholder: "One target per line"
  - name: tools
    label: "Tooling / Malware"
    type: stringList
    placeholder: "One tool per line"
  - name: ttps
    label: "Observed TTP Themes"
    type: stringList
    placeholder: "One TTP theme per line"
  - name: tags
    label: "Tags"
    type: stringList
    placeholder: "One tag per line"
  - name: relatedPosts
    label: "Related Report Slugs"
    type: stringList
    placeholder: "One blog slug per line"
  - name: timeline
    label: "Timeline"
    type: objectList
    itemLabel: "Timeline entry"
    addLabel: "Add timeline entry"
    fields:
      - name: date
        label: "Date"
        type: text
        required: true
        placeholder: "2025-04"
      - name: title
        label: "Title"
        type: text
        required: true
        placeholder: "Event title"
      - name: summary
        label: "Summary"
        type: textarea
        required: true
        placeholder: "Event summary"
  - name: references
    label: "References"
    type: objectList
    itemLabel: "Reference"
    addLabel: "Add reference"
    fields:
      - name: title
        label: "Title"
        type: text
        required: true
        placeholder: "Reference title"
      - name: url
        label: "URL"
        type: text
        required: true
        placeholder: "https://..."
      - name: publisher
        label: "Publisher"
        type: text
        placeholder: "Publisher"
  - name: featured
    label: "Featured"
    type: checkbox
  - name: executiveSummary
    label: "Executive Summary"
    type: markdownBody
    required: true
    rows: 18
---
{{executiveSummary}}

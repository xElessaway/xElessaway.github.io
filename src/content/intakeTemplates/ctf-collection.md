---
id: ctf-collection
label: "CTF Collection"
contentType: ctfCollections
targetPathPattern: "src/content/ctfCollections/{{slug}}.md"
previewPathPattern: "/ctf/{{slug}}/"
fieldGroups:
  - label: "Core"
    description: "Primary collection metadata."
    fields:
      - title
      - slug
      - summary
      - status
      - year
      - featured
  - label: "Notes"
    description: "Optional markdown notes stored in the file body."
    fields:
      - notes
defaultValues:
  status: active
  featured: false
  notes: |
    Add collection notes here.
frontmatterOrder:
  - title
  - summary
  - status
  - year
  - featured
fields:
  - name: title
    label: "Collection Title"
    type: text
    required: true
    placeholder: "Collection title"
  - name: slug
    label: "Slug"
    type: text
    required: true
    deriveFrom: title
    placeholder: "collection-slug"
  - name: summary
    label: "Summary"
    type: textarea
    required: true
    placeholder: "One-paragraph collection summary"
  - name: status
    label: "Status"
    type: select
    required: true
    options:
      - label: "Active"
        value: active
      - label: "Retired"
        value: retired
      - label: "Archived"
        value: archived
  - name: year
    label: "Year"
    type: text
    required: true
    placeholder: "2026"
  - name: featured
    label: "Featured"
    type: checkbox
  - name: notes
    label: "Markdown Notes"
    type: markdownBody
    rows: 10
---
{{notes}}

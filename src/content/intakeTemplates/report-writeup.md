---
id: report-writeup
label: "Report / Writeup"
contentType: blog
targetPathPattern: "src/content/blog/{{slug}}.md"
previewPathPattern: "/blog/{{slug}}/"
fieldGroups:
  - label: "Core"
    description: "Required archive fields for a new report or writeup."
    fields:
      - title
      - slug
      - description
      - publishedAt
      - archiveSection
  - label: "Metadata"
    description: "Optional tags and display controls."
    fields:
      - tags
      - cover
      - featured
      - draft
  - label: "Body"
    description: "Markdown content for the report body."
    fields:
      - body
defaultValues:
  archiveSection: reports
  tags: []
  featured: false
  draft: false
  body: |
    ## Summary

    Add the report body here.
frontmatterOrder:
  - title
  - description
  - publishedAt
  - archiveSection
  - tags
  - cover
  - featured
  - draft
fields:
  - name: title
    label: "Title"
    type: text
    required: true
    placeholder: "Entry title"
  - name: slug
    label: "Slug"
    type: text
    required: true
    deriveFrom: title
    placeholder: "entry-slug"
  - name: description
    label: "Description"
    type: textarea
    required: true
    placeholder: "One-sentence summary"
  - name: publishedAt
    label: "Published Date"
    type: date
    required: true
  - name: archiveSection
    label: "Archive Lane"
    type: select
    required: true
    options:
      - label: "Reports"
        value: reports
      - label: "Writeups"
        value: writeups
  - name: tags
    label: "Tags"
    type: stringList
    placeholder: "One tag per line"
  - name: cover
    label: "Cover Image URL"
    type: text
    placeholder: "https://..."
  - name: featured
    label: "Featured"
    type: checkbox
  - name: draft
    label: "Draft"
    type: checkbox
  - name: body
    label: "Markdown Body"
    type: markdownBody
    required: true
    rows: 18
---
{{body}}

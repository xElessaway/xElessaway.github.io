---
id: ctf-challenge
label: "CTF Challenge"
contentType: ctfChallenges
targetPathPattern: "src/content/ctfChallenges/{{slug}}.md"
previewPathPattern: "/ctf/{{collection}}/{{slug}}/"
fieldGroups:
  - label: "Core"
    description: "Route and challenge metadata."
    fields:
      - collection
      - title
      - slug
      - difficulty
      - order
      - prompt
      - passwordFormat
  - label: "Assets and Validation"
    description: "Challenge assets and answer hashing."
    fields:
      - assets
      - image
      - hint
      - rawAnswers
      - acceptedAliases
  - label: "Notes"
    description: "Optional markdown notes stored in the file body."
    fields:
      - notes
defaultValues:
  difficulty: medium
  assets:
    - label: "Flag Archive"
      url: ""
      kind: archive
  acceptedAliases: []
  rawAnswers: []
  notes: |
    Add challenge notes here.
frontmatterOrder:
  - collection
  - title
  - difficulty
  - prompt
  - passwordFormat
  - assets
  - image
  - hint
  - answerHashes
  - acceptedAliases
  - order
fields:
  - name: collection
    label: "Collection Slug"
    type: text
    required: true
    placeholder: "osint-1"
  - name: title
    label: "Challenge Title"
    type: text
    required: true
    placeholder: "Challenge title"
  - name: slug
    label: "Slug"
    type: text
    required: true
    deriveFrom: title
    placeholder: "challenge-slug"
  - name: difficulty
    label: "Difficulty"
    type: select
    required: true
    options:
      - label: "Easy"
        value: easy
      - label: "Medium"
        value: medium
      - label: "Hard"
        value: hard
  - name: order
    label: "Display Order"
    type: number
    required: true
    placeholder: "1"
  - name: prompt
    label: "Prompt"
    type: textarea
    required: true
    placeholder: "Challenge prompt"
  - name: passwordFormat
    label: "Password Format"
    type: text
    required: true
    placeholder: "Social Media Post/Tweet ID"
  - name: assets
    label: "Assets"
    type: objectList
    itemLabel: "Asset"
    addLabel: "Add asset"
    fields:
      - name: label
        label: "Label"
        type: text
        required: true
        placeholder: "Flag Archive"
      - name: url
        label: "URL / Path"
        type: text
        required: true
        placeholder: "/downloads/ctf/..."
      - name: kind
        label: "Kind"
        type: select
        required: true
        options:
          - label: "Archive"
            value: archive
          - label: "Image"
            value: image
          - label: "Text"
            value: text
          - label: "External"
            value: external
  - name: image
    label: "Challenge Image"
    type: text
    placeholder: "/media/ctf/..."
  - name: hint
    label: "Hint"
    type: textarea
    placeholder: "Optional hint"
  - name: rawAnswers
    label: "Raw Answers"
    type: specialRawAnswers
    required: true
    outputName: answerHashes
    placeholder: "One accepted answer per line"
  - name: acceptedAliases
    label: "Accepted Aliases"
    type: stringList
    placeholder: "One alias per line"
  - name: notes
    label: "Markdown Notes"
    type: markdownBody
    rows: 14
---
{{notes}}

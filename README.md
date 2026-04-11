# Ahmed Elessaway (xElessaway)

Threat-focused cyber research site built with Astro for GitHub Pages.

## Sections

- `Home`: landing page for featured investigations, labs, and profile highlights.
- `Blog`: Medium-synced writeups plus local research briefs.
- `Threat Intelligence`: reusable actor dossier pages.
- `CTF`: collection pages plus dedicated challenge routes with browser-side validation.
- `About`: identity, focus, and public contact links.

## Development

```bash
npm install
npm run sync:medium
npm run dev
```

## Build

```bash
npm run sync:medium
npm run build
```

`npm run build` compiles Astro and syncs the generated static site into the repo root so GitHub Pages can serve it directly from `main`.

## GitHub Pages

- Runtime source: built files committed at the repository root.
- Authoring source: Astro app in `src/`, `public/`, and `scripts/`.
- Safety check workflow: `.github/workflows/ci.yml`.

# Neuwerk UI

This package contains the embedded Neuwerk management UI.

It is the web frontend served by the control-plane HTTPS listener and covers operator workflows such
as:

- policy management
- audit and threat findings
- service accounts and authentication flows
- runtime and integration settings

For product and operator documentation, start at the repository root `README.md` and the structured
docs under `www/src/content/docs/`.

## Local development

For local UI work, run:

```bash
npm run dev
```

The Vite dev server automatically starts with an embedded mock API, so no Neuwerk backend service is
required while developing the UI locally.

What to expect in dev:

- create/edit/delete flows are handled in-memory
- in-memory changes reset when the dev server restarts
- threat and wiretap views use synthetic development data (including mock wiretap streaming behavior)

# directus-extension-pii-protect (d9 PII Protect)

A d9 hook that does **one thing**: mask PII on the way out of the API, per role.

For a role flagged **`pii_mask`**, every value it reads via the API — items, GraphQL, aggregates, field
aliases, nested relations, file metadata — is scanned and each detected PII value is replaced by a
consistent, one-way token `[TYPE:hash]`. Binary files served via `/assets` are redacted (text hashed,
image/PDF masked); bulk export is refused. Anyone whose role isn't flagged reads the original (the database
stays in clear). This **complements RBAC — it does not replace it**; it keeps PII out of an AI agent's
prompts and traces. Detection runs in a separate **sidecar engine** (French-first).

## Installation

1. Drop this folder into the `extensions/` directory of the d9 instance (non-sandboxed hook — it needs
   `accountability` and the response object).
2. Start the **sidecar engine** and point the extension at it via `PII_PROTECT_ENGINE_URL`.

On first boot the extension **creates its own config field** on `directus_roles` (idempotent): a single
**"Mask PII in this role's API responses"** toggle appears on each role page. Editing it requires role-edit
rights, so a regular user can't change what is masked. Until a role opts in, the extension does nothing.

## Configuration (environment variables)

| Variable | Role | Default |
|---|---|---|
| `PII_PROTECT_ENGINE_URL` | URL of the sidecar engine (within the environment's network). | `http://host.docker.internal:8077` |
| `PII_PROTECT_ENGINE_TOKEN` | Optional shared secret sent to the engine (`X-Engine-Token`); set the same value on the engine. | *(empty = no auth)* |

Choosing **which PII types** to mask (`PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`) happens on the **engine
side**.

**No custom logs**: d9's native activity log already records accesses.

## How it works (one interceptor)

The hook wraps `res.json` once. On a data path, for a masked role, it collects the response's unique strings,
sends them to the engine's `/anonymize-batch` in a single round trip, and substitutes the returned tokens
back into the payload. Masking **by value** (not by named field) is what makes coverage uniform. If the engine
is unreachable it returns `503` — never the clear value (fail-closed). Masking is **one-way**: there is no
write-path and no decryption.

## Development

```bash
npm install
npm run build      # esbuild: transpile src/index.ts → dist/index.js (readable, non-minified, un-bundled)
npm run dev        # same, in watch mode
```

Single source: `src/index.ts`. Versioned output: `dist/index.js` (the artifact loaded by d9 — a plain 1:1
transpile, auditable). The hook has **no runtime dependency** (no imports — only Node/d9 globals).

## License

MIT © La Webcapsule

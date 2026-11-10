/**
 * directus-extension-pii-protect — hoop-style PII masking for d9, driven by the d9 ROLE.
 *
 * Model (output masking, NOT a crypto boundary — it complements RBAC, it does not replace it):
 *   A role is "masked" via ONE opt-in boolean on directus_roles (pii_mask). For a masked role, EVERY value
 *   that leaves the d9 API is scanned and its PII is replaced by a consistent, one-way token ([TYPE:hash]).
 *   Because we mask the RESPONSE BYTES by value (not named fields), it covers every read path uniformly:
 *   /items, GraphQL, aggregates, field aliases, nested relations, and file metadata — no route-by-route holes.
 *   Binary files served via /assets are redacted (text hashed, image/PDF masked, unknown type refused).
 *
 *   The DB stays in clear → authorized roles (admins/humans) read normally; only masked roles get scrubbed
 *   output. Masking is NON-reversible: no decryption endpoint, no write-path rehydrate → no decryption oracle,
 *   no risk of corrupting data on write. The intended use is keeping PII out of an AI agent's prompts/traces.
 *
 * Known, accepted limitation (agent assumed non-hostile): the DB still filters/sorts on the clear value, so a
 * deliberately adversarial role could use filter/search as an oracle. Defending that needs RBAC or at-rest.
 *
 * Environment:
 *   PII_PROTECT_ENGINE_URL    engine sidecar URL (default http://host.docker.internal:8077)
 *   PII_PROTECT_ENGINE_TOKEN  optional shared secret sent to the engine (X-Engine-Token)
 */

const ENGINE = process.env.PII_PROTECT_ENGINE_URL || 'http://host.docker.internal:8077';
const ENGINE_TOKEN = process.env.PII_PROTECT_ENGINE_TOKEN;
// Identifiers are never PII and clients (incl. the d9 app) need them to navigate — never mask a UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// File extension → engine redaction endpoint. Absent = unsupported type → fail-closed refusal.
const FILE_ROUTE: Record<string, string> = {
  txt: '/anonymize-doc', md: '/anonymize-doc', csv: '/anonymize-doc', json: '/anonymize-doc', docx: '/anonymize-doc',
  png: '/redact-image', jpg: '/redact-image', jpeg: '/redact-image', gif: '/redact-image',
  bmp: '/redact-image', tiff: '/redact-image', tif: '/redact-image', webp: '/redact-image',
  pdf: '/redact-pdf',
};
const ext = (name: string) => name.toLowerCase().split('.').pop() || '';

// Engine calls. Throw on error → the caller fails CLOSED (never serves clear on an engine failure).
async function post(path: string, payload: object): Promise<any> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (ENGINE_TOKEN) headers['x-engine-token'] = ENGINE_TOKEN;
  const r = await fetch(ENGINE + path, { method: 'POST', headers, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error('engine HTTP ' + r.status);
  return r.json();
}
const callFile = async (path: string, filename: string, buf: Buffer): Promise<Buffer> =>
  Buffer.from((await post(path, { filename, content_b64: buf.toString('base64') })).content_b64, 'base64');

async function bufferStream(stream: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}

// Per-role "is this role masked?", cached briefly. fail-CLOSED: a transient config-read error never opens up.
type Cfg = { masked: boolean; at: number };
const roleCache = new Map<string, Cfg>();
let fieldsReady = false; // set once the config field exists → distinguishes "not installed" from "read error"

export default ({ init }: any, { logger, database, services, getSchema }: any) => {
  async function roleMasked(roleId?: string): Promise<boolean> {
    if (!fieldsReady || !roleId) return false; // config not installed yet, or public request → inert
    const hit = roleCache.get(roleId);
    if (hit && Date.now() - hit.at < 3_000) return hit.masked;
    try {
      const row = await database('directus_roles').select('pii_mask').where({ id: roleId }).first();
      const masked = !!row?.pii_mask;
      roleCache.set(roleId, { masked, at: Date.now() });
      return masked;
    } catch (e: any) {
      if (hit) return hit.masked;                 // keep last known decision rather than fall open
      logger.warn('[pii-protect] role config read failed, failing closed: ' + e.message);
      return true;                                // unknown + unreadable → mask (never leak on error)
    }
  }

  // Scan every string value in a response payload and replace PII by its one-way token, IN PLACE.
  // One batched engine round trip per response (not per field) → bounded latency.
  const maskInPlace = async (root: any) => {
    const strings = new Set<string>();
    const walk = (v: any) => {
      if (typeof v === 'string') { if (v.length >= 2 && !UUID_RE.test(v)) strings.add(v); } // skip UUIDs (ids); engine chunks long text
      else if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k]);
    };
    walk(root);
    if (!strings.size) return;
    const list = [...strings];
    const { results } = await post('/anonymize-batch', { texts: list, strategy: 'hash' }); // throws → fail-closed
    const map = new Map<string, string>(list.map((s, i) => [s, results[i]]));
    const rep = (v: any): any => {
      if (typeof v === 'string') return map.get(v) ?? v;
      if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) v[i] = rep(v[i]); return v; }
      if (v && typeof v === 'object') { for (const k of Object.keys(v)) v[k] = rep(v[k]); return v; }
      return v;
    };
    rep(root);
  };

  // ---- SETUP: one opt-in boolean on the role page. No collection picker (masking is role-wide) → no
  //      "restart d9 after creating a table" problem. Idempotent, drop-in. ----
  init('app.after', async () => {
    try {
      const schema = await getSchema();
      const fieldsSvc = new services.FieldsService({ schema, accountability: { admin: true, role: null } });
      const have = new Set((await fieldsSvc.readAll('directus_roles')).map((f: any) => f.field));
      const piiMeta = {
        interface: 'boolean', special: ['cast-boolean'], width: 'full',
        options: { label: "Mask PII in this role's API responses" },
        note: "When ON, personal data in everything this role reads through the API is replaced by a masked token. Complements RBAC — it doesn't replace it.",
      };
      if (!have.has('pii_mask'))
        await fieldsSvc.createField('directus_roles', { field: 'pii_mask', type: 'boolean', meta: piiMeta, schema: { default_value: false } });
      else
        await fieldsSvc.updateField('directus_roles', { field: 'pii_mask', meta: piiMeta }); // refresh label/note on upgrade
      // Self-cleanup: drop the legacy fields from the previous (reversible, per-collection) model.
      for (const legacy of ['pii_encrypt_all', 'pii_encrypt_collections']) {
        if (have.has(legacy)) {
          try { await fieldsSvc.deleteField('directus_roles', legacy); logger.info('[pii-protect] removed legacy field ' + legacy); }
          catch (e: any) { logger.warn('[pii-protect] could not remove legacy field ' + legacy + ': ' + e.message); }
        }
      }
      fieldsReady = true;
      logger.info('[pii-protect] role config ready (pii_mask)');
    } catch (e: any) { logger.warn('[pii-protect] role config setup skipped: ' + e.message); }
  });

  // ---- OUTPUT MASKING: one interceptor over all JSON data responses + binary asset redaction ----
  init('routes.before', ({ app }: any) => {
    const SCAN = ['/items', '/graphql', '/files']; // JSON data paths; /assets handled separately (binary)
    const shouldScan = (p: string) => SCAN.some((s) => p === s || p.startsWith(s + '/'));

    // Bulk export (?export=csv|json|xml, /utils/export) STREAMS outside res.json → it can't be scrubbed.
    // For a masked role, refuse it (an agent has no need for a raw dump). Async /utils/export writes a FILE,
    // which is then downloaded via /assets → already redacted there, so this only blocks the streaming dumps.
    app.use(async (req: any, res: any, next: any) => {
      const path = (req.originalUrl || '').split('?')[0];
      const isExport = !!req.query?.export || path.startsWith('/utils/export');
      if (isExport && await roleMasked(req.accountability?.role)) {
        return res.status(403).json({ errors: [{ message: 'bulk export is disabled for this role (PII protection)' }] });
      }
      next();
    });

    // Intercept res.json on data paths (Directus emits every item/GraphQL/file response via res.json). We decide
    // scan at ENTRY from req.originalUrl — once inside a sub-router, req.path is relative ('/documents/1'). We do
    // NOT wrap res.send (res.json funnels into it) → no double-wrap deadlock.
    app.use((req: any, res: any, next: any) => {
      if (!shouldScan((req.originalUrl || '').split('?')[0])) return next(); // non-data path → zero overhead
      const origJson = res.json.bind(res);
      let handled = false;
      res.json = (body: any) => {
        if (handled) return origJson(body);
        handled = true;
        (async () => {
          if (body && typeof body === 'object' && await roleMasked(req.accountability?.role)) {
            await maskInPlace(body);                       // mutate the payload in place, then serialize
            res.setHeader('cache-control', 'no-store');    // role-dependent output: never cached/shared
          }
          origJson(body);
        })().catch((e: any) => {
          logger.warn('[pii-protect] masking failed (fail-closed): ' + e.message);
          if (!res.headersSent) res.status(503);
          origJson({ errors: [{ message: 'PII masking unavailable' }] });
        });
        return res;
      };
      next();
    });

    // Binary content: redact via d9's AssetsService with the REQUESTER's own permissions (perms enforced).
    // Covers the plain id and the "/assets/:id/anything.txt" alternate address. text→hashed, image/PDF→masked.
    app.get(['/assets/:pk', '/assets/:pk/:filename'], async (req: any, res: any, next: any) => {
      if (!(await roleMasked(req.accountability?.role))) return next(); // d9 serves normally (RBAC decides access)
      try {
        const assets = new services.AssetsService({ schema: await getSchema(), accountability: req.accountability });
        const { stream, file } = await assets.getAsset(req.params.pk, {}); // original bytes; throws if forbidden
        const name = file?.filename_download || String(req.params.pk);
        const endpoint = FILE_ROUTE[ext(name)];
        if (!endpoint) return res.status(415).send('[protected — unsupported file type]'); // nothing unknown leaks
        const out = await callFile(endpoint, name, await bufferStream(stream));
        res.setHeader('content-type', file?.type || 'application/octet-stream');
        res.setHeader('cache-control', 'no-store');
        res.setHeader('content-disposition', 'attachment; filename="protected' + (ext(name) ? '.' + ext(name) : '') + '"');
        res.send(out); // Buffer → passes through the wrapper untouched
      } catch (e: any) {
        logger.warn('[pii-protect] /assets (fail-closed): ' + e.message);
        res.status(503).send('[protected — unavailable]'); // never serve clear on error
      }
    });
  });

  logger.info('[pii-protect] loaded (engine ' + ENGINE + ', hoop-style output masking)');
};

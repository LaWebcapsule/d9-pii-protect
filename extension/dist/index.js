const ENGINE = process.env.PII_PROTECT_ENGINE_URL || "http://host.docker.internal:8077";
const ENGINE_TOKEN = process.env.PII_PROTECT_ENGINE_TOKEN;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FILE_ROUTE = {
  txt: "/anonymize-doc",
  md: "/anonymize-doc",
  csv: "/anonymize-doc",
  json: "/anonymize-doc",
  docx: "/anonymize-doc",
  png: "/redact-image",
  jpg: "/redact-image",
  jpeg: "/redact-image",
  gif: "/redact-image",
  bmp: "/redact-image",
  tiff: "/redact-image",
  tif: "/redact-image",
  webp: "/redact-image",
  pdf: "/redact-pdf"
};
const ext = (name) => name.toLowerCase().split(".").pop() || "";
async function post(path, payload) {
  const headers = { "content-type": "application/json" };
  if (ENGINE_TOKEN) headers["x-engine-token"] = ENGINE_TOKEN;
  const r = await fetch(ENGINE + path, { method: "POST", headers, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error("engine HTTP " + r.status);
  return r.json();
}
async function bufferStream(stream) {
  const chunks = [];
  for await (const c of stream) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks);
}
const roleCache = /* @__PURE__ */ new Map();
let fieldsReady = false;
var index_default = ({ init }, { logger, database, services, getSchema }) => {
  async function roleMasked(roleId) {
    if (!fieldsReady || !roleId) return false;
    const hit = roleCache.get(roleId);
    if (hit && Date.now() - hit.at < 3e3) return hit.masked;
    try {
      const row = await database("directus_roles").select("pii_mask").where({ id: roleId }).first();
      const masked = !!row?.pii_mask;
      roleCache.set(roleId, { masked, at: Date.now() });
      return masked;
    } catch (e) {
      if (hit) return hit.masked;
      logger.warn("[pii-protect] role config read failed, failing closed: " + e.message);
      return true;
    }
  }
  const maskInPlace = async (root) => {
    const strings = /* @__PURE__ */ new Set();
    const walk = (v) => {
      if (typeof v === "string") {
        if (v.length >= 2 && !UUID_RE.test(v)) strings.add(v);
      } else if (Array.isArray(v)) v.forEach(walk);
      else if (v && typeof v === "object") for (const k of Object.keys(v)) walk(v[k]);
    };
    walk(root);
    if (!strings.size) return;
    const list = [...strings];
    const { results } = await post("/anonymize-batch", { texts: list, strategy: "hash" });
    const map = new Map(list.map((s, i) => [s, results[i]]));
    const rep = (v) => {
      if (typeof v === "string") return map.get(v) ?? v;
      if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) v[i] = rep(v[i]);
        return v;
      }
      if (v && typeof v === "object") {
        for (const k of Object.keys(v)) v[k] = rep(v[k]);
        return v;
      }
      return v;
    };
    rep(root);
  };
  init("app.after", async () => {
    try {
      const schema = await getSchema();
      const fieldsSvc = new services.FieldsService({ schema, accountability: { admin: true, role: null } });
      const have = new Set((await fieldsSvc.readAll("directus_roles")).map((f) => f.field));
      const piiMeta = {
        interface: "boolean",
        special: ["cast-boolean"],
        width: "full",
        options: { label: "Mask PII in this role's API responses" },
        note: "When ON, personal data in everything this role reads through the API is replaced by a masked token. Complements RBAC \u2014 it doesn't replace it."
      };
      if (!have.has("pii_mask"))
        await fieldsSvc.createField("directus_roles", { field: "pii_mask", type: "boolean", meta: piiMeta, schema: { default_value: false } });
      else
        await fieldsSvc.updateField("directus_roles", { field: "pii_mask", meta: piiMeta });
      for (const legacy of ["pii_encrypt_all", "pii_encrypt_collections"]) {
        if (have.has(legacy)) {
          try {
            await fieldsSvc.deleteField("directus_roles", legacy);
            logger.info("[pii-protect] removed legacy field " + legacy);
          } catch (e) {
            logger.warn("[pii-protect] could not remove legacy field " + legacy + ": " + e.message);
          }
        }
      }
      fieldsReady = true;
      logger.info("[pii-protect] role config ready (pii_mask)");
    } catch (e) {
      logger.warn("[pii-protect] role config setup skipped: " + e.message);
    }
  });
  init("routes.before", ({ app }) => {
    const SCAN = ["/items", "/graphql", "/files"];
    const shouldScan = (p) => SCAN.some((s) => p === s || p.startsWith(s + "/"));
    app.use(async (req, res, next) => {
      const path = (req.originalUrl || "").split("?")[0];
      const isExport = !!req.query?.export || path.startsWith("/utils/export");
      if (isExport && await roleMasked(req.accountability?.role)) {
        return res.status(403).json({ errors: [{ message: "bulk export is disabled for this role (PII protection)" }] });
      }
      next();
    });
    app.use((req, res, next) => {
      if (!shouldScan((req.originalUrl || "").split("?")[0])) return next();
      const origJson = res.json.bind(res);
      let handled = false;
      res.json = (body) => {
        if (handled) return origJson(body);
        handled = true;
        (async () => {
          if (body && typeof body === "object" && await roleMasked(req.accountability?.role)) {
            await maskInPlace(body);
            res.setHeader("cache-control", "no-store");
          }
          origJson(body);
        })().catch((e) => {
          logger.warn("[pii-protect] masking failed (fail-closed): " + e.message);
          if (!res.headersSent) res.status(503);
          origJson({ errors: [{ message: "PII masking unavailable" }] });
        });
        return res;
      };
      next();
    });
    app.get(["/assets/:pk", "/assets/:pk/:filename"], async (req, res, next) => {
      if (!await roleMasked(req.accountability?.role)) return next();
      try {
        const assets = new services.AssetsService({ schema: await getSchema(), accountability: req.accountability });
        const { stream, file } = await assets.getAsset(req.params.pk, {});
        const name = file?.filename_download || String(req.params.pk);
        const endpoint = FILE_ROUTE[ext(name)];
        if (!endpoint) return res.status(415).send("[protected \u2014 unsupported file type]");
        const resp = await post(endpoint, { filename: name, content_b64: (await bufferStream(stream)).toString("base64") });
        const out = Buffer.from(resp.content_b64, "base64");
        const ctype = resp.content_type || file?.type || "application/octet-stream";
        const outExt = ctype.indexOf("text/") === 0 ? "txt" : ext(name) || "bin";
        res.setHeader("content-type", ctype);
        res.setHeader("cache-control", "no-store");
        res.setHeader("content-disposition", 'attachment; filename="protected.' + outExt + '"');
        res.send(out);
      } catch (e) {
        logger.warn("[pii-protect] /assets (fail-closed): " + e.message);
        res.status(503).send("[protected \u2014 unavailable]");
      }
    });
  });
  logger.info("[pii-protect] loaded (engine " + ENGINE + ", hoop-style output masking)");
};
export {
  index_default as default
};

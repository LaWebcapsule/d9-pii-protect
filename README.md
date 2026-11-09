# d9 PII Protect

Governed PII masking for AI agents in [d9](https://github.com/LaWebcapsule/d9).

For the roles you choose, PII in **every API response** (items, GraphQL, files, assets) is **masked on the
way out** — each detected value is replaced by a consistent, one-way token like `[NOM_PERSONNE:a3f9c2…]`
(documents/images are redacted). Authorized roles (admins, unconfigured roles) still read the original; the
database stays in clear. Detection is French-first (Presidio + a FR NER model) and runs in a self-contained
engine next to d9 — PII never leaves your environment.

This **complements RBAC — it does not replace it**. The goal is to keep PII out of an AI agent's prompts and
traces (protect the agent from itself), not to defend against a deliberately hostile user. See
[Known limitations](#known-limitations).

## 🤖 Set it up with AI

New to this? Open a ready-made setup guide in your favorite AI — it reads this repo and walks you through adding the extension to your d9, step by step:

[![Ask ChatGPT](https://img.shields.io/badge/Ask-ChatGPT-10a37f?logo=openai&logoColor=white)](https://chatgpt.com/?q=Help%20me%20install%20the%20%22d9%20PII%20Protect%22%20extension%20on%20my%20EXISTING%20d9%20instance%20%28a%20d9%20/%20Directus%209%20fork%29%20so%20that%20PII%20in%20free-text%20fields%2C%20documents%20and%20images%20is%20encrypted%20for%20the%20roles%20I%20choose%2C%20while%20authorized%20users%20still%20see%20the%20original.%20The%20project%3A%20https%3A//github.com/LaWebcapsule/d9-pii-protect%20%E2%80%94%20read%20its%20README%20and%20extension/README.md%20first.%20Then%20guide%20me%20step%20by%20step%20for%20MY%20setup%20%28ask%20me%20how%20my%20d9%20runs%20%E2%80%94%20Docker%3F%20how%20is%20it%20deployed%3F%20%E2%80%94%20before%20giving%20any%20command%29%3A%0A1%29%20Start%20the%20PII%20engine%20sidecar%20%28Docker%20image%20built%20from%20the%20repo%27s%20engine/%20folder%3B%20set%20PII_PROTECT_KEY%29%20and%20note%20its%20URL.%0A2%29%20Add%20the%20extension%20to%20my%20d9%20extensions/%20folder%20%28use%20the%20prebuilt%20extension/dist/index.js%2C%20or%20run%20npm%20install%20%26%26%20npm%20run%20build%29.%0A3%29%20Point%20the%20extension%20at%20the%20engine%20via%20the%20PII_PROTECT_ENGINE_URL%20env%20var%20on%20d9.%0A4%29%20Restart%20d9%20%E2%80%94%20it%20should%20log%20%22%5Bpii-protect%5D%20loaded%22%20and%20auto-create%20its%20config%20fields%20on%20roles.%0A5%29%20Open%20a%20role%20%28Settings%20%3E%20Roles%20%26%20Permissions%29%2C%20enable%20%22Encrypt%20all%20collections%22%20or%20tick%20specific%20collections.%0AVerify%3A%20read%20data%20as%20a%20user%20of%20that%20role%20%28PII%20appears%20as%20%5B%5BPII%3A...%5D%5D%29%20vs%20an%20admin%20%28clear%29.%20Ask%20me%20questions%20whenever%20you%20need%20details%20about%20my%20environment.) [![Ask Claude](https://img.shields.io/badge/Ask-Claude-d97757?logo=anthropic&logoColor=white)](https://claude.ai/new?q=Help%20me%20install%20the%20%22d9%20PII%20Protect%22%20extension%20on%20my%20EXISTING%20d9%20instance%20%28a%20d9%20/%20Directus%209%20fork%29%20so%20that%20PII%20in%20free-text%20fields%2C%20documents%20and%20images%20is%20encrypted%20for%20the%20roles%20I%20choose%2C%20while%20authorized%20users%20still%20see%20the%20original.%20The%20project%3A%20https%3A//github.com/LaWebcapsule/d9-pii-protect%20%E2%80%94%20read%20its%20README%20and%20extension/README.md%20first.%20Then%20guide%20me%20step%20by%20step%20for%20MY%20setup%20%28ask%20me%20how%20my%20d9%20runs%20%E2%80%94%20Docker%3F%20how%20is%20it%20deployed%3F%20%E2%80%94%20before%20giving%20any%20command%29%3A%0A1%29%20Start%20the%20PII%20engine%20sidecar%20%28Docker%20image%20built%20from%20the%20repo%27s%20engine/%20folder%3B%20set%20PII_PROTECT_KEY%29%20and%20note%20its%20URL.%0A2%29%20Add%20the%20extension%20to%20my%20d9%20extensions/%20folder%20%28use%20the%20prebuilt%20extension/dist/index.js%2C%20or%20run%20npm%20install%20%26%26%20npm%20run%20build%29.%0A3%29%20Point%20the%20extension%20at%20the%20engine%20via%20the%20PII_PROTECT_ENGINE_URL%20env%20var%20on%20d9.%0A4%29%20Restart%20d9%20%E2%80%94%20it%20should%20log%20%22%5Bpii-protect%5D%20loaded%22%20and%20auto-create%20its%20config%20fields%20on%20roles.%0A5%29%20Open%20a%20role%20%28Settings%20%3E%20Roles%20%26%20Permissions%29%2C%20enable%20%22Encrypt%20all%20collections%22%20or%20tick%20specific%20collections.%0AVerify%3A%20read%20data%20as%20a%20user%20of%20that%20role%20%28PII%20appears%20as%20%5B%5BPII%3A...%5D%5D%29%20vs%20an%20admin%20%28clear%29.%20Ask%20me%20questions%20whenever%20you%20need%20details%20about%20my%20environment.) [![Ask Perplexity](https://img.shields.io/badge/Ask-Perplexity-20808d?logo=perplexity&logoColor=white)](https://www.perplexity.ai/search?q=Help%20me%20install%20the%20%22d9%20PII%20Protect%22%20extension%20on%20my%20EXISTING%20d9%20instance%20%28a%20d9%20/%20Directus%209%20fork%29%20so%20that%20PII%20in%20free-text%20fields%2C%20documents%20and%20images%20is%20encrypted%20for%20the%20roles%20I%20choose%2C%20while%20authorized%20users%20still%20see%20the%20original.%20The%20project%3A%20https%3A//github.com/LaWebcapsule/d9-pii-protect%20%E2%80%94%20read%20its%20README%20and%20extension/README.md%20first.%20Then%20guide%20me%20step%20by%20step%20for%20MY%20setup%20%28ask%20me%20how%20my%20d9%20runs%20%E2%80%94%20Docker%3F%20how%20is%20it%20deployed%3F%20%E2%80%94%20before%20giving%20any%20command%29%3A%0A1%29%20Start%20the%20PII%20engine%20sidecar%20%28Docker%20image%20built%20from%20the%20repo%27s%20engine/%20folder%3B%20set%20PII_PROTECT_KEY%29%20and%20note%20its%20URL.%0A2%29%20Add%20the%20extension%20to%20my%20d9%20extensions/%20folder%20%28use%20the%20prebuilt%20extension/dist/index.js%2C%20or%20run%20npm%20install%20%26%26%20npm%20run%20build%29.%0A3%29%20Point%20the%20extension%20at%20the%20engine%20via%20the%20PII_PROTECT_ENGINE_URL%20env%20var%20on%20d9.%0A4%29%20Restart%20d9%20%E2%80%94%20it%20should%20log%20%22%5Bpii-protect%5D%20loaded%22%20and%20auto-create%20its%20config%20fields%20on%20roles.%0A5%29%20Open%20a%20role%20%28Settings%20%3E%20Roles%20%26%20Permissions%29%2C%20enable%20%22Encrypt%20all%20collections%22%20or%20tick%20specific%20collections.%0AVerify%3A%20read%20data%20as%20a%20user%20of%20that%20role%20%28PII%20appears%20as%20%5B%5BPII%3A...%5D%5D%29%20vs%20an%20admin%20%28clear%29.%20Ask%20me%20questions%20whenever%20you%20need%20details%20about%20my%20environment.)

<details><summary>Or copy the prompt</summary>

```text
Help me install the "d9 PII Protect" extension on my EXISTING d9 instance (a d9 / Directus 9 fork) so that PII in the API responses (items, GraphQL, files, assets) is masked for the roles I choose, while authorized users still see the original. The project: https://github.com/LaWebcapsule/d9-pii-protect — read its README and extension/README.md first. Then guide me step by step for MY setup (ask me how my d9 runs — Docker? how is it deployed? — before giving any command):
1) Start the PII engine sidecar (Docker image built from the repo's engine/ folder; set PII_PROTECT_KEY) and note its URL.
2) Add the extension to my d9 extensions/ folder (use the prebuilt extension/dist/index.js, or run npm install && npm run build).
3) Point the extension at the engine via the PII_PROTECT_ENGINE_URL env var on d9.
4) Restart d9 — it should log "[pii-protect] loaded" and auto-create its config field on roles.
5) Open a role (Settings > Roles & Permissions), enable "Mask PII in this role's API responses".
Verify: read data as a user of that role (PII appears as [TYPE:hash] tokens) vs an admin (clear). Ask me questions whenever you need details about my environment.
```

</details>

## Install

Add it to an **existing d9** — see [`extension/README.md`](extension/README.md) — or run the reference
stack from scratch:

```bash
cd deploy
cp .env.example .env            # set at least PII_PROTECT_KEY
docker compose up -d --build    # d9 on http://localhost:8055 + the PII engine
```

## Use it

Open **Settings → Roles & Permissions → a role**. The extension adds one control there automatically
(no setup script):

- **Mask PII in this role's API responses** — turn it on.

Every value that role reads via the API is then scanned and its PII replaced by a one-way token
(`[TYPE:hash]`, e.g. `[NOM_PERSONNE:a3f9c2…]`); anyone whose role isn't configured sees the clear value. The
token is a consistent keyed hash, so the same value always yields the same token (joins/dedup still work) but
there is no way back to the clear. It applies to **any role, humans included**, so you can also hide data from
some human maintainers. Changing this requires role-edit rights, so a regular user can't alter it.

## Configuration (environment variables)

| Variable | Where | What | Default |
|---|---|---|---|
| `PII_PROTECT_KEY` | engine | Secret key for the one-way HMAC tokens (use a secret/KMS in production). No default — the engine refuses to start without it. | — (required) |
| `PII_PROTECT_ENGINE_URL` | extension | URL of the engine. | `http://engine:8077` |
| `PII_PROTECT_ENGINE_TOKEN` | engine + extension | Optional shared secret; if set, the engine only accepts calls carrying it (`X-Engine-Token`). | *(empty = no auth)* |
| `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP` | engine | Allow-list / deny-list of PII types to mask. | *(empty = all)* |
| `PII_NER_MODEL` | engine | Hugging Face NER model (see [`engine/MODELS.md`](engine/MODELS.md)). | Anonym-IA FR |
| `PII_NER_THRESHOLD` | engine | NER confidence threshold. | `0.4` |
| `PII_NER_ONNX_THREADS` | engine | ONNX Runtime threads (empty = auto; cap to perf cores on Apple Silicon). | *(auto)* |
| `PII_HASH_LEN` | engine | Hex length of the token hash. | `12` |
| `PII_OCR_LANG` | engine | Tesseract language for image redaction. | `fra` |

## Customize

- Add a regex / recognizer → `engine/recognizers.py`.
- Change language / model → `PII_NER_MODEL` (candidates in `engine/MODELS.md`).
- Choose which PII types → `PII_PROTECT_ENTITIES` / `PII_PROTECT_SKIP`.

Architecture overview: [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Known limitations

This is **output masking that complements RBAC**, not encryption-at-rest. It reduces exposure of *detected*
PII to a *non-hostile* role across every HTTP read path. By design it does **not** cover:

- **A deliberately hostile role.** The database stores clear and still filters/sorts on the clear value, so a
  role that *actively* probes (`filter[field][_starts_with]=…`, binary-searching a value) can reconstruct it.
  Blocking that is the job of **RBAC** (don't grant the field) or encryption-at-rest.
- **PII coming *in*.** Only what *leaves* the API is masked; a role can still *write* clear PII to the database.
- **Data at rest.** A DB dump, direct SQL, an admin, or any unconfigured role sees the clear value — that's the point.
- **Non-string fields.** Only string values are scanned. PII placed in a numeric/boolean column isn't masked
  (use RBAC/field permissions there). Long text *is* handled — the engine chunks it.
- **WebSocket / realtime.** Messages are pushed outside the HTTP response path, so they aren't scrubbed.
  Realtime is **off by default**; keep it off for masked roles (or add a service-layer hook if you enable it).
- **Detection is best-effort.** Whatever the engine doesn't detect leaks (geographic entities — city/postal/
  street — are currently weak), and complex/non-UTF-8 documents may redact imperfectly. Improving recognizers
  is ongoing; everything masked is already more than a bare d9.

## License

MIT — see [LICENSE](LICENSE).

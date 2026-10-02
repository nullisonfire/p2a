# P2A → Cloudflare Pages + Worker + R2 migration

This repository is a Cloudflare-ready migration of the supplied PHP project.

## 1. Current architecture found in the archive

The supplied project is a cPanel/PHP application with:

- `index.php` — password-gated course viewer UI, course catalog, course navigation, content rendering, settings and purchase actions.
- `fetch.php` — authenticated P2A API proxy with filesystem JSON caching for courses/content.
- `sse.php` — long-running cache builder that downloads course contents, PDFs, exams and written exams into local JSON/PDF/ZIP files.
- `exam.php`, `answer.php`, `written_question.php` — PHP-rendered exam pages; they fetch/cache exam data and decrypt answer/explanation fields server-side.
- `pdf.php` — authenticated PDF proxy with local filesystem cache.
- `purchase.php` — authenticated purchase/free-order workflow backed by `purchased_course.json`.
- `accnt/index.php` — profile/authenticated-course viewer using JSON credential files.
- `cache.php`, `check.php`, `pdf/index.php`, `pdf_mapping/index.php`, `zip/*` — filesystem-oriented operator/cache/PDF/ZIP utilities.
- Three credential JSON files (`maisha.json`, `abdullah.json`, `waleed.json`) containing bearer tokens plus CSRF/app credentials.
- A hard-coded access passcode and a hard-coded AES decryption secret are present in the source.

The archive does **not** contain the referenced `cache/` tree or `tokens.json`, so the existing cached course/content/PDF/exam data cannot be migrated from this ZIP alone.

## 2. Target architecture

```text
User
  ↓
Cloudflare Pages (static HTML/CSS/JS)
  ↓ HTTPS + HttpOnly session cookie
Cloudflare Worker /api/*
  ├── authenticated P2A API requests
  ├── cache lookup / cache fill
  ├── PDF proxy
  ├── exam decryption
  └── R2 access control
        ↓
Cloudflare R2 (private bucket)
  ├── catalog/courses.json
  ├── courses/<slug>.json
  ├── contents/<slug>.json
  ├── exam/<id>.json
  ├── written/<id>.json
  ├── pdf/<slug>.pdf
  └── state/purchased_course.json

External:
Pages → Worker → https://p2a.academy/api/*
```

The browser never receives bearer tokens, CSRF values, `x_app_key`, `x_secret`, or the AES secret.

## 3. File migration table

| Original | New Location | Action | Reason |
|---|---|---|---|
| `index.php` | `public/index.html` + `public/config.js` | Converted | PHP UI/passcode flow becomes static UI + Worker session; existing dark viewer layout retained. |
| `fetch.php` | `worker/src/index.js` | Converted | Upstream credentials and filesystem cache are server-side concerns. |
| `fetch_courses.php` | `public/data/courses.json` + R2 `catalog/courses.json` | Converted | The archive contains a static catalog; no PHP execution is required. |
| `purchase.php` | Worker `/api/purchase` | Converted | Purchase API needs authenticated upstream requests and persistent state. |
| `pdf.php` | Worker `/api/pdf` + R2 `pdf/*` | Converted | PDF proxy and cache require server-side credentials/R2 access. |
| `exam.php` | `public/exam/index.html` + Worker `/api/exam` | Converted | UI is static; authenticated fetch/decryption stays server-side. |
| `answer.php` | `public/answer/index.html` + Worker `/api/exam` | Converted | Answer/explanation decryption stays in Worker. |
| `written_question.php` | `public/written/index.html` + Worker `/api/written` | Converted | Authenticated written-exam data is served by Worker. |
| `accnt/index.php` | `public/account/index.html` + Worker `/api/profile` | Converted | Profile/course API calls remain server-side. |
| `purchased_course.json` | R2 `state/purchased_course.json` | Moved/private | It is application state, not a public asset. |
| `maisha.json`, `abdullah.json`, `waleed.json` | Worker secret `AUTH_ACCOUNTS_JSON` | Removed from repo | They contain live credentials and must not be published. Rotate them before use. |
| `tokens.json` | Worker secret `AUTH_ACCOUNTS_JSON` | Not present in archive; do not recreate publicly | Referenced by PHP but absent from supplied ZIP. |
| `cache/contents/*.json` | R2 `contents/*.json` | Planned bulk migration | Cache directory is referenced by PHP but absent from archive. |
| `cache/courses/*.json` | R2 `courses/*.json` | Planned bulk migration | Same cache-key convention is preserved. |
| `cache/exam/*.json` | R2 `exam/*.json` | Planned bulk migration | Preserves numeric exam IDs. |
| `cache/written/*.json` | R2 `written/*.json` | Planned bulk migration | Preserves numeric written-exam IDs. |
| `cache/pdf/*.pdf` | R2 `pdf/*.pdf` | Planned bulk migration | Preserves PDF slug keys. |
| `cache/pdf-zips/*` | R2 `pdf-zips/*` | Operator-only migration | ZIP explorer is filesystem-specific; no public R2 listing is exposed by the Worker. |
| `sse.php` | Not exposed as a public endpoint | Requires redesign | It is a long-running filesystem cache builder. Use a controlled Worker/cron/admin job later; do not expose it anonymously. |
| `cache.php`, `check.php`, `pdf_mapping/index.php`, `pdf/index.php`, `zip/*` | Operator tooling | Not part of public Pages UI | These depend on local filesystem scanning/ZIP/PDF generation. R2-compatible admin tooling should be added separately if required. |
| `.htaccess` files | Cloudflare settings / `_headers` | Replaced | Apache directives do not execute on Pages/Workers. |

## 4. Security findings

The archive contains credential material that should be considered compromised:

- bearer/JWT tokens
- CSRF token
- application key
- secret token/header value
- a hard-coded access passcode
- a hard-coded AES decryption secret
- commented login passwords in `login.php`

**Do not commit or deploy those values. Rotate the P2A credentials upstream before production cutover.** The migration repository contains placeholders only.

The Worker expects these secrets:

```text
ACCESS_PASSCODE
SESSION_SECRET
AUTH_ACCOUNTS_JSON
P2A_AES_SECRET
```

`AUTH_ACCOUNTS_JSON` should contain the rotated credentials using the account names already used by the application. The example structure is in `secrets/auth-accounts.example.json`.

## 5. Worker API

All protected endpoints require the Worker session cookie created by `/api/auth/login`.

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/auth/login` | POST JSON `{passcode}` | Validate access code and issue HttpOnly session |
| `/api/auth/session` | GET | Check current session |
| `/api/auth/accounts` | GET | List configured account aliases, never credentials |
| `/api/auth/select-account` | POST JSON `{account}` | Select one server-side credential set |
| `/api/auth/logout` | GET | Clear session |
| `/api/courses` | GET | Read course catalog from private R2 |
| `/api/purchased-courses` | GET | Read purchase state from private R2 |
| `/api/fetch?fetch=course&course_url=...` | GET | Read/cache a course |
| `/api/fetch?fetch=content&slug=...` | GET | Read/cache course content |
| `/api/purchase?slug=...` | GET | Run existing payment/free-order flow |
| `/api/exam?id=...` | GET | Read/cache exam and decrypt answer/explanation fields server-side |
| `/api/written?exam=...` | GET | Read/cache written exam |
| `/api/profile` | GET | Fetch profile + authenticated courses |
| `/api/pdf?slug=...` | GET | Read/cache a PDF in private R2 |

R2 keys are validated before use. Content slugs are restricted to `[A-Za-z0-9_-]+`; exam IDs are numeric.

## 6. R2 structure

```text
p2a-cache/
├── catalog/
│   └── courses.json
├── courses/
│   └── <course-slug>.json
├── contents/
│   └── <content-slug>.json
├── exam/
│   └── <exam-id>.json
├── written/
│   └── <exam-id>.json
├── pdf/
│   └── <pdf-slug>.pdf
├── pdf-zips/
│   └── <existing zip files>
└── state/
    └── purchased_course.json
```

Keep the bucket private. The Worker is the access-controlled asset endpoint.

## 7. Local project setup

No framework or build system is required for Pages.

### Pages

- Framework preset: **None / Static HTML**
- Build command: **leave blank**
- Build output directory: `public`
- Production branch: `main`

Before deploying, edit `public/config.js` and replace the Worker URL placeholder.

### Worker

Install Wrangler locally or use the Cloudflare dashboard's Worker tooling. From this directory:

```bash
npx wrangler login
npx wrangler r2 bucket create p2a-cache
npx wrangler secret put ACCESS_PASSCODE
npx wrangler secret put SESSION_SECRET
npx wrangler secret put AUTH_ACCOUNTS_JSON
npx wrangler secret put P2A_AES_SECRET
npx wrangler deploy
```

Set `ALLOWED_ORIGINS` in `wrangler.toml` to the exact Pages origin, for example:

```text
https://your-project.pages.dev
```

If a custom Pages domain is used, include that exact origin as well, comma-separated.

## 8. R2 migration from cPanel

The supplied ZIP does not include the `cache/` directory, so obtain it directly from the old cPanel host before cutover.

For multi-GB data, use the R2 S3-compatible endpoint rather than uploading individual objects manually.

Install/configure AWS CLI and then:

```bash
export R2_BUCKET=p2a-cache
export R2_ACCOUNT_ID=YOUR_CLOUDFLARE_ACCOUNT_ID
export AWS_ACCESS_KEY_ID=YOUR_R2_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=YOUR_R2_SECRET_ACCESS_KEY

./scripts/upload-r2.sh /path/to/old-project/cache /path/to/old-project/purchased_course.json
./scripts/upload-catalog.sh
```

The sync preserves the old cache's relative keys, so `cache/contents/foo.json` becomes `contents/foo.json` in R2.

Create the R2 API token from Cloudflare with the minimum bucket permissions needed for migration. Do not put R2 credentials in GitHub.

## 9. GitHub

From the repository root:

```bash
git init
git add .
git commit -m "Initial Cloudflare migration"
git branch -M main
git remote add origin YOUR_GITHUB_REPO
git push -u origin main
```

Before `git add`, run:

```bash
./scripts/secret-check.sh
```

The `.gitignore` excludes environment files, token/credential JSON, local caches and inspection artifacts.

## 10. Cloudflare Pages deployment

1. Open **Cloudflare Dashboard**.
2. Go to **Workers & Pages**.
3. Create a **Pages** project.
4. Connect the GitHub repository.
5. Select branch `main`.
6. Framework preset: **None**.
7. Build command: blank.
8. Output directory: `public`.
9. Deploy.
10. Copy the resulting `pages.dev` origin into `wrangler.toml` under `ALLOWED_ORIGINS`.
11. Edit `public/config.js` with the deployed Worker URL.
12. Commit/push that config change and let Pages redeploy.

## 11. Worker deployment

After the R2 bucket exists and secrets are loaded:

```bash
npx wrangler deploy
```

Verify:

```bash
curl https://YOUR-WORKER.workers.dev/api/health
```

Expected response:

```json
{"ok":true}
```

Do not test protected endpoints with real credentials pasted into shell history. Use the browser session flow instead.

## 12. Testing checklist

### Completed locally

- All 17 PHP files in the supplied archive pass `php -l` syntax validation.
- Worker source passes Node syntax validation.
- Static HTML inline JavaScript passes Node syntax validation.
- The supplied course catalog was extracted into `public/data/courses.json`.
- No archive credential values were copied into the migration files.

### Requires Cloudflare/P2A credentials and the missing cPanel cache

- [ ] Pages loads from `pages.dev`.
- [ ] Access-code login creates an HttpOnly session.
- [ ] Invalid access code is rejected server-side.
- [ ] Account aliases load without exposing credential values.
- [ ] Course catalog loads from R2.
- [ ] Course browsing works.
- [ ] Course content cache hit works.
- [ ] Course content cache miss calls P2A and writes R2.
- [ ] Purchase flow works against the real P2A account.
- [ ] PDFs load through `/api/pdf` and are cached in R2.
- [ ] Videos still embed through YouTube URLs returned by the existing content format.
- [ ] Exam data loads and answer/explanation fields are decrypted in Worker only.
- [ ] Written-exam data loads.
- [ ] Profile/authenticated courses load.
- [ ] CORS permits only the configured Pages origins.
- [ ] R2 remains private; direct unauthenticated object access is denied.
- [ ] No token/secret appears in browser Network responses, page source, JS bundles or GitHub.
- [ ] No PHP URL remains in the public frontend.

## 13. cPanel → Cloudflare cutover

1. Keep the existing cPanel project online.
2. Rotate the exposed P2A credentials and create the new Worker secret set.
3. Create the R2 bucket and bulk-copy the existing `cache/` directory.
4. Upload `catalog/courses.json` and `state/purchased_course.json`.
5. Deploy the Worker and verify `/api/health`.
6. Deploy Pages and verify the login, course grid, course viewer, PDF and exam flows.
7. Test with real account credentials using a small representative set of courses/content.
8. Compare cache hits/misses and API responses against the cPanel implementation.
9. Only after the new deployment is verified, switch DNS/links to Pages.
10. Leave cPanel running during a rollback window.
11. Shut down the old PHP application only after the new Pages/Worker/R2 system has been stable and the old cache has been safely retained/backed up.

## 14. Important limitations from the supplied ZIP

The archive is incomplete for a byte-for-byte migration because it references but does not contain:

- the `cache/` directory and its JSON/PDF/ZIP contents;
- `tokens.json` referenced by several PHP files;
- the live state of the upstream P2A API.

The migration therefore preserves the cache key conventions and API behavior without inventing missing cache data. The Worker will populate missing R2 objects on demand after valid rotated credentials are installed.

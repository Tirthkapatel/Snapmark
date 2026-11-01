# Snapmark — photo stamp app

Snap your photos into collectible postage stamps. Web app + API in one repo:

- `index.html` — the whole app (camera, stamp cutter, collections, calendar, scrapbook, letters)
- `api/index.js` — auth + sync server (signup OTP by email, login, forgot password, stamps sync)
- Photos are stored on Cloudinary; accounts + stamp records live in Turso (libSQL)

## Deploy (Vercel + Turso)

1. **Turso** — create a database named `snapmark` at https://turso.tech (free, no card).
   Copy its **Database URL** and create an **Auth Token**.
2. **Vercel** — New Project → import this repo. Framework preset: **Other**. No build command.
3. **Environment variables** (Project → Settings → Environment Variables):
   - `TURSO_DATABASE_URL` — from step 1
   - `TURSO_AUTH_TOKEN` — from step 1
   - `SESSION_SECRET` — any long random string
   - `SENDER_EMAIL` — the Gmail address OTP mails are sent from
   - `GMAIL_APP_PASSWORD` — a Google **App Password** for that Gmail
     (Google Account → Security → 2-Step Verification → App passwords)
4. **Redeploy** after setting the variables. Open the Vercel URL — the app and
   login work on the same link. Without the two mail variables the server runs
   in dev mode and OTP codes are only printed in the function logs.

## Local development

```bash
npm install
node api/index.js   # http://localhost:8792 — app + API on one origin
```

Without `TURSO_DATABASE_URL` it uses a local file DB at `server/data/snapmark.db`.

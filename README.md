# Review for Reward

A small full-stack web application that lets **anyone** collect Google reviews
from customers, submit a screenshot, and get credit on a public leaderboard —
with a perceptual-hash anti-fraud check and a hidden admin approval queue in
between.

## Stack

- **Backend / API:** Python · FastAPI · Uvicorn
- **Database:** SQLite via SQLAlchemy (file: `app.db`) — real persisted
  server-side storage, not browser storage.
- **Templating:** Jinja2 (server-rendered HTML + progressive enhancement)
- **Auth:** Google OAuth2 (server-verified ID token) OR phone-number + OTP
  (Twilio). No passwords ever stored.
- **Email:** Resend
- **SMS:** Twilio
- **Image storage:** Vercel Blob (falls back to server disk)
- **Anti-fraud:** 64-bit difference hash (`imagehash.dhash`) compared against
  every prior submission by Hamming distance.

## Run locally

```bash
pip install -r requirements.txt
cp .env.example .env      # then fill in the keys you have
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

The server starts on `http://localhost:8000`.

## Switching on real providers

All integrations are **fully implemented** and turn on automatically when the
matching environment variable is present. Without keys, the app runs in a
clearly-labeled **dev mode** so every flow is still testable:

| Feature  | Env vars to set                              | Dev-mode fallback                              |
|----------|----------------------------------------------|------------------------------------------------|
| Google   | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`   | Simulated Google sign-in (enter any email)     |
| Email    | `RESEND_API_KEY`, `EMAIL_FROM`               | Email body printed to server logs              |
| SMS      | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` | 6-digit OTP shown on the sign-in page & in logs |
| Blob     | `BLOB_READ_WRITE_TOKEN`                      | Stored under `/uploads` on the server disk     |

### Google OAuth redirect URI

Once the app is running at its public URL (e.g.
`https://<your-host>`), register that exact URL as an authorized origin in the
Google Cloud Console and add the redirect URI:

```
https://<your-host>/auth/google/callback
```

The app derives the callback from the request's `X-Forwarded-Proto` / `Host`
headers (or `PUBLIC_URL` if you set it explicitly), so it works behind the
preview proxy without configuration.

### Admin allowlist

Set `ADMIN_EMAILS` in `.env` to a comma-separated list of exact,
Google-verified email addresses:

```
ADMIN_EMAILS=nothing210306@gmail.com,other.admin@company.com
```

There is **no in-app admin control**. Admin permission is re-evaluated on every
login and re-checked server-side on every admin API call. Non-admins (and
unauthenticated callers) hitting `/admin*` receive a generic **404** so the
existence of the admin area is never disclosed.

The hidden admin URL is:

```
/admin
```

It is not linked or referenced anywhere in the regular UI.

## How the anti-fraud check works

On every upload the server:

1. Validates type (JPEG/PNG/WebP) and size (≤ 12 MB).
2. Normalizes EXIF orientation and color mode.
3. Computes a 64-bit **difference hash** (`imagehash.dhash`, 8×8).
4. Compares against every prior submission's dHash by **Hamming distance**.
5. Rejects the upload if the distance is ≤ `DUPLICATE_THRESHOLD` (default 5).

This catches exact re-uploads, JPEG recompressions, small crops, and resizes —
the things a person would actually do when reusing a screenshot — without
rejecting genuinely different reviews. The threshold is tunable via
`DUPLICATE_THRESHOLD`.

## Notifications

Each submitter is notified through the channel matching how they signed up:

- **Google users** → email via Resend
- **Phone users** → SMS via Twilio
- **Everyone** → in-app notification center (bell icon in the top bar)

Notifications are sent at three stages: `under_verification`, `approved`, and
`rejected` (with the admin's rejection reason, if supplied).

## OTP rate limiting

Phone OTP requests are limited to **5 per phone number per hour**
(`OTP_MAX_PER_HOUR`) and codes expire after **5 minutes** (`OTP_TTL_SECONDS`).
Codes are stored as SHA-256 hashes, never in plaintext.

## API / route map

Public (auth required where noted):

- `GET /` — upload page & personal submission history
- `GET /signin` — Google / phone sign-in
- `POST /auth/google/login` · `GET /auth/google/callback`
- `POST /auth/phone/request` · `POST /auth/phone/verify`
- `POST /auth/logout`
- `GET /profile` · `POST /profile` — one-time profile form
- `POST /submit` — file upload (auth required)
- `GET /leaderboard` — public leaderboard
- `GET /api/notifications` · `POST /api/notifications/read`
- `GET /healthz`

Hidden admin (allowlist enforced server-side, 404 otherwise):

- `GET /admin` — review queue, approved/rejected history, audit log
- `POST /admin/submissions/{id}/approve`
- `POST /admin/submissions/{id}/reject`
- `GET /admin/leaderboard.csv` — admin-only CSV export

## Security notes

- The server is the **only** enforcement point. The frontend has no
  `is_admin` flag; every admin handler calls `require_admin`, which recomputes
  the allowlist match from the signed session's verified identity.
- Sessions are signed, `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS.
- CSRF state for Google OAuth is carried in a short-lived signed cookie and
  compared with `secrets.compare_digest`.
- Uploads are parsed with Pillow and rejected if they're not valid images.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`) are applied to every response.
- OTP codes are hashed at rest; an audit log captures sign-ins, uploads,
  duplicate-blocks, approvals, and rejections with timestamps and IPs.

## Layout

```
app.py              FastAPI app + all routes
auth.py             session cookies, OTP helpers, is_admin check
config.py           env-var loading & feature flags
db.py               SQLAlchemy models & session
google_auth.py      Google OAuth2 code → verified email
notifications.py    Resend + Twilio + in-app notifications
storage.py          Vercel Blob / disk storage
image_utils.py      dHash + Hamming distance + validation
templates/          Jinja2 pages
static/app.css      design system
uploads/            disk-storage fallback
```

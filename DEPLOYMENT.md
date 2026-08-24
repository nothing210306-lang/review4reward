# Deployment — Review for Reward

**Live URL:** https://review4reward.vercel.app
**Vercel project:** `review4reward` (team `nothing-7942`)
**Database:** Supabase Postgres (Mumbai, ap-south-1)
**Storage:** Supabase Storage (configured; service key pending — see below)

## What's already done

- Project created on Vercel and wired to Supabase Postgres (`DATABASE_URL`).
- Tables auto-created by SQLAlchemy on first cold start (users, submissions,
  otp_challenges, notifications, audit_log).
- `SESSION_SECRET` set to a fresh random value; `ADMIN_EMAILS=nothing210306@gmail.com`.
- Admin area at `/admin` returns **404** to anyone not on the allowlist
  (verified live). There is no link to it anywhere in the UI.
- All routes serve 200/303/404 as expected; CSS and static assets load.

## What you need to add to finish (all in Vercel → Project → Settings → Environment Variables)

### 1. Supabase Storage keys (required to enable uploads)

Without these, the deployed app can't save screenshots (Vercel's filesystem is
read-only). Get them from **Supabase → Project Settings → API**:

| Variable | Value |
|---|---|
| `SUPABASE_URL` | `https://boorzharuxxyuamajcuf.supabase.co` |
| `SUPABASE_ANON_KEY` | the `anon` `public` JWT from the API settings page |
| `SUPABASE_SERVICE_KEY` | the `service_role` JWT (click "Reveal") |

Once added, redeploy (Vercel → Deployments → latest → "Redeploy"). The app
creates a private bucket called `review-screenshots` automatically on cold start.

### 2. Google OAuth (required for Google sign-in)

1. Google Cloud Console → APIs & Services → Credentials → **Create OAuth client ID** (Web application).
2. **Authorized JavaScript origins:** `https://review4reward.vercel.app`
3. **Authorized redirect URIs:** `https://review4reward.vercel.app/auth/google/callback`
4. Add to Vercel env vars:

| Variable | Value |
|---|---|
| `GOOGLE_CLIENT_ID` | from the OAuth client |
| `GOOGLE_CLIENT_SECRET` | from the OAuth client |

Without these, the sign-in page shows a simulated "dev mode" Google form — **this
is intentionally disabled in production** once `GOOGLE_CLIENT_ID` is set.

### 3. Resend (email notifications)

| Variable | Value |
|---|---|
| `RESEND_API_KEY` | `re_...` from resend.com/api-keys |
| `EMAIL_FROM` | e.g. `Review for Reward <reviews@yourdomain.com>` (must be a verified domain in Resend) |

Without these, "under verification / approved / rejected" emails are logged to
the Vercel function logs instead of sent.

### 4. Twilio (SMS OTP + notifications)

| Variable | Value |
|---|---|
| `TWILIO_ACCOUNT_SID` | `AC...` |
| `TWILIO_AUTH_TOKEN` | from Twilio console |
| `TWILIO_FROM_NUMBER` | E.164, e.g. `+1...` |

Without these, the 6-digit OTP is shown on the sign-in page so phone sign-in is
still testable.

After adding any of the above, redeploy from the Vercel dashboard (no code
changes needed — the providers turn on automatically).

## Security notes

- The admin allowlist is `nothing210306@gmail.com`. Add more addresses via
  `ADMIN_EMAILS` (comma-separated) and redeploy.
- The `SESSION_SECRET` is already set; rotate it anytime by overwriting the
  env var and redeploying (all existing sessions will be invalidated).
- Supabase `service_role` key bypasses RLS — it's stored as an encrypted Vercel
  env var and only ever used server-side; the anon key is what ships to the
  browser for direct-to-storage uploads.
- OTP rate limit: 5/hour/phone, 5-minute expiry, hashed at rest.
- Duplicate detection: 64-bit dHash, Hamming threshold 8 (tunable via
  `DUPLICATE_THRESHOLD`).

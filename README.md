# Karl Phelps Driving School platform

```
public/   Public website + Student Portal   -> deploy as Cloudflare Pages site #1
admin/    Admin Management System           -> deploy as a SEPARATE Cloudflare Pages site #2 (own URL)
worker/   API (Cloudflare Worker + cron)    -> npx wrangler deploy
firestore.rules
```

## Setup (in order)
1. **Firebase**: enable Authentication > Email/Password. Create Firestore (production mode). Publish `firestore.rules`.
   Project settings > Service accounts > Generate key (keep this JSON private; you only paste two values from it into Cloudflare).
2. **Cloudinary**: note the cloud name, API key, API secret.
3. **Worker**: edit `worker/wrangler.toml` vars, then in `worker/`:
   `npx wrangler secret put FB_CLIENT_EMAIL` (client_email), `FB_PRIVATE_KEY` (private_key), `CLOUDINARY_API_SECRET`, `BOOTSTRAP_KEY` (any long random text), then `npx wrangler deploy`.
4. **Config**: fill `public/config.js` and `admin/config.js` (Firebase web config + Worker URL). Add both site URLs to `ALLOWED_ORIGIN` and to Firebase Auth > Settings > Authorized domains.
5. **Create the first admin** (once):
   `curl -X POST https://YOUR-WORKER/bootstrap -H "Content-Type: application/json" -d '{"key":"YOUR_BOOTSTRAP_KEY","email":"you@example.com","password":"a-long-password","name":"Your Name"}'`
   Then run `npx wrangler secret delete BOOTSTRAP_KEY`.
6. Sign in to the admin site > Settings: add bank details, phone/email, locations, and review packages (Save packages once to store them).
7. Deploy: `npx wrangler pages deploy public` and `npx wrangler pages deploy admin`. Serve over HTTPS (the pages use ES modules; they will not work from file://).
8. In Cloudflare, add a rate-limiting rule for the Worker (login-adjacent and registration endpoints).

## What is implemented
Registration + atomic Student IDs, login, password reset, enrollment (bank transfer with proof / I Paid On-Site), admin payment verification and on-site recording,
sessions (create, auto Scheduled>Started>Ended by cron, manual early end), student I Attended / I Missed It with reasons and instant admin/instructor alerts,
progress against admin-configurable requirements, in-app notifications by role, instructor creation with temporary password and forced change, suspend/reactivate (immediate),
package/bank/location/contact management, audit log, role checks enforced in the Worker on every request.

## Not implemented yet
Video library and approval workflow, learning materials, licence processing, support tickets, FCM push and email delivery, session reminders, per-instructor student assignments,
reports, notification preferences, profile editing. The student nav omits sections that are not built.

## Notes
- All session times are entered and shown in Lagos time (WAT).
- Test the full flow on a staging Firebase project first (register, enroll, verify, create a session, let it run, respond). This code has not been run against live services.
- Admin list screens load up to roughly 1,000 records; add pagination when the school grows beyond that.

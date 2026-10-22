# Ambizcon Team Work Management Dashboard

Internal work-record and productivity system for the **Development**, **Marketing** and **Creative** teams, with an **Admin** command centre. Next.js 15 · React 19 · TypeScript (strict) · Tailwind · Framer Motion · React Three Fiber (login scene only) · Recharts · Supabase.

## Run it

```bash
npm install
npm run dev        # http://localhost:3100
```

**Demo mode (default).** With no Supabase variables set, the app runs against a seeded, browser-local backend that mirrors the database triggers (activity timeline, notifications, user log). The login page shows one-click demo accounts. *Settings → Reset* restores the seed data. Demo mode is **not secure** (cookie-based role, data in localStorage) and is only active when `NEXT_PUBLIC_SUPABASE_URL` is empty.

**Real mode (Supabase).**

1. Create a Supabase project; copy `.env.example` → `.env.local` and fill in URL, anon key, service-role key (server only).
2. Run `supabase/migrations/0001` … `0006` (in order) in the SQL editor (or `supabase db push`).
3. `SEED_PASSWORD='a-strong-password' npm run seed` creates demo users, clients and ~250 records.
4. Create real users from **Admin → Users** (invite email; no passwords are shared).

`npm run gen:sql` regenerates `0002`/`0003` from `src/lib/modules.ts` — the single declarative definition of every module (fields, table, status, expiry, animation).

## Architecture

| Area | Where |
|---|---|
| Module definitions (27 modules, fields, derived columns, expiry, completion animation) | `src/lib/modules.ts` |
| Generic CRUD page, table/card/gallery views, filters, form, drawer, timeline | `src/components/records/*`, `DataTable`, `FilterBar` |
| Module-specific widgets (calendar, mailer/ads/analytics charts, daily check, YouTube stats, expiry tiers) | `src/components/records/extras.tsx` |
| Auth, route + data authorization | `src/middleware.ts`, `src/lib/access.ts`, Postgres RLS |
| Data layer (Supabase and demo share one interface) | `src/lib/data/*` |
| Dashboards, Admin Overview, Users, Reports | `dashboards.tsx`, `admin.tsx` |
| Characters, completion scenes, motivation | `ThreeDCharacter.tsx`, `CompletionAnimation.tsx`, `MotivationPopup.tsx`, `lib/motivations.ts` |
| Admin user API (service role, admin-verified, zod-validated) | `src/app/api/admin/users/route.ts` |

## Security model

- **Supabase Auth** for sign-in; `profiles.team/role` decide access. Role is never chosen at login.
- **Route protection** in middleware (server-side) — changing the URL to another team's dashboard redirects back with an “access denied” toast.
- **Row Level Security** on every table: team members read/write only their team's tables; admins all; Marketing may *insert only* into Creative tables (the request workflow). Profile role/team/status changes are blocked for non-admins by a trigger.
- Activity logs, user log and notifications are written **only by SECURITY DEFINER triggers** — clients cannot forge them.
- Service-role key is used only in the admin API route and the seed script. Domain Access stores access status only — no passwords.
- Inputs validated with zod (client and API).

## Behaviour notes

- Status colours are tints/shades of `#13798A`, `#8BA277`, `#95A575`; urgency is shown with darker fill, icons and a pulse rather than extra hues.
- “Overdue” is calculated automatically (open + past its due/expiry date). Expiry modules compute days remaining and Healthy / Warning / Critical / Expired, with tiers at 90/60/30/15/7 days.
- Daily motivation: one slogan per user per day; scheduled message wins, otherwise the team + all-team pool is cycled before any repeat (`pickMotivation`).
- Sound: drop `complete.mp3`, `notify.mp3`, `welcome.mp3` into `public/sounds` and enable *Settings → Sound effects*.
- Characters are layered SVG with pointer-tilt; WebGL is used only on the login page and is code-split.

## Scheduled reminders (expiry and task due/overdue)

`0006_scheduled_reminders.sql` adds `public.run_reminders()`. It reads the admin-configured `expiry_alert_days` and `company_timezone` settings, notifies the responsible employee and all admins on each threshold day (weekly once expired), notifies assignees of due/overdue tasks, and de-duplicates through `reminder_log`, so it is safe to run repeatedly. Completed and cancelled records are skipped. Only the service role can execute it.

Pick one way to run it daily:
- **Vercel Cron** (included in `vercel.json`): set `CRON_SECRET`, `SUPABASE_SERVICE_ROLE_KEY` and the Supabase URL; Vercel calls `GET /api/cron/reminders` with `Authorization: Bearer $CRON_SECRET`.
- **pg_cron** on Supabase: `select cron.schedule('ambizcon-reminders', '30 0 * * *', $$select public.run_reminders()$$);`

Verified by `npm run test:sql` against an in-process Postgres (it is *not* verified against a live Supabase project). Email delivery is not part of this job.

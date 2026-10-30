# Budget v2

## Local run

Requires Node 20+ and PostgreSQL. Set `DATABASE_URL`, `JWT_SECRET` (at least 32 characters), `ADMIN_EMAIL`, and `ADMIN_PASSWORD` in the environment. `ADMIN_EMAIL` is promoted to admin when the server starts. On first boot the service creates the tables and admin account. Run `npm install` then `npm start`.

The Express service serves the frontend and API from the same origin. Health check: `/api/health`. Admin console: `/admin.html`.

## Free-tier deployment plan

Use Neon Postgres plus one Render web service for the combined frontend and API. Terrence must create/own the Neon and Render accounts, create the Neon database, connect the source repository to Render, and add the environment variables in Render's dashboard. Render free instances can sleep when idle. Do not commit secrets.

## Features and data

Passwords use bcrypt. User data is isolated by account. The admin dashboard shows account metadata, usage counters, and bug report messages; it does not show budget entry content. Budget entries and balances are stored as ordinary server-side data, not end-to-end encrypted. Offline fallback keeps the local browser copy and attempts sync when connectivity returns. Bug reports are stored in the app's own Postgres database.

## Admin bootstrap

Use `ADMIN_EMAIL=terrenceuzoma4@gmail.com`. Set a strong, unique `ADMIN_PASSWORD` in Render's environment settings. The account is created/promoted at service startup. Terrence can then sign in on the app and open `/admin.html`.

## WatchUp

WatchUp's public website and signup flow are reachable and advertise a free plan, but its SDK package, API documentation, project key, and integration instructions were not verified. No unverified SDK is included. The built-in bug-report endpoint and admin dashboard are the working feedback path. WatchUp signup still requires a chosen password and the signup page's required name field; no account was created.

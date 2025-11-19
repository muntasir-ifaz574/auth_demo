# Auth Demo (Go + Supabase + Vercel)

This project delivers a production-ready authentication API written in Go. It implements:

- Signup with email/full name/phone/password, 6-digit OTP verification, JWT issuance (30-day expiry)
- OTP resend with 3-minute validity window
- Password-based sign-in followed by OTP verification and JWT response
- Forgot password (email OTP + password reset)
- Authenticated password updates

The API is designed for deployment to Vercel and uses Supabase (Postgres) for persistence.

## Getting started locally

1. **Environment**
   ```bash
   # macOS example
   cp .env.example .env
   # fill in DATABASE_URL, JWT_SECRET, and email settings
   ```

2. **Run migrations** against your Supabase/Postgres instance:
   ```sql
   \i docs/schema.sql
   ```

3. **Start the API**
   ```bash
   go run ./cmd/server
   ```

4. **Test endpoints** using any HTTP client:
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/signup \
     -H 'Content-Type: application/json' \
     -d '{"email":"alice@example.com","fullName":"Alice","phoneNumber":"+8801...","password":"Sup3rSecret!"}'
   ```

## Deploying on Vercel

Vercel builds Go apps as serverless functions. The default `vercel.json` (see below) routes all requests to `cmd/api`. Steps:

1. **Create Supabase project** and copy the `DATABASE_URL` from the dashboard.
2. **Provision secrets** in Vercel:
   ```bash
   vercel env add DATABASE_URL
   vercel env add JWT_SECRET
   vercel env add EMAIL_PROVIDER # log | smtp
   # add the rest from .env.example
   ```
3. **Deploy**
   ```bash
   vercel --prod
   ```

## Environment variables

See `.env.example` for the full list. Key values:

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Supabase Postgres connection string |
| `JWT_SECRET` | HMAC secret used to sign JWTs |
| `JWT_ISSUER` | Optional issuer claim (default `auth-demo`) |
| `JWT_EXPIRY_DAYS` | Token expiry in days (default `30`) |
| `OTP_TTL_MINUTES` | OTP validity window (default `3`) |
| `EMAIL_PROVIDER` | `log` (stdout) or `smtp` |
| `EMAIL_FROM`, `EMAIL_SMTP_*` | SMTP credentials when provider=`smtp` |

## Database schema summary

- `users`: stores verified user accounts.
- `otp_codes`: stores transient OTP codes and serialized payloads for signup/login/password reset flows.

The full SQL lives in `docs/schema.sql`.

## API overview

| Endpoint | Method | Description |
| --- | --- | --- |
| `/api/v1/auth/signup` | POST | Start signup, generate OTP |
| `/api/v1/auth/signup/verify` | POST | Verify OTP, create user, return JWT |
| `/api/v1/auth/signup/resend` | POST | Resend signup OTP |
| `/api/v1/auth/signin` | POST | Validate password, send OTP |
| `/api/v1/auth/signin/verify` | POST | Verify OTP, return JWT |
| `/api/v1/auth/signin/resend` | POST | Resend signin OTP |
| `/api/v1/auth/password/forgot` | POST | Send OTP for password reset |
| `/api/v1/auth/password/forgot/verify` | POST | Verify OTP + new password |
| `/api/v1/auth/password/forgot/resend` | POST | Resend password-reset OTP |
| `/api/v1/auth/password` | PATCH | Authenticated password change (JWT required) |

JSON responses follow the examples in `internal/handlers/auth/handler.go`.

## Testing tips

- Use the `log` email provider for local/dev to inspect OTPs in stdout.
- OTPs expire after 3 minutes; resending invalidates previous codes.
- JWTs last 30 days; adjust via `JWT_EXPIRY_DAYS`.
- When hosting on Vercel, tail logs (`vercel logs`) to confirm OTP emails are sent.

## Future enhancements

- Add rate limiting for OTP endpoints.
- Persist resend counts and enforce max attempts per window.
- Plug in a transactional email provider (Resend, Postmark) via a new `email.Sender` implementation.

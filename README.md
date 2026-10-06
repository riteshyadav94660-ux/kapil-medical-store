# Kapil Medical — Secure Admin Starter

## Run locally
Requires Node.js 20+.

1. Extract the ZIP.
2. Open a terminal in the extracted folder.
3. Set environment variables BEFORE starting:
   - ADMIN_USERNAME
   - ADMIN_PASSWORD
   - SESSION_SECRET
4. Run `npm install`
5. Run `npm start`
6. Store: http://localhost:3000
7. Admin: http://localhost:3000/admin

If environment variables are not set, the code uses placeholders and prints a warning. Do NOT deploy with those placeholders.

## Security included
- bcrypt password hashing
- server-side session authentication
- HTTP-only SameSite session cookie
- protected admin APIs
- login rate limiting
- API rate limiting
- Helmet security headers

## Still required before public production
- HTTPS
- secure session store (not Express MemoryStore)
- CSRF protection
- stronger validation and audit logging
- production database/backups
- secure prescription upload/storage and access controls
- real Razorpay server-side payment verification/webhooks
- courier integration
- applicable pharmacy/legal compliance

Never put payment secrets or admin passwords into frontend JavaScript.

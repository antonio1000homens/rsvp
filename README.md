# RSVP

Security-conscious dinner-party RSVP authentication app. Static assets live in a private S3 bucket and are served by a Node.js Lambda. Guest records, one-time challenges, and passkey public credentials use a small provisioned DynamoDB table.

The Lambda Function URL is technically public but rejects every request that does not carry the secret origin header. The Cloudflare Worker is the only component given that secret. The direct Function URL is deliberately not committed to this repository.

## Local checks

```bash
npm ci
npm run build
npm test
npm run check:shell
cfn-lint cloudformation/rsvp.yaml cloudformation/bootstrap-github.yaml
```

## First deployment

The bootstrap creates the required SSM SecureString parameters, a repository-specific GitHub OIDC role, and a restricted CloudFormation service role. Secret values are generated locally and are never printed or passed as CloudFormation parameters.

```bash
AWS_PROFILE=windsor bash scripts/bootstrap-aws.sh
AWS_PROFILE=windsor npm run whatsapp:configure
AWS_PROFILE=windsor npm run captcha:configure
AWS_PROFILE=windsor bash scripts/deploy-aws.sh
AWS_PROFILE=windsor bash scripts/verify-aws.sh
```

The bootstrap also creates the GitHub `production` environment, restricts it to `master`, and sets these repository variables:

- `AWS_ROLE_TO_ASSUME`
- `AWS_CLOUDFORMATION_ROLE_ARN`
- `CODE_BUCKET`

Pull requests build, test, and lint without AWS credentials. Pushes to `master` deploy with short-lived GitHub OIDC credentials.

## Infrastructure

- Main stack: `rsvp`
- Bootstrap stack: `rsvp-github-bootstrap`
- Region: `eu-west-2`
- Site bucket: `rsvp-243857182133-eu-west-2-site`
- DynamoDB table: `rsvp`
- Lambda: `rsvp-app`

Cloudflare routing and Access configuration are intentionally separate from this AWS deployment.

## Cloudflare and TLS

`calcada2026.pt` and `www.calcada2026.pt` are configured as Worker custom domains. The Worker replaces any client-supplied origin credential with its secret value and proxies only to the expected HTTPS Lambda Function URL in `eu-west-2`.

Once the domain is active in Cloudflare and delegated to its assigned nameservers, initialize the Worker secrets and deploy:

```bash
AWS_PROFILE=windsor bash scripts/deploy-cloudflare.sh --configure-secrets
bash scripts/verify-cloudflare.sh
```

TLS is end-to-end:

- Cloudflare automatically provisions and renews the browser-facing certificate.
- Worker subrequests use the Lambda Function URL over validated HTTPS.
- HTTP requests receive a permanent `308` HTTPS redirect.
- HTTPS responses include HSTS without preloading the domain.

Subsequent GitHub deployments need a narrowly scoped `CLOUDFLARE_API_TOKEN` secret in the existing `production` environment. That token should be limited to Worker script and route editing for the Windsor account and `calcada2026.pt` zone.

## Landing-page CAPTCHA

The guest directory is not loaded until Cloudflare Turnstile has been completed. The browser receives only the public site key. Lambda sends the one-use token to Cloudflare's Siteverify endpoint and, only after successful validation, issues a short-lived signed CAPTCHA gate cookie. The Turnstile secret never reaches the browser, Worker, repository, or logs.

Create a Turnstile widget in the Cloudflare dashboard for `calcada2026.pt` and `www.calcada2026.pt`, then configure both keys interactively:

```bash
AWS_PROFILE=windsor npm run captcha:configure
```

The site key is stored as `/rsvp/turnstile-site-key` (String); the server secret is stored as `/rsvp/turnstile-secret` (SecureString). The command masks the secret while you enter it and never prints it. Turnstile tokens are five-minute, single-use values, so the backend validates them server-side before returning guest names.

## Guest whitelist

Guest identity uses a public contact name.

Add a guest:

```bash
aws sso login --profile windsor
AWS_PROFILE=windsor npm run guest:add
```

The command prompts for the contact name and stores no phone number. Duplicate enabled contact names are rejected.

List or disable enabled guests:

```bash
AWS_PROFILE=windsor npm run guest:list
AWS_PROFILE=windsor npm run guest:disable
```

Disabling removes the nickname from the public directory, revokes existing sessions, and retains passkeys so that the guest can be re-enabled later. Keep any private mapping of nicknames to phone numbers outside this public repository.

Friends who are not yet listed should first join the WhatsApp group. The host can then add them to the phone contacts and run the contact-sync automation. Once the contact is seeded, the name appears in the public list as an unconfirmed contact.

An unconfirmed contact selects their name from the list. The site creates a five-minute WhatsApp challenge and a QR/deep link containing:

```text
VALIDATION contact=Ana%20Costa&nonce=<opaque-nonce>&sig=<HMAC-SHA-256-signature>
```

The browser never chooses or edits this message. Tasker should verify that the WhatsApp sender is a contact and forward the contact name plus the exact message to `/api/phone/register`:

```text
POST https://calcada2026.pt/api/phone/register
Authorization: Bearer <phone-webhook-secret>
Content-Type: application/json
```

```json
{"sender":"Ana Costa","message":"VALIDATION contact=Ana%20Costa&nonce=<opaque-nonce>&sig=<signature>"}
```

The contact field is URL-encoded, so Tasker can extract and URL-decode it without Base64 padding or JSON parsing. The nonce and signature are opaque strings and must be forwarded unchanged. The signature is an HMAC-SHA-256 over the exact `contact=...&nonce=...` portion using the private `/rsvp/validation-secret` SecureString. The backend verifies the nonce, stored contact, expiry, and sender name before marking the existing guest `confirmed`. Names are matched case-insensitively with accents and cedillas ignored. The private phone lookup HMAC remains unchanged; plaintext phone numbers are not stored. The contact must then create a passkey. Confirmed contacts use passkey login only.

## WhatsApp Business app configuration

This project does **not** use Meta's WhatsApp API or Meta webhooks. The QR code opens a normal `wa.me` link addressed to the WhatsApp Business app number. A manually approved Tasker or MacroDroid action calls the RSVP backend.

Configure the destination number:

```bash
AWS_PROFILE=windsor npm run whatsapp:configure
```

The command validates E.164 format and writes the public number to the `/rsvp/whatsapp-number` SSM String parameter. The backend removes `+` when constructing the `wa.me` URL.

The bootstrap creates `/rsvp/phone-webhook-secret` as a random SSM SecureString for the registration callback. Copy it to the local clipboard without printing it:

```bash
AWS_PROFILE=windsor npm run whatsapp:copy-secret
```

Paste it into the private Tasker configuration, then clear the clipboard. After explicitly approving the contact match, forward the complete `VALIDATION ...` message unchanged to `/api/phone/register` with the validated contact name as `sender`. The backend returns `204` after confirming the existing guest; replayed, expired, altered, or mismatched challenges are rejected. The waiting browser then offers passkey creation. Private passkey material never leaves the guest's authenticator; DynamoDB stores only public keys and counters.

Rotate a compromised phone webhook secret with:

```bash
AWS_PROFILE=windsor npm run whatsapp:rotate-secret
```

This immediately invalidates the old value and copies the replacement to the clipboard. Update Tasker or MacroDroid before approving another login.

The SSM parameters have separate purposes:

- `/rsvp/origin-secret` authenticates Cloudflare to the Lambda origin.
- `/rsvp/session-secret` signs short-lived browser cookies.
- `/rsvp/phone-webhook-secret` authenticates the phone automation.
- `/rsvp/validation-secret` signs and verifies registration WhatsApp payloads; copy this only to the registration automation that constructs or validates the message.
- `/rsvp/whatsapp-number` is the public destination number used in the QR link.
- `/rsvp/turnstile-site-key` is the public landing-page widget key.
- `/rsvp/turnstile-secret` is the private server-side validation key.

Do not put SSM values, phone numbers, callback payloads, cookies, or passkey data in source files, GitHub variables, issue comments, or deployment logs.

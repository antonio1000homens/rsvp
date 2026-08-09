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

Each guest has two names: `nickname` is the public name shown on the site; `sender` is the private WhatsApp sender name used by Tasker to validate the registration. They may be the same, but they are stored separately.

Add a guest:

```bash
aws sso login --profile windsor
AWS_PROFILE=windsor npm run guest:add
```

The command prompts for the public nickname and WhatsApp sender name and stores no phone number. Duplicate enabled nicknames are rejected.

List or disable enabled guests:

```bash
AWS_PROFILE=windsor npm run guest:list
AWS_PROFILE=windsor npm run guest:disable
AWS_PROFILE=windsor npm run guest:mark-added
```

## Groups and memberships

Groups are host-managed and a guest can be assigned to any number of them. A group has a stable slug derived from its name; memberships are separate DynamoDB records, so assigning a guest to a second group never replaces the first assignment or their passkeys.

Create each group, then add the relevant guests. The public directory asks guests to choose a group and only shows that group's members.

```bash
AWS_PROFILE=windsor npm run group:add
AWS_PROFILE=windsor npm run group:add-member
```

Existing installations remain compatible while no groups exist: the directory continues to show all enabled guests. Once groups are created, assign every guest who should be visible in a group; unassigned guests remain enabled but are not shown through a group selection.

## RSVP availability and preferences

After CAPTCHA and, when enabled, trivia validation, the guest selects their existing name. If they already have a passkey, they use it and can view or edit their saved response. If they have already submitted a response but do not have a passkey, the site says that a response exists and offers WhatsApp validation to retrieve it; after approval, the saved choices are loaded and can be edited. Guests without a previous response see the availability form. Only after the form is completed does it show a QR code and device link for WhatsApp.

The WhatsApp message is a signed one-time validation request associated with the selected guest. For a new response it also carries the completed choices in the pending server-side challenge; for retrieval it carries no voting data. Tasker verifies the WhatsApp sender is the expected contact, then forwards the sender and the exact message to `POST /api/phone/register`. The backend validates the signature, nonce, sender, and expiry, then either saves the pending response or authorizes the browser to retrieve the existing response. Tasker does not need to know which operation is taking place. The site then offers optional passkey creation, which lets the guest fetch and edit their answer later.

The response also records the preference group: `18+`, `+1s`, or `Famílias`. Participant count defaults to one. Guests can select `Não posso em nenhuma data`; this is stored explicitly and removes the requirement to select a date. Guests can select one or more proposed restaurants; responses store these as the `restaurantChoices` array. Older responses containing the former single `restaurantChoice` field remain readable. Passkeys remain available as an optional way to return to and edit a saved response in the browser. Dietary restrictions are returned only to an authenticated passkey session; the post-trivia landing page shows anonymous aggregate availability, meal, and restaurant proposal totals weighted by participant count.

The availability labels are configured at deploy time. Use real dates or day names before production deployment:

```bash
AWS_PROFILE=windsor AVAILABILITY_DAYS='19 December 2026,20 December 2026,21 December 2026,22 December 2026,23 December 2026' bash scripts/deploy-aws.sh
```

`AVAILABILITY_DAYS` must contain exactly five distinct comma-separated labels. It defaults to 19–23 December 2026.

## Event administration

Grant a confirmed guest access to the in-app administration section:

```bash
AWS_PROFILE=windsor npm run guest:grant-admin
```

The administrator can view the fixed event dates, add or remove restaurant proposals (one per line), configure the trivia questions and accepted answers, and see group membership totals. New restaurant proposals automatically appear as checkboxes in both registration forms. Trivia is disabled by default, so an administrator can sign in and configure it in the browser. Enter one question per line as `Question | accepted answer, alternative answer`; creating the first question enables trivia automatically. It can later be disabled with the “Usar perguntas de validação” setting. Group creation and membership assignment remain host commands (`group:add` and `group:add-member`) so a public browser session cannot alter invitations.

Disabling removes the nickname from the public directory, revokes existing sessions, and retains passkeys so that the guest can be re-enabled later. Keep any private mapping of nicknames to phone numbers outside this public repository.

Friends who are not yet listed should first join the WhatsApp group. The host can then add them to the phone contacts and seed a record with both names. Once seeded, the nickname appears in the public list as an unconfirmed guest.

When a selected guest without a passkey completes the availability form, the site creates a five-minute WhatsApp challenge and only then shows its QR/deep link:

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

The `contact` field in the validation message is URL-encoded for compatibility with the existing Tasker flow. The nonce and signature are opaque strings and must be forwarded unchanged. The signature is an HMAC-SHA-256 over the exact `contact=...&nonce=...` portion using the private `/rsvp/validation-secret` SecureString. The backend verifies the nonce, stored `sender`, expiry, and WhatsApp sender name before confirming the guest and saving the response selected before the QR code was shown. Names are matched case-insensitively with accents and cedillas ignored. It then offers, but does not require, passkey creation.

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

Paste it into the private Tasker configuration, then clear the clipboard. After explicitly approving the contact match, forward the complete `VALIDATION ...` message unchanged to `/api/phone/register` with the validated contact name as `sender`. The endpoint returns `202` once the message is accepted into the private RSVP queue. A dedicated worker then verifies and stores it; the browser shows a waiting indicator and polls the registration status until processing finishes. Tasker should retry only network or 5xx failures, never a `202` response.


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

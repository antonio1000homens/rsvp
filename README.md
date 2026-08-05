# RSVP

Security-conscious dinner-party RSVP skeleton. Static assets live in a private S3 bucket and are served by a Node.js Lambda. RSVP persistence uses a small provisioned DynamoDB table.

The Lambda Function URL is technically public but rejects every request that does not carry the secret origin header. The future Cloudflare Worker will be the only component given that secret. The direct Function URL is deliberately not committed to this repository.

## Local checks

```bash
npm ci
npm run build
npm test
npm run check:shell
cfn-lint cloudformation/rsvp.yaml cloudformation/bootstrap-github.yaml
```

## First deployment

The bootstrap creates three SSM SecureString parameters, a repository-specific GitHub OIDC role, and a restricted CloudFormation service role. Secret values are generated locally and are never printed or passed as CloudFormation parameters.

```bash
AWS_PROFILE=windsor bash scripts/bootstrap-aws.sh
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

## Guest usernames and passwords

The current `/api/*` implementation is intentionally a `501` placeholder; no guest credentials are stored yet. When RSVP authentication is implemented, store one record per invitee in DynamoDB and never store a plaintext password or passphrase.

Recommended credential record:

- `pk`: `GUEST#<stable-id>`
- `sk`: `PROFILE`
- `contactLookup`: HMAC-SHA-256 of the normalized email address or phone number, using the `/rsvp/contact-pepper` SSM SecureString as the key
- `passwordHash`: a slow password hash such as Argon2id (or bcrypt if Argon2id is unavailable), including its salt and cost parameters
- non-secret profile fields such as display name, invitation status, and RSVP response

Use the contact lookup GSI to find the record, then verify the supplied passphrase against `passwordHash`. Do not use the contact value itself as a DynamoDB key, and do not log contacts, passphrases, hashes, SSM values, cookies, or complete request bodies. Normalize contacts consistently before hashing (lowercase and trim email addresses; use a canonical E.164 representation for phone numbers).

The SSM parameters created by `scripts/bootstrap-aws.sh` have separate purposes:

- `/rsvp/contact-pepper` protects contact lookups and must remain a SecureString.
- `/rsvp/session-secret` signs short-lived, HTTP-only, Secure, SameSite session cookies or tokens.
- `/rsvp/origin-secret` is only for the Cloudflare-to-Lambda origin check; it is not a guest password.

Create or rotate guest credentials through a controlled administrative script or AWS Console workflow that writes only the password hash and HMAC lookup value. Do not put guest passwords in CloudFormation parameters, GitHub variables, source files, issue comments, or deployment logs. If a password is sent to a guest, send it through a separate private channel and require a reset after first login.

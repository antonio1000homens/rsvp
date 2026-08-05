#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${ROOT_DIR}/wrangler.jsonc"
REGION="${AWS_REGION:-eu-west-2}"
STACK_NAME="${STACK_NAME:-rsvp}"
PROFILE_NAME="${AWS_PROFILE:-windsor}"
CONFIGURE_SECRETS='false'

if [ "${1:-}" = '--configure-secrets' ]; then
  CONFIGURE_SECRETS='true'
elif [ -n "${1:-}" ]; then
  echo "Usage: $0 [--configure-secrets]" >&2
  exit 2
fi

command -v npx >/dev/null 2>&1 || { echo 'Missing required command: npx' >&2; exit 1; }

wrangler_cli() {
  npx --no-install wrangler "$@"
}

cd "${ROOT_DIR}"
wrangler_cli deploy --config "${CONFIG_FILE}"

if [ "${CONFIGURE_SECRETS}" = 'true' ]; then
  command -v aws >/dev/null 2>&1 || { echo 'Missing required command: aws' >&2; exit 1; }

  AWS_PROFILE="${PROFILE_NAME}" aws cloudformation describe-stacks \
    --region "${REGION}" \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='FunctionUrl'].OutputValue | [0]" \
    --output text \
    | wrangler_cli secret put ORIGIN_URL --config "${CONFIG_FILE}"

  AWS_PROFILE="${PROFILE_NAME}" aws ssm get-parameter \
    --region "${REGION}" \
    --name /rsvp/origin-secret \
    --with-decryption \
    --query Parameter.Value \
    --output text \
    | wrangler_cli secret put ORIGIN_SECRET --config "${CONFIG_FILE}"
fi

wrangler_cli secret list --config "${CONFIG_FILE}"

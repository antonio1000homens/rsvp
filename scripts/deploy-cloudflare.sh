#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${ROOT_DIR}/wrangler.jsonc"
REGION="${AWS_REGION:-eu-west-2}"
STACK_NAME="${STACK_NAME:-rsvp}"
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  PROFILE_NAME=''
else
  PROFILE_NAME="${AWS_PROFILE:-windsor}"
fi
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

aws_cli() {
  if [ -n "${PROFILE_NAME}" ]; then
    aws --profile "${PROFILE_NAME}" --region "${REGION}" "$@"
  else
    aws --region "${REGION}" "$@"
  fi
}

cd "${ROOT_DIR}"

if [ "${CONFIGURE_SECRETS}" = 'true' ]; then
  command -v aws >/dev/null 2>&1 || { echo 'Missing required command: aws' >&2; exit 1; }

  api_origin_url="$(aws_cli cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='ApiFunctionUrl'].OutputValue | [0]" \
    --output text)"
  site_origin_url="$(aws_cli cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='SiteFunctionUrl'].OutputValue | [0]" \
    --output text)"
  origin_secret="$(aws_cli ssm get-parameter \
    --name /rsvp/origin-secret \
    --with-decryption \
    --query Parameter.Value \
    --output text)"
  [ -n "${api_origin_url}" ] && [ "${api_origin_url}" != 'None' ] || { echo 'Missing API Function URL output' >&2; exit 1; }
  [ -n "${site_origin_url}" ] && [ "${site_origin_url}" != 'None' ] || { echo 'Missing site Function URL output' >&2; exit 1; }
  [ -n "${origin_secret}" ] && [ "${origin_secret}" != 'None' ] || { echo 'Missing RSVP origin secret' >&2; exit 1; }

  printf '%s' "${api_origin_url}" | wrangler_cli secret put API_ORIGIN_URL --config "${CONFIG_FILE}"
  printf '%s' "${site_origin_url}" | wrangler_cli secret put SITE_ORIGIN_URL --config "${CONFIG_FILE}"
  printf '%s' "${origin_secret}" | wrangler_cli secret put ORIGIN_SECRET --config "${CONFIG_FILE}"
  unset origin_secret
fi

wrangler_cli deploy --config "${CONFIG_FILE}"

wrangler_cli secret list --config "${CONFIG_FILE}"

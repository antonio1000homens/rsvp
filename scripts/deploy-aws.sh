#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-eu-west-2}"
STACK_NAME="${STACK_NAME:-rsvp}"
BOOTSTRAP_STACK_NAME="${BOOTSTRAP_STACK_NAME:-rsvp-github-bootstrap}"
CODE_BUCKET="${CODE_BUCKET:-aws2022-lambda-code}"
TEMPLATE_FILE="${ROOT_DIR}/cloudformation/rsvp.yaml"

if [ -n "${GITHUB_ACTIONS:-}" ]; then
  PROFILE_NAME=''
else
  PROFILE_NAME="${AWS_PROFILE:-windsor}"
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

error() {
  echo "ERROR: $*" >&2
  exit 1
}

for command_name in aws npm zip curl; do
  command -v "${command_name}" >/dev/null 2>&1 || error "Missing required command: ${command_name}"
done

aws_cli() {
  if [ -n "${PROFILE_NAME}" ]; then
    aws --profile "${PROFILE_NAME}" --region "${REGION}" "$@"
  else
    aws --region "${REGION}" "$@"
  fi
}

service_role_arn="${AWS_CLOUDFORMATION_ROLE_ARN:-}"
if [ -z "${service_role_arn}" ]; then
  service_role_arn="$(aws_cli cloudformation describe-stacks \
    --stack-name "${BOOTSTRAP_STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='CloudFormationServiceRoleArn'].OutputValue | [0]" \
    --output text)"
fi
[ -n "${service_role_arn}" ] && [ "${service_role_arn}" != "None" ] || error "Missing CloudFormation service role ARN. Run scripts/bootstrap-aws.sh first."

cd "${ROOT_DIR}"
npm ci
npm run build

cp "${ROOT_DIR}/dist/lambda/index.mjs" "${TEMP_DIR}/index.mjs"
(
  cd "${TEMP_DIR}"
  zip -q lambda.zip index.mjs
)

if [ -n "${GITHUB_SHA:-}" ]; then
  deploy_id="${GITHUB_SHA}"
elif git rev-parse HEAD >/dev/null 2>&1; then
  deploy_id="$(git rev-parse HEAD)"
else
  deploy_id="$(date -u +%Y%m%d%H%M%S)"
fi

function_code_key="rsvp/${deploy_id}/lambda.zip"
aws_cli s3 cp "${TEMP_DIR}/lambda.zip" "s3://${CODE_BUCKET}/${function_code_key}" --only-show-errors

aws_cli cloudformation validate-template --template-body "file://${TEMPLATE_FILE}" >/dev/null
aws_cli cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE_FILE}" \
  --role-arn "${service_role_arn}" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    CodeBucket="${CODE_BUCKET}" \
    FunctionCodeKey="${function_code_key}"

site_bucket="$(aws_cli cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='SiteBucketName'].OutputValue | [0]" \
  --output text)"

aws_cli s3 sync "${ROOT_DIR}/dist/frontend" "s3://${site_bucket}/" \
  --delete \
  --exclude index.html \
  --cache-control 'public,max-age=31536000,immutable' \
  --only-show-errors
aws_cli s3 cp "${ROOT_DIR}/dist/frontend/index.html" "s3://${site_bucket}/index.html" \
  --cache-control 'no-cache' \
  --content-type 'text/html; charset=utf-8' \
  --only-show-errors

aws_cli cloudformation update-termination-protection \
  --stack-name "${STACK_NAME}" \
  --enable-termination-protection >/dev/null

function_url="$(aws_cli cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='FunctionUrl'].OutputValue | [0]" \
  --output text)"
http_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${function_url}")"
[ "${http_status}" = "403" ] || error "Expected an unauthenticated Function URL request to return 403, got ${http_status}."

aws_cli cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs' \
  --output table

echo "RSVP AWS deployment completed successfully."

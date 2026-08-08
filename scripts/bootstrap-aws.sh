#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="${AWS_REGION:-eu-west-2}"
PROFILE_NAME="${AWS_PROFILE:-windsor}"
ACCOUNT_ID="${AWS_ACCOUNT_ID:-243857182133}"
STACK_NAME="${BOOTSTRAP_STACK_NAME:-rsvp-github-bootstrap}"
REPOSITORY="${GITHUB_REPOSITORY:-antonio1000homens/rsvp}"
ENVIRONMENT="${GITHUB_ENVIRONMENT:-production}"
CODE_BUCKET="${CODE_BUCKET:-aws2022-lambda-code}"
TEMPLATE_FILE="${ROOT_DIR}/cloudformation/bootstrap-github.yaml"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

error() {
  echo "ERROR: $*" >&2
  exit 1
}

for command_name in aws gh openssl python3; do
  command -v "${command_name}" >/dev/null 2>&1 || error "Missing required command: ${command_name}"
done

aws_cli() {
  aws --profile "${PROFILE_NAME}" --region "${REGION}" "$@"
}

if ! aws_cli sts get-caller-identity >/dev/null 2>&1; then
  echo "AWS SSO session is not active; starting login for profile ${PROFILE_NAME}."
  aws sso login --profile "${PROFILE_NAME}"
fi

actual_account="$(aws_cli sts get-caller-identity --query Account --output text)"
[ "${actual_account}" = "${ACCOUNT_ID}" ] || error "Expected AWS account ${ACCOUNT_ID}, got ${actual_account}."

oidc_provider="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
aws_cli iam get-open-id-connect-provider --open-id-connect-provider-arn "${oidc_provider}" >/dev/null

create_secure_parameter_if_missing() {
  local parameter_name="$1"
  local input_file="${TEMP_DIR}/parameter.json"
  local generated_value

  if aws_cli ssm get-parameter --name "${parameter_name}" >/dev/null 2>&1; then
    echo "Secure parameter already exists: ${parameter_name}"
    return
  fi

  generated_value="$(openssl rand -hex 32)"
  PARAMETER_NAME="${parameter_name}" python3 -c '
import json
import os
import sys

value = sys.stdin.read().strip()
with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({
        "Name": os.environ["PARAMETER_NAME"],
        "Description": "RSVP application secret generated during bootstrap",
        "Type": "SecureString",
        "Tier": "Standard",
        "Value": value,
    }, output)
' "${input_file}" <<<"${generated_value}"
  chmod 600 "${input_file}"
  aws_cli ssm put-parameter --cli-input-json "file://${input_file}" >/dev/null
  : >"${input_file}"
  unset generated_value
  echo "Created secure parameter: ${parameter_name}"
}

create_secure_parameter_if_missing /rsvp/origin-secret
create_secure_parameter_if_missing /rsvp/session-secret
create_secure_parameter_if_missing /rsvp/phone-webhook-secret
create_secure_parameter_if_missing /rsvp/validation-secret

aws_cli cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE_FILE}" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    GitHubOidcProviderArn="${oidc_provider}" \
    GitHubRepository="${REPOSITORY}" \
    GitHubEnvironment="${ENVIRONMENT}" \
    CodeBucket="${CODE_BUCKET}"

deploy_role_arn="$(aws_cli cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='GitHubDeployRoleArn'].OutputValue | [0]" \
  --output text)"
service_role_arn="$(aws_cli cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFormationServiceRoleArn'].OutputValue | [0]" \
  --output text)"

printf '%s\n' '{"wait_timer":0,"prevent_self_review":false,"reviewers":[],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}' \
  | gh api --method PUT "repos/${REPOSITORY}/environments/${ENVIRONMENT}" --input - >/dev/null

if ! gh api "repos/${REPOSITORY}/environments/${ENVIRONMENT}/deployment-branch-policies" \
  --jq '.branch_policies[] | select(.name == "master") | .name' | grep -qx master; then
  printf '%s\n' '{"name":"master","type":"branch"}' \
    | gh api --method POST "repos/${REPOSITORY}/environments/${ENVIRONMENT}/deployment-branch-policies" --input - >/dev/null
fi

gh variable set AWS_ROLE_TO_ASSUME --repo "${REPOSITORY}" --body "${deploy_role_arn}"
gh variable set AWS_CLOUDFORMATION_ROLE_ARN --repo "${REPOSITORY}" --body "${service_role_arn}"
gh variable set CODE_BUCKET --repo "${REPOSITORY}" --body "${CODE_BUCKET}"

aws_cli cloudformation update-termination-protection \
  --stack-name "${STACK_NAME}" \
  --enable-termination-protection >/dev/null

echo "Bootstrap complete. GitHub OIDC and CloudFormation roles are scoped to ${REPOSITORY}:${ENVIRONMENT}."

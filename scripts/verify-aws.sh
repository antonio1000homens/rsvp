#!/usr/bin/env bash

set -euo pipefail

REGION="${AWS_REGION:-eu-west-2}"
STACK_NAME="${STACK_NAME:-rsvp}"

if [ -n "${GITHUB_ACTIONS:-}" ]; then
  PROFILE_NAME=''
else
  PROFILE_NAME="${AWS_PROFILE:-windsor}"
fi

aws_cli() {
  if [ -n "${PROFILE_NAME}" ]; then
    aws --profile "${PROFILE_NAME}" --region "${REGION}" "$@"
  else
    aws --region "${REGION}" "$@"
  fi
}

output_value() {
  local key="$1"
  aws_cli cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='${key}'].OutputValue | [0]" \
    --output text
}

stack_status="$(aws_cli cloudformation describe-stacks --stack-name "${STACK_NAME}" --query 'Stacks[0].StackStatus' --output text)"
case "${stack_status}" in
  CREATE_COMPLETE|UPDATE_COMPLETE) ;;
  *) echo "Unexpected stack status: ${stack_status}" >&2; exit 1 ;;
esac

termination_protection="$(aws_cli cloudformation describe-stacks --stack-name "${STACK_NAME}" --query 'Stacks[0].EnableTerminationProtection' --output text)"
[ "${termination_protection}" = "True" ]

site_bucket="$(output_value SiteBucketName)"
table_name="$(output_value TableName)"
function_name="$(output_value FunctionName)"
function_url="$(output_value FunctionUrl)"
phone_queue_url="$(output_value PhoneRegistrationQueueUrl)"
phone_processor_arn="$(output_value PhoneProcessorFunctionArn)"
summary_queue_url="$(output_value SummaryQueueUrl)"
summary_processor_arn="$(output_value SummaryProcessorFunctionArn)"

public_access="$(aws_cli s3api get-public-access-block --bucket "${site_bucket}" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text)"
[ "${public_access}" = $'True\tTrue\tTrue\tTrue' ]

table_config="$(aws_cli dynamodb describe-table --table-name "${table_name}" --query 'Table.[TableStatus,BillingModeSummary.BillingMode,ProvisionedThroughput.ReadCapacityUnits,ProvisionedThroughput.WriteCapacityUnits,DeletionProtectionEnabled,SSEDescription.Status]' --output text)"
[ "${table_config}" = $'ACTIVE\tPAY_PER_REQUEST\t0\t0\tTrue\tENABLED' ]

ttl_status="$(aws_cli dynamodb describe-time-to-live --table-name "${table_name}" --query 'TimeToLiveDescription.TimeToLiveStatus' --output text)"
case "${ttl_status}" in ENABLED|ENABLING) ;; *) echo "Unexpected TTL status: ${ttl_status}" >&2; exit 1 ;; esac

function_config="$(aws_cli lambda get-function-configuration --function-name "${function_name}" --query '[Runtime,MemorySize,Timeout]' --output text)"
[ "${function_config}" = $'nodejs24.x\t256\t15' ]

auth_config="$(aws_cli lambda get-function-configuration --function-name "${function_name}" --query 'Environment.Variables.[WHATSAPP_NUMBER_PARAMETER,PHONE_WEBHOOK_SECRET_PARAMETER,TURNSTILE_SITE_KEY_PARAMETER,TURNSTILE_SECRET_PARAMETER,WEBAUTHN_RP_ID,WEBAUTHN_EXPECTED_ORIGIN]' --output text)"
[ "${auth_config}" = $'/rsvp/whatsapp-number\t/rsvp/phone-webhook-secret\t/rsvp/turnstile-site-key\t/rsvp/turnstile-secret\tcalcada2026.pt\thttps://calcada2026.pt' ]

concurrency="$(aws_cli lambda get-function-concurrency --function-name "${function_name}" --query 'ReservedConcurrentExecutions' --output text)"
[ "${concurrency}" = '5' ]

queue_config="$(aws_cli sqs get-queue-attributes --queue-url "${phone_queue_url}" --attribute-names SqsManagedSseEnabled RedrivePolicy --query 'Attributes.[SqsManagedSseEnabled,RedrivePolicy]' --output text)"
queue_sse="${queue_config%%$'\t'*}"
queue_redrive="${queue_config#*$'\t'}"
queue_sse_normalized="$(printf '%s' "${queue_sse}" | tr '[:upper:]' '[:lower:]')"
if [ "${queue_sse_normalized}" != 'true' ] || [[ "${queue_redrive}" != *'maxReceiveCount'* ]]; then
  echo "Unexpected phone queue configuration" >&2
  exit 1
fi

processor_config="$(aws_cli lambda get-function-configuration --function-name "${phone_processor_arn}" --query '[Runtime,MemorySize,Timeout]' --output text)"
[ "${processor_config}" = $'nodejs24.x\t256\t15' ]
processor_concurrency="$(aws_cli lambda get-function-concurrency --function-name "${phone_processor_arn}" --query 'ReservedConcurrentExecutions' --output text)"
[ "${processor_concurrency}" = '1' ]

mapping_config="$(aws_cli lambda list-event-source-mappings --function-name "${phone_processor_arn}" --query 'EventSourceMappings[0].[BatchSize,State]' --output text)"
[ "${mapping_config}" = $'1\tEnabled' ]

dlq_alarm="$(aws_cli cloudwatch describe-alarms --alarm-names rsvp-phone-registration-dlq-not-empty --query 'MetricAlarms[0].AlarmName' --output text)"
[ "${dlq_alarm}" = 'rsvp-phone-registration-dlq-not-empty' ]

summary_queue_config="$(aws_cli sqs get-queue-attributes --queue-url "${summary_queue_url}" --attribute-names SqsManagedSseEnabled RedrivePolicy --query 'Attributes.[SqsManagedSseEnabled,RedrivePolicy]' --output text)"
summary_queue_sse="${summary_queue_config%%$'\t'*}"
summary_queue_redrive="${summary_queue_config#*$'\t'}"
summary_queue_sse_normalized="$(printf '%s' "${summary_queue_sse}" | tr '[:upper:]' '[:lower:]')"
if [ "${summary_queue_sse_normalized}" != 'true' ] || [[ "${summary_queue_redrive}" != *'maxReceiveCount'* ]]; then
  echo "Unexpected summary queue configuration" >&2
  exit 1
fi

summary_processor_config="$(aws_cli lambda get-function-configuration --function-name "${summary_processor_arn}" --query '[Runtime,MemorySize,Timeout,Environment.Variables.GEMINI_API_KEY_PARAMETER]' --output text)"
[ "${summary_processor_config}" = $'nodejs24.x\t256\t15\t/rsvp/gemini-api-key' ]
summary_processor_concurrency="$(aws_cli lambda get-function-concurrency --function-name "${summary_processor_arn}" --query 'ReservedConcurrentExecutions' --output text)"
[ "${summary_processor_concurrency}" = '1' ]
summary_mapping_config="$(aws_cli lambda list-event-source-mappings --function-name "${summary_processor_arn}" --query 'EventSourceMappings[0].[BatchSize,State]' --output text)"
[ "${summary_mapping_config}" = $'1\tEnabled' ]
summary_dlq_alarm="$(aws_cli cloudwatch describe-alarms --alarm-names rsvp-summary-dlq-not-empty --query 'MetricAlarms[0].AlarmName' --output text)"
[ "${summary_dlq_alarm}" = 'rsvp-summary-dlq-not-empty' ]

retention="$(aws_cli logs describe-log-groups --log-group-name-prefix "/aws/lambda/${function_name}" --query 'logGroups[?logGroupName==`/aws/lambda/'"${function_name}"'`].retentionInDays | [0]' --output text)"
[ "${retention}" = '30' ]

http_status="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' "${function_url}")"
[ "${http_status}" = '403' ]

echo "Verified RSVP stack ${STACK_NAME}: ${stack_status}, private S3, protected origin, active DynamoDB, and constrained Lambda."

#!/usr/bin/env bash

set -euo pipefail

DOMAIN="${DOMAIN:-calcada2026.pt}"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-30}"
VERIFY_DELAY_SECONDS="${VERIFY_DELAY_SECONDS:-10}"

for command_name in curl dig openssl; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "Missing required command: ${command_name}" >&2; exit 1; }
done

cloudflare_nameserver='false'
for attempt in $(seq 1 "${VERIFY_ATTEMPTS}"); do
  if dig +short NS "${DOMAIN}" | grep -Eq '\.ns\.cloudflare\.com\.?$'; then
    cloudflare_nameserver='true'
    break
  fi
  [ "${attempt}" -eq "${VERIFY_ATTEMPTS}" ] || sleep "${VERIFY_DELAY_SECONDS}"
done
[ "${cloudflare_nameserver}" = 'true' ] || { echo "${DOMAIN} is not delegated to Cloudflare nameservers." >&2; exit 1; }

http_headers="$(mktemp)"
https_headers="$(mktemp)"
trap 'rm -f -- "${http_headers}" "${https_headers}"' EXIT

http_status="$(curl --silent --show-error --output /dev/null --dump-header "${http_headers}" --write-out '%{http_code}' "http://${DOMAIN}/")"
[ "${http_status}" = '308' ] || { echo "Expected HTTP 308 redirect, got ${http_status}." >&2; exit 1; }
grep -Eiq "^location: https://${DOMAIN}/" "${http_headers}"

https_status="$(curl --silent --show-error --tlsv1.2 --output /dev/null --dump-header "${https_headers}" --write-out '%{http_code}' "https://${DOMAIN}/")"
[ "${https_status}" = '200' ] || { echo "Expected HTTPS site response 200, got ${https_status}." >&2; exit 1; }
grep -Eiq '^strict-transport-security: max-age=31536000; includeSubDomains' "${https_headers}"
grep -Eiq '^cf-ray:' "${https_headers}"

health_status="$(curl --silent --show-error --tlsv1.2 --output /dev/null --write-out '%{http_code}' "https://${DOMAIN}/health")"
[ "${health_status}" = '200' ] || { echo "Expected protected origin health response 200, got ${health_status}." >&2; exit 1; }

www_headers="$(mktemp)"
trap 'rm -f -- "${http_headers}" "${https_headers}" "${www_headers}"' EXIT
www_status="$(curl --silent --show-error --tlsv1.2 --output /dev/null --dump-header "${www_headers}" --write-out '%{http_code}' "https://www.${DOMAIN}/")"
[ "${www_status}" = '308' ] || { echo "Expected canonical www redirect 308, got ${www_status}." >&2; exit 1; }
grep -Eiq "^location: https://${DOMAIN}/" "${www_headers}"

printf '' | openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" -verify_return_error 2>&1 \
  | grep -q 'Verify return code: 0 (ok)'

echo "Verified ${DOMAIN}: Cloudflare DNS, canonical HTTPS redirects, valid TLS, HSTS, edge proxy, and protected Lambda origin."

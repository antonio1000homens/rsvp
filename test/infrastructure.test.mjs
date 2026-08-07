import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('CloudFormation grants only the new table and SSM capabilities required by authentication', async () => {
  const template = await readFile(new URL('../cloudformation/rsvp.yaml', import.meta.url), 'utf8');
  assert.match(template, /dynamodb:TransactWriteItems/);
  assert.match(template, /Default: \/rsvp\/whatsapp-number/);
  assert.match(template, /Default: \/rsvp\/phone-webhook-secret/);
  assert.match(template, /Default: \/rsvp\/turnstile-site-key/);
  assert.match(template, /Default: \/rsvp\/turnstile-secret/);
  assert.match(template, /WEBAUTHN_RP_ID: !Ref WebauthnRpId/);
  assert.match(template, /WEBAUTHN_EXPECTED_ORIGIN: !Ref WebauthnExpectedOrigin/);
  assert.doesNotMatch(template, /ssm:GetParametersByPath/);
});

test('bootstrap generates the phone webhook secret without embedding a value', async () => {
  const script = await readFile(new URL('../scripts/bootstrap-aws.sh', import.meta.url), 'utf8');
  assert.match(script, /create_secure_parameter_if_missing \/rsvp\/phone-webhook-secret/);
  assert.doesNotMatch(script, /phone-webhook-secret.*Value/);
});

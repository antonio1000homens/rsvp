#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { GetParameterCommand, PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { normalizeE164 } from '../shared/identity.mjs';

const region = process.env.AWS_REGION || 'eu-west-2';
const numberParameter = process.env.WHATSAPP_NUMBER_PARAMETER || '/rsvp/whatsapp-number';
const secretParameter = process.env.PHONE_WEBHOOK_SECRET_PARAMETER || '/rsvp/phone-webhook-secret';

const clipboardCommand = () => {
  if (process.platform === 'darwin') return { command: 'pbcopy', args: [] };
  if (process.env.WAYLAND_DISPLAY) return { command: 'wl-copy', args: [] };
  return { command: 'xclip', args: ['-selection', 'clipboard'] };
};

const copySecret = async (ssm) => {
  const result = await ssm.send(new GetParameterCommand({ Name: secretParameter, WithDecryption: true }));
  const secret = result.Parameter?.Value;
  if (!secret) throw new Error(`Missing SecureString parameter ${secretParameter}.`);
  const clipboard = clipboardCommand();
  const copied = spawnSync(clipboard.command, clipboard.args, {
    input: secret,
    encoding: 'utf8',
    stdio: ['pipe', 'ignore', 'ignore'],
  });
  if (copied.status !== 0) throw new Error('No supported clipboard command is available. The secret was not printed.');
  process.stdout.write('The phone webhook secret is now on the clipboard. Clear the clipboard after configuring the automation.\n');
};

export const main = async (command = process.argv[2], ssm = new SSMClient({ region })) => {
  if (command === 'copy-secret') return copySecret(ssm);

  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    if (command === 'configure') {
      const number = normalizeE164(await prompt.question('WhatsApp Business number in E.164 format: '));
      await ssm.send(new PutParameterCommand({
        Name: numberParameter,
        Description: 'Public WhatsApp Business app number used by the RSVP login link',
        Type: 'String',
        Value: number,
        Overwrite: true,
        Tier: 'Standard',
      }));
      process.stdout.write(`Configured ${numberParameter}.\n`);
      return;
    }

    if (command === 'rotate-secret') {
      const confirmation = await prompt.question('Type ROTATE to invalidate the phone automation secret: ');
      if (confirmation !== 'ROTATE') throw new Error('Secret rotation cancelled.');
      await ssm.send(new PutParameterCommand({
        Name: secretParameter,
        Description: 'Bearer secret for manually approved phone automation callbacks',
        Type: 'SecureString',
        Value: randomBytes(32).toString('base64url'),
        Overwrite: true,
        Tier: 'Standard',
      }));
      await copySecret(ssm);
      return;
    }
    throw new Error('Usage: whatsapp-config.mjs <configure|copy-secret|rotate-secret>');
  } finally {
    prompt.close();
  }
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${error.message}\n`);
    process.exitCode = 1;
  });
}

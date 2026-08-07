#!/usr/bin/env node

import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { PutParameterCommand, SSMClient } from '@aws-sdk/client-ssm';

const region = process.env.AWS_REGION || 'eu-west-2';
const siteKeyParameter = process.env.TURNSTILE_SITE_KEY_PARAMETER || '/rsvp/turnstile-site-key';
const secretParameter = process.env.TURNSTILE_SECRET_PARAMETER || '/rsvp/turnstile-secret';

const promptHidden = (question) => new Promise((resolve, reject) => {
  const input = process.stdin;
  const output = process.stdout;
  if (!input.isTTY || !input.setRawMode) {
    reject(new Error('Turnstile secret must be entered from an interactive terminal.'));
    return;
  }
  let value = '';
  output.write(question);
  input.setRawMode(true);
  input.resume();
  const onData = (chunk) => {
    for (const character of chunk.toString('utf8')) {
      if (character === '\u0003') {
        input.setRawMode(false);
        input.off('data', onData);
        output.write('\n');
        reject(new Error('Cancelled.'));
        return;
      }
      if (character === '\r' || character === '\n') {
        input.setRawMode(false);
        input.off('data', onData);
        output.write('\n');
        resolve(value);
        return;
      }
      if (character === '\u007f') value = value.slice(0, -1);
      else if (character >= ' ') value += character;
    }
  };
  input.on('data', onData);
});

export const main = async (command = process.argv[2], ssm = new SSMClient({ region })) => {
  if (command !== 'configure') throw new Error('Usage: turnstile-config.mjs configure');
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const siteKey = (await prompt.question('Turnstile site key: ')).trim();
    if (!/^[A-Za-z0-9_-]{10,128}$/.test(siteKey)) throw new Error('Invalid Turnstile site key format.');
    prompt.close();
    const secret = (await promptHidden('Turnstile secret key (input hidden): ')).trim();
    if (!secret || secret.length > 256) throw new Error('Invalid Turnstile secret key.');
    await ssm.send(new PutParameterCommand({
      Name: siteKeyParameter,
      Description: 'Public Cloudflare Turnstile site key for the RSVP landing page',
      Type: 'String',
      Value: siteKey,
      Overwrite: true,
      Tier: 'Standard',
    }));
    await ssm.send(new PutParameterCommand({
      Name: secretParameter,
      Description: 'Cloudflare Turnstile server-side validation secret',
      Type: 'SecureString',
      Value: secret,
      Overwrite: true,
      Tier: 'Standard',
    }));
    process.stdout.write('Turnstile configuration stored in SSM. The secret was not printed.\n');
  } finally {
    if (!prompt.closed) prompt.close();
  }
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${error.message}\n`);
    process.exitCode = 1;
  });
}

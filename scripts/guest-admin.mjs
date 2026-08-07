#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { contactLookupFor, normalizeE164, normalizeNickname } from '../shared/identity.mjs';

const region = process.env.AWS_REGION || 'eu-west-2';
const tableName = process.env.RSVP_TABLE || 'rsvp';
const pepperParameter = process.env.CONTACT_PEPPER_PARAMETER || '/rsvp/contact-pepper';

const defaultClients = () => ({
  ddb: DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
    marshallOptions: { removeUndefinedValues: true },
  }),
  ssm: new SSMClient({ region }),
});

const directoryKey = (lookup) => ({ pk: 'DIRECTORY', sk: `NICKNAME#${lookup}` });
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const sendWithRetry = async (client, command) => {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await client.send(command);
    } catch (error) {
      const throttled = error?.name === 'ProvisionedThroughputExceededException' || error?.name === 'ThrottlingException';
      if (!throttled || attempt >= 7) throw error;
      await sleep(500 * (attempt + 1));
    }
  }
};

const promptInterface = () => createInterface({ input: process.stdin, output: process.stdout });

const readPepper = async (ssm) => {
  const result = await ssm.send(new GetParameterCommand({ Name: pepperParameter, WithDecryption: true }));
  const value = result.Parameter?.Value;
  if (!value) throw new Error(`Missing SecureString parameter ${pepperParameter}.`);
  return value;
};

const findByContact = async (ddb, contactLookup) => {
  const lookup = await ddb.send(new GetCommand({
    TableName: tableName,
    Key: { pk: `CONTACT#${contactLookup}`, sk: 'LOOKUP' },
    ConsistentRead: true,
  }));
  if (!lookup.Item?.guestId) return null;
  const profile = await ddb.send(new GetCommand({
    TableName: tableName,
    Key: { pk: `GUEST#${lookup.Item.guestId}`, sk: 'PROFILE' },
    ConsistentRead: true,
  }));
  return profile.Item || null;
};

export const addGuest = async ({ ddb, ssm, prompt = promptInterface() }) => {
  try {
    const nicknameInput = await prompt.question('Public nickname: ');
    const phoneInput = await prompt.question('Phone number in E.164 format: ');
    const nickname = normalizeNickname(nicknameInput);
    const phone = normalizeE164(phoneInput);
    const contactLookup = contactLookupFor(phone, await readPepper(ssm));
    const existingContact = await findByContact(ddb, contactLookup);
    if (existingContact?.enabled) throw new Error('That phone number is already assigned to an enabled guest.');

    const guestId = existingContact?.guestId || randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);
    const directory = {
      ...directoryKey(nickname.lookup),
      entityType: 'directory',
      guestId,
      nickname: nickname.display,
    };

    const profileItem = {
      pk: `GUEST#${guestId}`,
      sk: 'PROFILE',
      entityType: 'guest',
      guestId,
      nickname: nickname.display,
      contactLookup,
      enabled: true,
      sessionVersion: Number(existingContact?.sessionVersion || 1),
      createdAt: existingContact?.createdAt || createdAt,
      updatedAt: createdAt,
    };

    const profileWrite = existingContact
      ? {
          Update: {
            TableName: tableName,
            Key: { pk: profileItem.pk, sk: profileItem.sk },
            UpdateExpression: 'SET nickname = :nickname, enabled = :enabled, updatedAt = :now',
            ConditionExpression: 'contactLookup = :lookup AND enabled = :disabled',
            ExpressionAttributeValues: {
              ':nickname': nickname.display,
              ':enabled': true,
              ':disabled': false,
              ':lookup': contactLookup,
              ':now': createdAt,
            },
          },
        }
      : {
          Put: {
            TableName: tableName,
            Item: profileItem,
            ConditionExpression: 'attribute_not_exists(pk)',
          },
        };

    const writes = [
        profileWrite,
        {
          Put: {
            TableName: tableName,
            Item: directory,
            ConditionExpression: 'attribute_not_exists(pk)',
          },
        },
      ];
    if (!existingContact) {
      writes.push({
        Put: {
          TableName: tableName,
          Item: {
            pk: `CONTACT#${contactLookup}`,
            sk: 'LOOKUP',
            entityType: 'contactLookup',
            guestId,
          },
          ConditionExpression: 'attribute_not_exists(pk)',
        },
      });
    }
    await ddb.send(new TransactWriteCommand({ TransactItems: writes }));
    process.stdout.write(`Whitelisted ${nickname.display}. No plaintext phone number was stored.\n`);
  } finally {
    prompt.close?.();
  }
};

export const listGuests = async ({ ddb }) => {
  const result = await ddb.send(new QueryCommand({
    TableName: tableName,
    KeyConditionExpression: 'pk = :pk',
    ExpressionAttributeValues: { ':pk': 'DIRECTORY' },
    ProjectionExpression: 'nickname',
  }));
  const nicknames = (result.Items || []).map((item) => item.nickname).sort((a, b) => a.localeCompare(b));
  if (nicknames.length === 0) {
    process.stdout.write('No enabled guests.\n');
    return;
  }
  for (const nickname of nicknames) process.stdout.write(`${nickname}\tenabled\n`);
};

export const disableGuest = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const nicknameInput = await prompt.question('Public nickname to disable: ');
    const nickname = normalizeNickname(nicknameInput);
    const key = directoryKey(nickname.lookup);
    const result = await ddb.send(new GetCommand({ TableName: tableName, Key: key, ConsistentRead: true }));
    if (!result.Item) throw new Error('No enabled guest has that nickname.');
    const now = Math.floor(Date.now() / 1000);
    await ddb.send(new TransactWriteCommand({
      TransactItems: [
        {
          Delete: {
            TableName: tableName,
            Key: key,
            ConditionExpression: 'guestId = :guestId',
            ExpressionAttributeValues: { ':guestId': result.Item.guestId },
          },
        },
        {
          Update: {
            TableName: tableName,
            Key: { pk: `GUEST#${result.Item.guestId}`, sk: 'PROFILE' },
            UpdateExpression: 'SET enabled = :disabled, updatedAt = :now ADD sessionVersion :one',
            ConditionExpression: 'enabled = :enabled',
            ExpressionAttributeValues: {
              ':disabled': false, ':enabled': true, ':now': now, ':one': 1,
            },
          },
        },
      ],
    }));
    process.stdout.write(`Disabled ${result.Item.nickname}; credentials were retained and sessions were revoked.\n`);
  } finally {
    prompt.close?.();
  }
};

export const seedContacts = async ({ ddb, ssm, file }) => {
  const contents = await readFile(file, 'utf8');
  const contacts = contents.split(/\r?\n/).map((line, index) => {
    if (!line.trim()) return null;
    const cleanLine = line.trim().replace(/,+\s*$/, '');
    const separator = cleanLine.lastIndexOf(',');
    if (separator < 1) throw new Error(`Invalid contact on line ${index + 1}.`);
    return {
      name: cleanLine.slice(0, separator).trim(),
      phone: normalizeE164(cleanLine.slice(separator + 1).trim()),
    };
  }).filter(Boolean);
  const pepper = await readPepper(ssm);
  const results = [];
  for (const contact of contacts) {
    const nickname = normalizeNickname(`${contact.name} — Por confirmar`);
    const contactLookup = contactLookupFor(contact.phone, pepper);
    const existingContact = await findByContact(ddb, contactLookup);
    if (existingContact) {
      results.push(`${nickname.display}: skipped (phone already seeded)`);
      continue;
    }
    const directory = {
      ...directoryKey(nickname.lookup), entityType: 'directory', guestId: randomUUID(), nickname: nickname.display,
    };
    const createdAt = Math.floor(Date.now() / 1000);
    const profileItem = {
      pk: `GUEST#${directory.guestId}`, sk: 'PROFILE', entityType: 'guest', guestId: directory.guestId,
      nickname: nickname.display, contactLookup, enabled: true, sessionVersion: 1, createdAt,
    };
    await sendWithRetry(ddb, new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: tableName, Item: profileItem, ConditionExpression: 'attribute_not_exists(pk)' } },
      { Put: { TableName: tableName, Item: directory, ConditionExpression: 'attribute_not_exists(pk)' } },
      { Put: { TableName: tableName, Item: { pk: `CONTACT#${contactLookup}`, sk: 'LOOKUP', entityType: 'contactLookup', guestId: directory.guestId }, ConditionExpression: 'attribute_not_exists(pk)' } },
    ] }));
    results.push(`${nickname.display}: seeded`);
  }
  for (const result of results) process.stdout.write(`${result}\n`);
};

export const main = async (command = process.argv[2], clients = defaultClients()) => {
  if (command === 'add') return addGuest({ ...clients });
  if (command === 'seed') return seedContacts({ ...clients, file: process.argv[3] });
  if (command === 'list') return listGuests({ ...clients });
  if (command === 'disable') return disableGuest({ ...clients });
  throw new Error('Usage: guest-admin.mjs <add|list|disable>');
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${error.message}\n`);
    process.exitCode = 1;
  });
}

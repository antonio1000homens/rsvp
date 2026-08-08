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
import { normalizeNickname } from '../shared/identity.mjs';

const region = process.env.AWS_REGION || 'eu-west-2';
const tableName = process.env.RSVP_TABLE || 'rsvp';
const defaultClients = () => ({
  ddb: DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
    marshallOptions: { removeUndefinedValues: true },
  }),
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

const findByNickname = async (ddb, nickname) => {
  const profile = await ddb.send(new GetCommand({
    TableName: tableName,
    Key: directoryKey(nickname.lookup),
    ConsistentRead: true,
  }));
  if (!profile.Item?.guestId) return null;
  const guest = await ddb.send(new GetCommand({
    TableName: tableName,
    Key: { pk: `GUEST#${profile.Item.guestId}`, sk: 'PROFILE' },
    ConsistentRead: true,
  }));
  return guest.Item || null;
};

export const addGuest = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const nicknameInput = await prompt.question('Public nickname: ');
    const nickname = normalizeNickname(nicknameInput);
    const existingContact = await findByNickname(ddb, nickname);
    if (existingContact?.enabled) throw new Error('That contact is already enabled.');

    const guestId = existingContact?.guestId || randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);
    const directory = {
      ...directoryKey(nickname.lookup),
      entityType: 'directory',
      guestId,
      nickname: nickname.display,
      identityStatus: existingContact?.identityStatus || 'unconfirmed',
    };

    const profileItem = {
      pk: `GUEST#${guestId}`,
      sk: 'PROFILE',
      entityType: 'guest',
      guestId,
      nickname: nickname.display,
      identityStatus: existingContact?.identityStatus || 'unconfirmed',
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
            ConditionExpression: 'enabled = :disabled',
            ExpressionAttributeValues: {
              ':nickname': nickname.display,
              ':enabled': true,
              ':disabled': false,
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
    await ddb.send(new TransactWriteCommand({ TransactItems: writes }));
    process.stdout.write(`Whitelisted ${nickname.display}.\n`);
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

export const seedContacts = async ({ ddb, file }) => {
  const contents = await readFile(file, 'utf8');
  const contacts = contents.split(/\r?\n/).map((line, index) => {
    if (!line.trim()) return null;
    const cleanLine = line.trim().replace(/,+\s*$/, '');
    const separator = cleanLine.lastIndexOf(',');
    if (separator < 1) throw new Error(`Invalid contact on line ${index + 1}.`);
    return {
      name: cleanLine.slice(0, separator).trim(),
    };
  }).filter(Boolean);
  const results = [];
  for (const contact of contacts) {
    const nickname = normalizeNickname(contact.name);
    const existingContact = await findByNickname(ddb, nickname);
    if (existingContact) {
      if (existingContact.identityStatus !== 'confirmed') {
        const oldDirectory = directoryKey(normalizeNickname(existingContact.nickname).lookup);
        const newNickname = normalizeNickname(contact.name);
        const newDirectory = { ...directoryKey(newNickname.lookup), entityType: 'directory', guestId: existingContact.guestId, nickname: newNickname.display, identityStatus: 'unconfirmed' };
        const directoryItems = oldDirectory.sk === newDirectory.sk
          ? [{ Update: { TableName: tableName, Key: oldDirectory, UpdateExpression: 'SET nickname = :nickname, identityStatus = :status', ExpressionAttributeValues: { ':nickname': newNickname.display, ':status': 'unconfirmed' }, ConditionExpression: 'guestId = :guestId', } }]
          : [
              { Delete: { TableName: tableName, Key: oldDirectory } },
              { Put: { TableName: tableName, Item: newDirectory, ConditionExpression: 'attribute_not_exists(pk)' } },
            ];
        await sendWithRetry(ddb, new TransactWriteCommand({ TransactItems: [
          { Update: { TableName: tableName, Key: { pk: `GUEST#${existingContact.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET nickname = :nickname, identityStatus = :status, updatedAt = :now', ExpressionAttributeValues: { ':nickname': newNickname.display, ':status': 'unconfirmed', ':enabled': true, ':now': Math.floor(Date.now() / 1000) }, ConditionExpression: 'enabled = :enabled', } },
          ...directoryItems,
        ] }));
        results.push(`${newNickname.display}: migrated`);
      } else results.push(`${nickname.display}: skipped (already confirmed)`);
      continue;
    }
    const directory = {
      ...directoryKey(normalizeNickname(contact.name).lookup), entityType: 'directory', guestId: randomUUID(), nickname: contact.name, identityStatus: 'unconfirmed',
    };
    const createdAt = Math.floor(Date.now() / 1000);
    const profileItem = {
      pk: `GUEST#${directory.guestId}`, sk: 'PROFILE', entityType: 'guest', guestId: directory.guestId,
      nickname: contact.name, identityStatus: 'unconfirmed', enabled: true, sessionVersion: 1, createdAt,
    };
    await sendWithRetry(ddb, new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: tableName, Item: profileItem, ConditionExpression: 'attribute_not_exists(pk)' } },
      { Put: { TableName: tableName, Item: directory, ConditionExpression: 'attribute_not_exists(pk)' } },
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

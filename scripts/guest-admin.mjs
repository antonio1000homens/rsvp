#!/usr/bin/env node

import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  ScanCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { normalizeContactName, normalizeNickname } from '../shared/identity.mjs';

const region = process.env.AWS_REGION || 'eu-west-2';
const tableName = process.env.RSVP_TABLE || 'rsvp';
const groupIdFor = (value) => String(value || '').normalize('NFKD')
  .replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pt-PT').trim()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

const groupDetails = (value) => {
  const name = String(value || '').trim().replace(/\s+/g, ' ');
  const groupId = groupIdFor(name);
  if (!name || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(groupId)) throw new Error('Provide a group name with letters or numbers.');
  return { groupId, name };
};
const defaultClients = () => ({
  ddb: DynamoDBDocumentClient.from(new DynamoDBClient({ region }), {
    marshallOptions: { removeUndefinedValues: true },
  }),
});

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
  const result = await ddb.send(new ScanCommand({
    TableName: tableName,
    FilterExpression: 'sk = :profile AND nickname = :nickname',
    ExpressionAttributeValues: { ':profile': 'PROFILE', ':nickname': nickname.display },
  }));
  return result.Items?.[0] || null;
};

export const addGuest = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const nicknameInput = await prompt.question('Public nickname: ');
    const nickname = normalizeNickname(nicknameInput);
    const senderInput = await prompt.question('WhatsApp sender name: ');
    const sender = normalizeContactName(senderInput);
    const existingContact = await findByNickname(ddb, nickname);
    if (existingContact?.enabled) throw new Error('That contact is already enabled.');

    const guestId = existingContact?.guestId || randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);
    const profileItem = {
      pk: `GUEST#${guestId}`,
      sk: 'PROFILE',
      entityType: 'guest',
      guestId,
      nickname: nickname.display,
      sender: sender.display,
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
            UpdateExpression: 'SET nickname = :nickname, sender = :sender, enabled = :enabled, updatedAt = :now',
            ConditionExpression: 'enabled = :disabled',
            ExpressionAttributeValues: {
              ':nickname': nickname.display,
              ':sender': sender.display,
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

    await ddb.send(new TransactWriteCommand({ TransactItems: [profileWrite] }));
    process.stdout.write(`Whitelisted ${nickname.display}.\n`);
  } finally {
    prompt.close?.();
  }
};

export const listGuests = async ({ ddb }) => {
  const result = await ddb.send(new ScanCommand({
    TableName: tableName,
    FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled',
    ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true },
    ProjectionExpression: 'nickname',
  }));
  const nicknames = (result.Items || []).map((item) => item.nickname).sort((a, b) => a.localeCompare(b));
  if (nicknames.length === 0) {
    process.stdout.write('No enabled guests.\n');
    return;
  }
  for (const nickname of nicknames) process.stdout.write(`${nickname}\tenabled\n`);
};

export const addGroup = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const group = groupDetails(await prompt.question('Group name: '));
    const existing = await ddb.send(new GetCommand({ TableName: tableName, Key: { pk: `GROUP#${group.groupId}`, sk: 'PROFILE' } }));
    if (existing.Item?.enabled) throw new Error('That group already exists.');
    const timestamp = Math.floor(Date.now() / 1000);
    await ddb.send(new PutCommand({
      TableName: tableName,
      Item: { pk: `GROUP#${group.groupId}`, sk: 'PROFILE', entityType: 'group', ...group, enabled: true, createdAt: timestamp, updatedAt: timestamp },
      ConditionExpression: 'attribute_not_exists(pk)',
    }));
    process.stdout.write(`Created group ${group.name} (${group.groupId}).\n`);
  } finally { prompt.close?.(); }
};

export const addGroupMember = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const groupId = groupIdFor(await prompt.question('Group ID: '));
    const group = await ddb.send(new GetCommand({ TableName: tableName, Key: { pk: `GROUP#${groupId}`, sk: 'PROFILE' } }));
    if (!group.Item?.enabled || group.Item.entityType !== 'group') throw new Error('No enabled group has that ID.');
    const nickname = normalizeNickname(await prompt.question('Guest nickname: '));
    const guest = await findByNickname(ddb, nickname);
    if (!guest?.enabled) throw new Error('No enabled guest has that nickname.');
    const timestamp = Math.floor(Date.now() / 1000);
    await ddb.send(new PutCommand({
      TableName: tableName,
      Item: { pk: `GROUP#${groupId}`, sk: `MEMBER#${guest.guestId}`, entityType: 'groupMember', groupId, guestId: guest.guestId, createdAt: timestamp },
      ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
    }));
    process.stdout.write(`Added ${guest.nickname} to ${group.Item.name}.\n`);
  } finally { prompt.close?.(); }
};

export const disableGuest = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const nicknameInput = await prompt.question('Public nickname to disable: ');
    const nickname = normalizeNickname(nicknameInput);
    const result = await ddb.send(new ScanCommand({ TableName: tableName, FilterExpression: 'sk = :profile AND nickname = :nickname AND enabled = :enabled', ExpressionAttributeValues: { ':profile': 'PROFILE', ':nickname': nickname.display, ':enabled': true }, ProjectionExpression: 'pk, sk, nickname' }));
    const guest = result.Items?.[0];
    if (!guest) throw new Error('No enabled guest has that nickname.');
    const now = Math.floor(Date.now() / 1000);
    await ddb.send(new TransactWriteCommand({
      TransactItems: [
        {
          Update: {
            TableName: tableName,
            Key: { pk: guest.pk, sk: guest.sk },
            UpdateExpression: 'SET enabled = :disabled, updatedAt = :now ADD sessionVersion :one',
            ConditionExpression: 'enabled = :enabled',
            ExpressionAttributeValues: {
              ':disabled': false, ':enabled': true, ':now': now, ':one': 1,
            },
          },
        },
      ],
    }));
    process.stdout.write(`Disabled ${guest.nickname}; credentials were retained and sessions were revoked.\n`);
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
    const sender = normalizeContactName(contact.name);
    const existingContact = await findByNickname(ddb, nickname);
    if (existingContact) {
      if (existingContact.identityStatus !== 'confirmed') {
        const newNickname = normalizeNickname(contact.name);
        await sendWithRetry(ddb, new TransactWriteCommand({ TransactItems: [
          { Update: { TableName: tableName, Key: { pk: `GUEST#${existingContact.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET nickname = :nickname, sender = :sender, identityStatus = :status, updatedAt = :now', ExpressionAttributeValues: { ':nickname': newNickname.display, ':sender': sender.display, ':status': 'unconfirmed', ':enabled': true, ':now': Math.floor(Date.now() / 1000) }, ConditionExpression: 'enabled = :enabled', } },
        ] }));
        results.push(`${newNickname.display}: migrated`);
      } else results.push(`${nickname.display}: skipped (already confirmed)`);
      continue;
    }
    const guestId = randomUUID();
    const createdAt = Math.floor(Date.now() / 1000);
    const profileItem = {
      pk: `GUEST#${guestId}`, sk: 'PROFILE', entityType: 'guest', guestId,
      nickname: nickname.display, sender: sender.display, identityStatus: 'unconfirmed', enabled: true, sessionVersion: 1, createdAt,
    };
    await sendWithRetry(ddb, new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: tableName, Item: profileItem, ConditionExpression: 'attribute_not_exists(pk)' } },
    ] }));
    results.push(`${nickname.display}: seeded`);
  }
  for (const result of results) process.stdout.write(`${result}\n`);
};

export const markContactAdded = async ({ ddb, prompt = promptInterface() }) => {
  try {
    const nickname = normalizeNickname(await prompt.question('Nickname do contacto adicionado: '));
    const result = await ddb.send(new ScanCommand({
      TableName: tableName,
      FilterExpression: 'sk = :profile AND nickname = :nickname AND identityStatus = :toAdd',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':nickname': nickname.display, ':toAdd': 'to_add' },
      ProjectionExpression: 'pk, sk, nickname',
    }));
    const guest = result.Items?.[0];
    if (!guest) throw new Error('No pending contact-add request has that nickname.');
    await ddb.send(new TransactWriteCommand({ TransactItems: [{ Update: {
      TableName: tableName, Key: { pk: guest.pk, sk: guest.sk },
      UpdateExpression: 'SET identityStatus = :unconfirmed, updatedAt = :now',
      ConditionExpression: 'identityStatus = :toAdd AND enabled = :enabled',
      ExpressionAttributeValues: { ':unconfirmed': 'unconfirmed', ':toAdd': 'to_add', ':enabled': true, ':now': Math.floor(Date.now() / 1000) },
    } }] }));
    process.stdout.write(`Marked ${guest.nickname} as ready for WhatsApp verification.\n`);
  } finally { prompt.close?.(); }
};

export const main = async (command = process.argv[2], clients = defaultClients()) => {
  if (command === 'add') return addGuest({ ...clients });
  if (command === 'group:add') return addGroup({ ...clients });
  if (command === 'group:add-member') return addGroupMember({ ...clients });
  if (command === 'seed') return seedContacts({ ...clients, file: process.argv[3] });
  if (command === 'list') return listGuests({ ...clients });
  if (command === 'disable') return disableGuest({ ...clients });
  if (command === 'mark-added') return markContactAdded({ ...clients });
  throw new Error('Usage: guest-admin.mjs <add|list|disable|mark-added|group:add|group:add-member>');
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${error.message}\n`);
    process.exitCode = 1;
  });
}

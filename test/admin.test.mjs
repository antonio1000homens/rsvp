import assert from 'node:assert/strict';
import test from 'node:test';
import { addGroup, addGroupMember, addGuest } from '../scripts/guest-admin.mjs';

const promptFor = (...answers) => ({
  async question() { return answers.shift(); },
  close() {},
});

test('guest add writes a name-based unconfirmed guest without phone data', async () => {
  const calls = [];
  const ddb = {
    async send(command) {
      calls.push(command);
      if (command.constructor.name === 'GetCommand') return {};
      return {};
    },
  };
  await addGuest({ ddb, prompt: promptFor('Dinner Fox', 'dinner-fox') });
  const transaction = calls.find((command) => command.constructor.name === 'TransactWriteCommand');
  assert.ok(transaction);
  const serialized = JSON.stringify(transaction.input);
  assert.doesNotMatch(serialized, /phone|contactLookup|351|912345678/);
  assert.match(serialized, /Dinner Fox/);
});

test('guest add rejects an already enabled contact', async () => {
  let transactionSent = false;
  const ddb = {
    async send(command) {
      if (command.constructor.name === 'ScanCommand') {
        return { Items: [{ pk: 'GUEST#existing', sk: 'PROFILE', guestId: 'existing', nickname: 'Duplicate', enabled: true }] };
      }
      transactionSent = true;
      return {};
    },
  };
  await assert.rejects(
    addGuest({ ddb, prompt: promptFor('Duplicate', 'duplicate') }),
    /already enabled/,
  );
  assert.equal(transactionSent, false);
});

test('group commands create an independent group and a member link', async () => {
  const calls = [];
  let groupReads = 0;
  const ddb = {
    async send(command) {
      calls.push(command);
      if (command.constructor.name === 'GetCommand' && command.input.Key.pk === 'GROUP#friends') {
        groupReads += 1;
        return groupReads === 1 ? {} : { Item: { pk: 'GROUP#friends', sk: 'PROFILE', entityType: 'group', groupId: 'friends', name: 'Friends', enabled: true } };
      }
      if (command.constructor.name === 'ScanCommand') return { Items: [{ pk: 'GUEST#guest-one', sk: 'PROFILE', guestId: 'guest-one', nickname: 'Alice', enabled: true }] };
      return {};
    },
  };
  await addGroup({ ddb, prompt: promptFor('Friends') });
  await addGroupMember({ ddb, prompt: promptFor('friends', 'Alice') });
  const serialized = JSON.stringify(calls.map((call) => call.input));
  assert.match(serialized, /GROUP#friends/);
  assert.match(serialized, /MEMBER#guest-one/);
});

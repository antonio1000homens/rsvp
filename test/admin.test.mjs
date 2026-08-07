import assert from 'node:assert/strict';
import test from 'node:test';
import { addGuest } from '../scripts/guest-admin.mjs';

const promptFor = (...answers) => ({
  async question() { return answers.shift(); },
  close() {},
});

test('guest add writes a contact HMAC and never sends the plaintext phone to DynamoDB', async () => {
  const calls = [];
  const ddb = {
    async send(command) {
      calls.push(command);
      if (command.constructor.name === 'GetCommand') return {};
      return {};
    },
  };
  const ssm = { send: async () => ({ Parameter: { Value: 'test-pepper' } }) };
  await addGuest({ ddb, ssm, prompt: promptFor('Dinner Fox', '+351 912 345 678') });
  const transaction = calls.find((command) => command.constructor.name === 'TransactWriteCommand');
  assert.ok(transaction);
  const serialized = JSON.stringify(transaction.input);
  assert.doesNotMatch(serialized, /351|912345678/);
  assert.match(serialized, /Dinner Fox/);
  assert.match(serialized, /contactLookup/);
});

test('guest add rejects a phone already assigned to an enabled profile', async () => {
  let transactionSent = false;
  const ddb = {
    async send(command) {
      if (command.constructor.name === 'GetCommand' && command.input.Key.pk.startsWith('CONTACT#')) {
        return { Item: { guestId: 'existing' } };
      }
      if (command.constructor.name === 'GetCommand') {
        return { Item: { guestId: 'existing', enabled: true } };
      }
      transactionSent = true;
      return {};
    },
  };
  const ssm = { send: async () => ({ Parameter: { Value: 'test-pepper' } }) };
  await assert.rejects(
    addGuest({ ddb, ssm, prompt: promptFor('Duplicate', '+351912345678') }),
    /already assigned/,
  );
  assert.equal(transactionSent, false);
});

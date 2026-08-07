import assert from 'node:assert/strict';
import test from 'node:test';
import {
  contactLookupFor,
  normalizeE164,
  normalizeNickname,
  safeEqual,
  tokenHash,
} from '../shared/identity.mjs';

test('normalizes E.164 input and rejects ambiguous phone numbers', () => {
  assert.equal(normalizeE164(' +351 912-345-678 '), '+351912345678');
  assert.throws(() => normalizeE164('912345678'), /E\.164/);
  assert.throws(() => normalizeE164('+00123'), /E\.164/);
});

test('contact lookup is deterministic, peppered, and contains no phone number', () => {
  const first = contactLookupFor('+351912345678', 'pepper-one');
  assert.equal(first, contactLookupFor('+351 912 345 678', 'pepper-one'));
  assert.notEqual(first, contactLookupFor('+351912345678', 'pepper-two'));
  assert.doesNotMatch(first, /912345678/);
  assert.equal(first.length, 43);
});

test('normalizes public nicknames and hashes challenge tokens', () => {
  assert.deepEqual(normalizeNickname('  Tó   Ninho '), { display: 'Tó Ninho', lookup: 'tó ninho' });
  assert.throws(() => normalizeNickname(''), /Nickname/);
  assert.equal(tokenHash('one'), tokenHash('one'));
  assert.notEqual(tokenHash('one'), tokenHash('two'));
  assert.equal(safeEqual('same', 'same'), true);
  assert.equal(safeEqual('same', 'different'), false);
});

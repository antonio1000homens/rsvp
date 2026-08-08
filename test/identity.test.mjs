import assert from 'node:assert/strict';
import test from 'node:test';
import {
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

test('normalizes public nicknames and hashes challenge tokens', () => {
  assert.deepEqual(normalizeNickname('  Tó   Ninho '), { display: 'Tó Ninho', lookup: 'tó ninho' });
  assert.throws(() => normalizeNickname(''), /Nickname/);
  assert.equal(tokenHash('one'), tokenHash('one'));
  assert.notEqual(tokenHash('one'), tokenHash('two'));
  assert.equal(safeEqual('same', 'same'), true);
  assert.equal(safeEqual('same', 'different'), false);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import { aggregateEventSummary, buildEventNarrativePrompt, cleanNarrative, generateEventNarrative } from '../lambda/event-summary.mjs';
import { processSummaryEvent } from '../lambda/summary-worker.mjs';

test('event-summary prompt is pt-PT and only contains aggregate RSVP data plus the public nickname', () => {
  const prompt = buildEventNarrativePrompt({
    summary: { guests: 3, responses: 2, byDay: { '23 dezembro': 3 }, byMeal: { lunch: 0, dinner: 3, drinks: 0 }, restaurants: { 'Restaurante A': 3 } },
    activity: { type: 'registration', nickname: 'Célia' },
  });
  assert.match(prompt, /português de Portugal/);
  assert.match(prompt, /Célia acabou de confirmar/);
  assert.doesNotMatch(prompt, /private|910000000|scrypt/);
});

test('event-summary falls back after Gemini rate limiting and accepts only bounded plain text', async () => {
  const calls = [];
  const result = await generateEventNarrative({
    apiKey: 'test-key', prompt: 'teste', models: ['first', 'second'],
    fetchImpl: async (url) => {
      calls.push(url);
      if (calls.length === 1) return { ok: false, status: 429 };
      return { ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: 'O Restaurante A parece ser o favorito.' }] } }] }) };
    },
  });
  assert.equal(result.model, 'second');
  assert.equal(calls.length, 2);
  assert.equal(cleanNarrative('<b>texto</b>'), '');
  assert.equal(cleanNarrative('x'.repeat(601)), '');
});

test('event-summary aggregates legacy and multi-select restaurant votes without private fields', () => {
  assert.deepEqual(aggregateEventSummary({
    configuredRestaurants: ['A'],
    responses: [
      { guestCount: 2, availableDays: ['23'], mealTypes: ['dinner'], restaurantChoices: ['A'] },
      { guestCount: 1, availableDays: ['23'], mealTypes: ['drinks'], restaurantChoice: 'B', dietaryRestrictions: 'private' },
    ],
  }), { responses: 2, guests: 3, byDay: { 23: 3 }, byMeal: { lunch: 0, dinner: 2, drinks: 1 }, restaurants: { A: 2, B: 1 } });
});

test('summary worker persists a successful narrative and leaves the previous one intact on Gemini failure', async () => {
  const writes = [];
  const ddbClient = { send: async (command) => {
    if (command.constructor.name === 'ScanCommand') return { Items: [{ guestCount: 2, availableDays: ['23'], mealTypes: ['dinner'], restaurantChoices: ['A'] }] };
    if (command.constructor.name === 'GetCommand') return { Item: { restaurantChoices: ['A'] } };
    if (command.constructor.name === 'PutCommand') { writes.push(command.input.Item); return {}; }
    throw new Error('unexpected_command');
  } };
  const input = { event: { activity: { type: 'registration', nickname: 'Célia' } }, ddbClient, tableName: 'test', getApiKey: async () => 'test-key', now: () => 123 };
  await processSummaryEvent({ ...input, generate: async () => ({ narrative: 'Célia juntou-se ao grupo.', model: 'test-model' }) });
  assert.deepEqual(writes[0], { pk: 'EVENT#DEFAULT', sk: 'AI_SUMMARY', entityType: 'aiSummary', narrative: 'Célia juntou-se ao grupo.', model: 'test-model', generatedAt: 123, lastActivity: { type: 'registration', nickname: 'Célia' } });
  await assert.rejects(processSummaryEvent({ ...input, generate: async () => { throw new Error('gemini_down'); } }));
  assert.equal(writes.length, 1);
});

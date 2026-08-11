import assert from 'node:assert/strict';
import test from 'node:test';
import { tokenHash } from '../shared/identity.mjs';
import { processPhoneRegistration } from '../lambda/phone-registration.mjs';
import {
  contentTypeFor,
  createHandler,
  hashPassword,
  safeObjectKey,
  secretsMatch,
  signToken,
  verifyPassword,
  verifyToken,
} from '../lambda/index.mjs';

const fixedNow = 2_000_000_000;
const values = {
  '/rsvp/origin-secret': 'correct-secret',
  '/rsvp/session-secret': 'session-secret',
  '/rsvp/phone-webhook-secret': 'phone-webhook-secret',
  '/rsvp/validation-secret': 'validation-secret',
  '/rsvp/whatsapp-number': '+351910000000',
  '/rsvp/turnstile-site-key': '0x4AAAAA-test-site-key',
  '/rsvp/turnstile-secret': 'turnstile-secret',
};

const env = {
  ORIGIN_SECRET_PARAMETER: '/rsvp/origin-secret',
  SESSION_SECRET_PARAMETER: '/rsvp/session-secret',
  PHONE_WEBHOOK_SECRET_PARAMETER: '/rsvp/phone-webhook-secret',
  VALIDATION_SECRET_PARAMETER: '/rsvp/validation-secret',
  WHATSAPP_NUMBER_PARAMETER: '/rsvp/whatsapp-number',
  TURNSTILE_SITE_KEY_PARAMETER: '/rsvp/turnstile-site-key',
  TURNSTILE_SECRET_PARAMETER: '/rsvp/turnstile-secret',
  TURNSTILE_HOSTNAME: 'calcada2026.pt',
  SITE_BUCKET: 'rsvp-test-site',
  RSVP_TABLE: 'rsvp-test',
  PHONE_QUEUE_URL: 'https://sqs.eu-west-2.amazonaws.com/123/rsvp-phone-registration',
  SUMMARY_QUEUE_URL: 'https://sqs.eu-west-2.amazonaws.com/123/rsvp-summary',
  WEBAUTHN_RP_ID: 'calcada2026.pt',
  WEBAUTHN_EXPECTED_ORIGIN: 'https://calcada2026.pt',
  WEBAUTHN_RP_NAME: 'Calçada 2026 RSVP',
};

const request = (path = '/', {
  secret = 'correct-secret',
  method = 'GET',
  body,
  headers = {},
  cookies = null,
} = {}) => ({
  rawPath: path,
  headers: { 'x-rsvp-origin-secret': secret, ...headers },
  requestContext: { http: { method, path } },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  cookies: cookies ?? [
    `rsvp_captcha=${signToken({ type: 'captcha', exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
    `rsvp_trivia=${signToken({ type: 'trivia', answered: true, exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
  ],
});

const keyOf = ({ pk, sk }) => `${pk}|${sk}`;
const conditionalError = (name = 'ConditionalCheckFailedException') => Object.assign(new Error(name), { name });

class FakeDdb {
  constructor(items = []) {
    this.items = new Map(items.map((item) => [keyOf(item), structuredClone(item)]));
  }

  get(key) { return this.items.get(keyOf(key)); }

  async send(command) {
    const name = command.constructor.name;
    const input = command.input;
    if (name === 'GetCommand') return { Item: this.get(input.Key) };
    if (name === 'QueryCommand') {
      const values = input.ExpressionAttributeValues || {};
      const pk = values[':pk'];
      const prefix = values[':prefix'];
      return {
        Items: [...this.items.values()].filter((item) => item.pk === pk && (!prefix || item.sk.startsWith(prefix))),
      };
    }
    if (name === 'ScanCommand') {
      const values = input.ExpressionAttributeValues || {};
      return {
        Items: [...this.items.values()].filter((item) =>
          (!values[':profile'] || item.sk === values[':profile']) &&
          (!values[':guest'] || item.entityType === values[':guest']) &&
          (!values[':group'] || item.entityType === values[':group']) &&
          (!values[':response'] || item.entityType === values[':response']) &&
          (!values[':enabled'] || item.enabled === values[':enabled'])),
      };
    }
    if (name === 'PutCommand') {
      if (input.ConditionExpression && this.get(input.Item)) throw conditionalError();
      this.items.set(keyOf(input.Item), structuredClone(input.Item));
      return {};
    }
    if (name === 'DeleteCommand') {
      this.items.delete(keyOf(input.Key));
      return {};
    }
    if (name === 'UpdateCommand') {
      const item = this.get(input.Key);
      if (!item || item.status !== 'pending' || item.expiresAt < input.ExpressionAttributeValues[':now']) {
        throw conditionalError();
      }
      item.status = input.ExpressionAttributeValues[':approved'];
      item.approvedAt = input.ExpressionAttributeValues[':now'];
      return {};
    }
    if (name === 'TransactWriteCommand') {
      for (const operation of input.TransactItems) {
        if (operation.Put && operation.Put.ConditionExpression && this.get(operation.Put.Item)) {
          throw conditionalError('TransactionCanceledException');
        }
        if (operation.Update) {
          const current = this.get(operation.Update.Key);
          const expressionValues = operation.Update.ExpressionAttributeValues;
          if (!current) throw conditionalError('TransactionCanceledException');
          if (expressionValues[':pending'] && (current.status !== 'pending' || current.expiresAt < expressionValues[':now'])) {
            throw conditionalError('TransactionCanceledException');
          }
          if (expressionValues[':previous'] !== undefined && current.counter !== expressionValues[':previous']) {
            throw conditionalError('TransactionCanceledException');
          }
        }
        if (operation.Delete?.ConditionExpression?.includes('nonce = :nonce')) {
          const current = this.get(operation.Delete.Key);
          if (!current || current.nonce !== operation.Delete.ExpressionAttributeValues[':nonce']) throw conditionalError('TransactionCanceledException');
        }
      }
      for (const operation of input.TransactItems) {
        if (operation.Put) this.items.set(keyOf(operation.Put.Item), structuredClone(operation.Put.Item));
        if (operation.Delete) this.items.delete(keyOf(operation.Delete.Key));
        if (operation.Update) {
          const current = this.get(operation.Update.Key);
          const expressionValues = operation.Update.ExpressionAttributeValues;
          if (expressionValues[':created']) {
            current.status = expressionValues[':created'];
            current.approvedAt = expressionValues[':now'];
          }
          if (expressionValues[':active']) current.status = expressionValues[':active'];
          if (expressionValues[':used']) {
            current.status = 'used';
            current.usedAt = expressionValues[':now'];
          }
          if (expressionValues[':next'] !== undefined) {
            current.counter = expressionValues[':next'];
            current.lastUsedAt = expressionValues[':now'];
          }
          if (expressionValues[':nonce'] !== undefined) current.nonce = expressionValues[':nonce'];
          if (expressionValues[':sender'] !== undefined) current.sender = expressionValues[':sender'];
          if (expressionValues[':senderLookup'] !== undefined) current.senderLookup = expressionValues[':senderLookup'];
          if (expressionValues[':validationExpiresAt'] !== undefined) current.validationExpiresAt = expressionValues[':validationExpiresAt'];
        }
      }
      return {};
    }
    throw new Error(`Unsupported command ${name}`);
  }
}

const webauthn = {
  async generateAuthenticationOptions(input) {
    return { challenge: 'authentication-challenge', rpId: input.rpID, allowCredentials: input.allowCredentials };
  },
  async generateRegistrationOptions(input) {
    return { challenge: 'registration-challenge', rp: { id: input.rpID }, user: { name: input.userName } };
  },
  async verifyRegistrationResponse() {
    return {
      verified: true,
      registrationInfo: {
        credential: {
          id: 'credential-one',
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: ['internal'],
        },
        credentialDeviceType: 'multiDevice',
        credentialBackedUp: true,
      },
    };
  },
  async verifyAuthenticationResponse() {
    return { verified: true, authenticationInfo: { newCounter: 1 } };
  },
};

const cookieFrom = (response, name) => {
  const serialized = response.cookies?.find((cookie) => cookie.startsWith(`${name}=`));
  assert.ok(serialized, `Missing ${name} cookie`);
  return serialized.split(';')[0];
};

const makeHandler = ({ objects = {}, items = [] } = {}) => {
  const requests = [];
  const s3 = {
    async send(command) {
      const key = command.input.Key;
      requests.push(key);
      if (!(key in objects)) {
        const error = new Error('missing');
        error.name = 'NoSuchKey';
        throw error;
      }
      return { Body: Buffer.from(objects[key]) };
    },
  };
  const ssm = { send: async (command) => ({ Parameter: { Value: values[command.input.Name] || '' } }) };
  const ddb = new FakeDdb(items);
  const queued = [];
  const sqs = { send: async (command) => { queued.push(command.input); return { MessageId: 'queued-message' }; } };
  let randomCounter = 1;
  const handler = createHandler({
    s3,
    ssm,
    sqs,
    ddb,
    webauthn,
    env,
    now: () => fixedNow,
    randomBytes: () => Buffer.alloc(32, randomCounter++),
    turnstileValidate: async () => ({ success: true, action: 'guest-directory', hostname: 'calcada2026.pt' }),
  });
  return { handler, requests, ddb, queued };
};

const guest = (overrides = {}) => ({
  pk: 'GUEST#123e4567-e89b-42d3-a456-426614174000',
  sk: 'PROFILE',
  entityType: 'guest',
  guestId: '123e4567-e89b-42d3-a456-426614174000',
  nickname: 'Toninho',
  enabled: true,
  sessionVersion: 1,
  ...overrides,
});

test('safeObjectKey normalizes valid paths and rejects traversal', () => {
  assert.equal(safeObjectKey('/'), 'index.html');
  assert.equal(safeObjectKey('/assets/app.js'), 'assets/app.js');
  assert.equal(safeObjectKey('/admin/'), 'admin/index.html');
  assert.equal(safeObjectKey('/%2e%2e/private'), null);
  assert.equal(safeObjectKey('/bad%2f..%2fsecret'), null);
  assert.equal(safeObjectKey('/bad%encoding'), null);
  assert.equal(safeObjectKey('/windows\\path'), null);
});

test('origin and signed tokens use timing-safe verification and expiry', () => {
  assert.equal(secretsMatch('same', 'same'), true);
  assert.equal(secretsMatch('short', 'longer'), false);
  const token = signToken({ type: 'test', exp: fixedNow + 1 }, 'secret');
  assert.equal(verifyToken(token, 'secret', fixedNow).type, 'test');
  assert.equal(verifyToken(token, 'wrong', fixedNow), null);
  assert.equal(verifyToken(token, 'secret', fixedNow + 2), null);
});

test('content types are constrained to known extensions', () => {
  assert.equal(contentTypeFor('index.html'), 'text/html; charset=utf-8');
  assert.equal(contentTypeFor('app.abcdef123456.js'), 'text/javascript; charset=utf-8');
  assert.equal(contentTypeFor('unknown.bin'), 'application/octet-stream');
});

test('rejects requests without the origin secret before accessing storage', async () => {
  const { handler, requests } = makeHandler({ objects: { 'index.html': 'secret page' } });
  const response = await handler(request('/', { secret: 'wrong-secret' }));
  assert.equal(response.statusCode, 403);
  assert.deepEqual(requests, []);
});

test('health endpoint is protected', async () => {
  const { handler } = makeHandler();
  const response = await handler(request('/health'));
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { status: 'ok' });
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('public guest directory returns nicknames and IDs but no private profile data', async () => {
  const { handler } = makeHandler({ items: [guest()] });
  const response = await handler({ ...request('/api/guests'), rawQueryString: 'q=ton' });
  assert.equal(response.statusCode, 200);
  const serialized = response.body;
  assert.deepEqual(JSON.parse(serialized), { guests: [{ id: guest().guestId, nickname: 'Toninho', registrationRequired: false }] });
  assert.doesNotMatch(serialized, /351911111111|contact-pepper/);
});

test('guest search requires a query and caps public matches at ten', async () => {
  const profiles = Array.from({ length: 12 }, (_, index) => guest({
    guestId: `123e4567-e89b-42d3-a456-4266141740${String(index).padStart(2, '0')}`,
    pk: `GUEST#123e4567-e89b-42d3-a456-4266141740${String(index).padStart(2, '0')}`,
    nickname: `Guest ${index}`,
  }));
  const { handler } = makeHandler({ items: profiles });
  const missing = await handler(request('/api/guests'));
  assert.equal(missing.statusCode, 400);
  const response = await handler({ ...request('/api/guests'), rawQueryString: 'q=guest' });
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(response.body).guests.length, 10);
});

test('groups filter the guest directory through independent many-to-many membership records', async () => {
  const otherGuest = guest({
    pk: 'GUEST#123e4567-e89b-42d3-a456-426614174001',
    guestId: '123e4567-e89b-42d3-a456-426614174001',
    nickname: 'Maria',
  });
  const group = { pk: 'GROUP#family', sk: 'PROFILE', entityType: 'group', groupId: 'family', name: 'Família', enabled: true };
  const membership = { pk: 'GROUP#family', sk: `MEMBER#${guest().guestId}`, entityType: 'groupMember', groupId: 'family', guestId: guest().guestId };
  const { handler } = makeHandler({ items: [guest(), otherGuest, group, membership] });
  const groups = await handler(request('/api/groups'));
  assert.deepEqual(JSON.parse(groups.body), { groups: [{ id: 'family', name: 'Família' }] });
  const response = await handler({ ...request('/api/guests'), rawQueryString: 'group=family&q=ton' });
  assert.deepEqual(JSON.parse(response.body), { guests: [{ id: guest().guestId, nickname: 'Toninho', registrationRequired: false }] });
  const rejected = await handler({ ...request('/api/guests'), rawQueryString: 'group=missing&q=ton' });
  assert.equal(rejected.statusCode, 404);
});

test('an authenticated guest can save RSVP choices and the trivia-gated summary is aggregate-only', async () => {
  const restaurantSettings = { pk: 'EVENT#DEFAULT', sk: 'SETTINGS', entityType: 'eventSettings', restaurantChoices: ['Tasquinha', 'O Pátio'] };
  const { handler, queued } = makeHandler({ items: [guest(), restaurantSettings] });
  const session = signToken({ type: 'session', guestId: guest().guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const response = await handler(request('/api/rsvp', {
    method: 'PUT',
    cookies: [`rsvp_session=${session}`],
    body: {
      availableDays: ['19 December 2026', '21 December 2026'], guestCount: 2, mealTypes: ['dinner', 'drinks'],
      restaurantChoices: ['Tasquinha', 'O Pátio'], dietaryRestrictions: 'Vegetariano',
    },
  }));
  assert.equal(response.statusCode, 200);
  const own = await handler(request('/api/rsvp', { cookies: [`rsvp_session=${session}`] }));
  assert.equal(JSON.parse(own.body).response.dietaryRestrictions, 'Vegetariano');
  assert.deepEqual(JSON.parse(own.body).response.restaurantChoices, ['Tasquinha', 'O Pátio']);
  const summary = await handler(request('/api/rsvp/summary'));
  const serialized = summary.body;
  assert.deepEqual(JSON.parse(serialized).byDay, { '19 December 2026': 2, '20 December 2026': 0, '21 December 2026': 2, '22 December 2026': 0, '23 December 2026': 0 });
  assert.deepEqual(JSON.parse(serialized).restaurantChoices, ['Tasquinha', 'O Pátio']);
  assert.deepEqual(JSON.parse(serialized).restaurants, { Tasquinha: 2, 'O Pátio': 2 });
  assert.equal(JSON.parse(queued[0].MessageBody).activity.type, 'rsvp_saved');
  assert.doesNotMatch(serialized, /Vegetariano/);
});

test('an admin-issued guest link bypasses trivia only until credentials are configured', async () => {
  const profile = guest({ isAdmin: true });
  const { handler, ddb } = makeHandler({ items: [profile] });
  const adminSession = signToken({ type: 'session', guestId: profile.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const created = await handler(request('/api/admin/guests/access-link', { method: 'POST', cookies: [`rsvp_session=${adminSession}`], body: { guestId: profile.guestId } }));
  assert.equal(created.statusCode, 200);
  const token = new URL(JSON.parse(created.body).link).searchParams.get('access');
  const firstUse = await handler(request('/api/access-link/consume', { method: 'POST', cookies: [], body: { token } }));
  assert.equal(JSON.parse(firstUse.body).mode, 'session');
  assert.match(firstUse.cookies?.find((cookie) => cookie.startsWith('rsvp_session=')) || '', /Max-Age=604800/);

  const password = { pk: `GUEST#${profile.guestId}`, sk: 'PASSWORD', entityType: 'passwordCredential', passwordHash: 'not-a-valid-password-hash' };
  ddb.items.set(keyOf(password), password);
  const protectedUse = await handler(request('/api/access-link/consume', { method: 'POST', cookies: [], body: { token } }));
  assert.equal(JSON.parse(protectedUse.body).mode, 'credentials');
  const accessCookie = cookieFrom(protectedUse, 'rsvp_access_link');
  const started = await handler(request('/api/auth/start', { method: 'POST', cookies: [accessCookie], body: { guestId: profile.guestId } }));
  assert.equal(started.statusCode, 200);
  assert.equal(JSON.parse(started.body).mode, 'password');
});

test('the phone webhook queues the Tasker payload for asynchronous validation', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const { handler, queued } = makeHandler({ items: [profile] });
  const started = await handler(request('/api/rsvp/whatsapp/start', { method: 'POST', body: {
    guestId: profile.guestId,
    availableDays: ['19 December 2026'], guestCount: 2, mealTypes: ['dinner'],
    restaurantChoice: 'Por decidir', dietaryRestrictions: 'Vegetariano',
  } }));
  assert.equal(started.statusCode, 200);
  const message = new URL(JSON.parse(started.body).whatsappUrl).searchParams.get('text');
  const response = await handler(request('/api/phone/register', {
    method: 'POST', cookies: [], headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: 'Antonio Costa', message },
  }));
  assert.equal(response.statusCode, 202);
  assert.deepEqual(JSON.parse(queued[0].MessageBody), { sender: 'Antonio Costa', message, receivedAt: fixedNow });
});

test('the phone worker persists a queued, signed RSVP and acknowledges business failures', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const { handler, ddb } = makeHandler({ items: [profile] });
  const started = await handler(request('/api/rsvp/whatsapp/start', { method: 'POST', body: {
    guestId: profile.guestId, availableDays: ['19 December 2026'], guestCount: 2,
    mealTypes: ['dinner'], restaurantChoice: 'Por decidir', dietaryRestrictions: 'Vegetariano',
  } }));
  const message = new URL(JSON.parse(started.body).whatsappUrl).searchParams.get('text');
  assert.equal(await processPhoneRegistration({ sender: 'Antonio Costa', message, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'created');
  assert.deepEqual(ddb.get({ pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE' }).availableDays, ['19 December 2026']);
  assert.equal(await processPhoneRegistration({ sender: 'Antonio Costa', message, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'registration_challenge_unavailable');
});

test('a callback accepted before expiry survives worker delay and an admin can safely reissue a pending RSVP', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed', isAdmin: true });
  const { handler, ddb } = makeHandler({ items: [profile] });
  const started = await handler(request('/api/rsvp/whatsapp/start', { method: 'POST', body: {
    guestId: profile.guestId, availableDays: ['19 December 2026'], guestCount: 2,
    mealTypes: ['dinner'], restaurantChoice: 'Por decidir', dietaryRestrictions: 'Vegetariano',
  } }));
  const originalMessage = new URL(JSON.parse(started.body).whatsappUrl).searchParams.get('text');
  const adminSession = signToken({ type: 'session', guestId: profile.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const reissued = await handler(request('/api/admin/guests/reissue-registration', {
    method: 'POST', cookies: [`rsvp_session=${adminSession}`], body: { guestId: profile.guestId },
  }));
  assert.equal(reissued.statusCode, 200);
  const reissuedMessage = new URL(JSON.parse(reissued.body).whatsappUrl).searchParams.get('text');
  assert.equal(await processPhoneRegistration({ sender: 'Antonio Costa', message: originalMessage, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow + 3600, receivedAt: fixedNow }), 'registration_unavailable');
  assert.equal(await processPhoneRegistration({ sender: 'Antonio Costa', message: reissuedMessage, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow + 3600, receivedAt: fixedNow + 1 }), 'created');
  assert.deepEqual(ddb.get({ pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE' }).availableDays, ['19 December 2026']);
});

test('a member can link another member through signed WhatsApp approval and synchronize both RSVPs', async () => {
  const memberA = guest({ nickname: 'Ana', sender: 'Ana', identityStatus: 'confirmed' });
  const memberB = guest({ pk: 'GUEST#123e4567-e89b-42d3-a456-426614174001', guestId: '123e4567-e89b-42d3-a456-426614174001', nickname: 'Bruno', sender: 'Bruno', identityStatus: 'unconfirmed' });
  const aResponse = { pk: `RSVP#${memberA.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: memberA.guestId, availableDays: ['19 December 2026'], guestCount: 1, mealTypes: ['dinner'], restaurantChoices: ['Por decidir'] };
  const session = signToken({ type: 'session', guestId: memberA.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const { handler, ddb } = makeHandler({ items: [memberA, memberB, aResponse] });
  const created = await handler(request('/api/link', { method: 'POST', cookies: [`rsvp_session=${session}`], body: { targetGuestId: memberB.guestId } }));
  assert.equal(created.statusCode, 200);
  const pending = JSON.parse(created.body);
  assert.equal(pending.status, 'pending');
  const message = new URL(pending.whatsappUrl).searchParams.get('text');
  assert.equal(await processPhoneRegistration({ sender: 'Other', message, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'sender_mismatch');
  assert.equal(await processPhoneRegistration({ sender: 'Bruno', message: `${message.slice(0, -1)}x`, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'invalid_validation_signature');
  assert.equal(await processPhoneRegistration({ sender: 'Bruno', message, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'linked');
  assert.equal(ddb.get({ pk: `GUEST#${memberA.guestId}`, sk: 'LINK' }).status, 'active');
  assert.equal(ddb.get({ pk: `GUEST#${memberB.guestId}`, sk: 'LINK' }).status, 'active');
  assert.deepEqual(ddb.get({ pk: `RSVP#${memberB.guestId}`, sk: 'RESPONSE' }).availableDays, ['19 December 2026']);
  const saved = await handler(request('/api/rsvp', { method: 'PUT', cookies: [`rsvp_session=${session}`], body: { availableDays: ['20 December 2026'], guestCount: 2, mealTypes: ['lunch'], restaurantChoices: ['Por decidir'] } }));
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(ddb.get({ pk: `RSVP#${memberB.guestId}`, sk: 'RESPONSE' }).availableDays, ['20 December 2026']);
  assert.equal(ddb.get({ pk: `RSVP#${memberB.guestId}`, sk: 'RESPONSE' }).guestCount, 2);
  const directory = JSON.parse((await handler({ ...request('/api/guests'), rawQueryString: 'q=ana' })).body);
  assert.deepEqual(directory.guests.find((entry) => entry.linked), {
    id: memberA.guestId,
    nickname: 'Ana & Bruno',
    linked: true,
    members: [
      { id: memberA.guestId, nickname: 'Ana', registrationRequired: false },
      { id: memberB.guestId, nickname: 'Bruno', registrationRequired: true },
    ],
  });
});

test('a guest with an existing RSVP can retrieve it through WhatsApp without changing the Tasker payload', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const response = { pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: profile.guestId, availableDays: ['19 December 2026'], guestCount: 2, mealTypes: ['dinner'], restaurantChoices: ['Por decidir'], dietaryRestrictions: 'Vegetariano' };
  const { handler, ddb } = makeHandler({ items: [profile, response] });
  const started = await handler(request('/api/auth/start', { method: 'POST', body: { guestId: profile.guestId } }));
  assert.equal(started.statusCode, 200);
  assert.equal(JSON.parse(started.body).mode, 'whatsapp-retrieve');
  const retrieval = await handler(request('/api/rsvp/whatsapp/start', { method: 'POST', body: { guestId: profile.guestId, mode: 'retrieve' } }));
  assert.equal(retrieval.statusCode, 200);
  assert.equal(JSON.parse(retrieval.body).mode, 'retrieve');
  const registrationCookie = cookieFrom(retrieval, 'rsvp_registration');
  const message = new URL(JSON.parse(retrieval.body).whatsappUrl).searchParams.get('text');
  assert.equal(await processPhoneRegistration({ sender: 'Antonio Costa', message, ddb, tableName: env.RSVP_TABLE, validationSecret: values['/rsvp/validation-secret'], now: fixedNow }), 'created');
  const retrieved = await handler(request('/api/rsvp', { cookies: [registrationCookie] }));
  assert.equal(retrieved.statusCode, 200);
  assert.deepEqual(JSON.parse(retrieved.body).response.restaurantChoices, ['Por decidir']);
  assert.equal(ddb.get({ pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE' }).updatedAt, undefined);
});

test('a guest with a passkey can retrieve the existing RSVP after passkey login', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const credential = { pk: `GUEST#${profile.guestId}`, sk: 'CREDENTIAL#credential-one', entityType: 'passkey', credentialId: 'credential-one', publicKey: Buffer.from([1, 2, 3]).toString('base64url'), counter: 0, transports: ['internal'] };
  const response = { pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: profile.guestId, availableDays: ['19 December 2026'], guestCount: 1, mealTypes: ['dinner'], restaurantChoices: ['Por decidir'] };
  const { handler } = makeHandler({ items: [profile, credential, response] });
  const started = await handler(request('/api/auth/start', { method: 'POST', body: { guestId: profile.guestId } }));
  assert.equal(JSON.parse(started.body).mode, 'passkey');
  const loggedIn = await handler(request('/api/auth/passkeys/login/verify', { method: 'POST', cookies: [cookieFrom(started, 'rsvp_webauthn')], body: { credential: { id: 'credential-one' } } }));
  const sessionCookie = cookieFrom(loggedIn, 'rsvp_session');
  const retrieved = await handler(request('/api/rsvp', { cookies: [sessionCookie] }));
  assert.equal(retrieved.statusCode, 200);
  assert.deepEqual(JSON.parse(retrieved.body).response.availableDays, ['19 December 2026']);
});

test('auth start advertises both passkey and password without starting a QR flow', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const credential = { pk: `GUEST#${profile.guestId}`, sk: 'CREDENTIAL#credential-one', entityType: 'passkey', credentialId: 'credential-one', publicKey: Buffer.from([1, 2, 3]).toString('base64url'), counter: 0, transports: ['internal'] };
  const password = { pk: `GUEST#${profile.guestId}`, sk: 'PASSWORD', entityType: 'passwordCredential', passwordHash: hashPassword('password-one'), createdAt: fixedNow };
  const { handler } = makeHandler({ items: [profile, credential, password] });
  const started = await handler(request('/api/auth/start', { method: 'POST', body: { guestId: profile.guestId } }));
  const payload = JSON.parse(started.body);
  assert.equal(payload.mode, 'credentials');
  assert.deepEqual(payload.methods, { passkey: true, password: true });
  assert.ok(started.cookies?.some((cookie) => cookie.startsWith('rsvp_webauthn=')));
});

test('an authenticated admin can switch guest identity without repeating the public gate', async () => {
  const admin = guest({ isAdmin: true });
  const target = guest({ guestId: '223e4567-e89b-42d3-a456-426614174001', pk: 'GUEST#223e4567-e89b-42d3-a456-426614174001', nickname: 'Outro convidado' });
  const { handler } = makeHandler({ items: [admin, target] });
  const session = signToken({ type: 'session', guestId: admin.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const started = await handler(request('/api/auth/start', { method: 'POST', cookies: [`rsvp_session=${session}`], body: { guestId: target.guestId } }));
  assert.equal(started.statusCode, 200);
  assert.equal(JSON.parse(started.body).mode, 'whatsapp-rsvp');
});

test('password hashes are salted and verify without exposing the plaintext', () => {
  const first = hashPassword('correct horse battery staple');
  const second = hashPassword('correct horse battery staple');
  assert.notEqual(first, second);
  assert.equal(verifyPassword('correct horse battery staple', first), true);
  assert.equal(verifyPassword('wrong password', first), false);
  assert.throws(() => hashPassword('short'), /invalid_password/);
});

test('a guest can set, use, replace, and remove a password', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const { handler, ddb } = makeHandler({ items: [profile] });
  const session = signToken({ type: 'session', guestId: profile.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const set = await handler(request('/api/auth/password', { method: 'POST', cookies: [`rsvp_session=${session}`], body: { password: 'password-one', confirmPassword: 'password-one' } }));
  assert.equal(set.statusCode, 200);
  assert.equal(ddb.get({ pk: `GUEST#${profile.guestId}`, sk: 'PASSWORD' }).entityType, 'passwordCredential');
  assert.equal(JSON.stringify(set.body).includes('password-one'), false);
  const started = await handler(request('/api/auth/start', { method: 'POST', body: { guestId: profile.guestId } }));
  assert.equal(JSON.parse(started.body).mode, 'password');
  assert.equal(started.cookies, undefined);
  const loggedIn = await handler(request('/api/auth/password/login', { method: 'POST', body: { guestId: profile.guestId, password: 'password-one' } }));
  assert.equal(loggedIn.statusCode, 200);
  const changed = await handler(request('/api/auth/password', { method: 'POST', cookies: [cookieFrom(loggedIn, 'rsvp_session')], body: { password: 'password-two', confirmPassword: 'password-two' } }));
  assert.equal(changed.statusCode, 200);
  const oldLogin = await handler(request('/api/auth/password/login', { method: 'POST', body: { guestId: profile.guestId, password: 'password-one' } }));
  assert.equal(oldLogin.statusCode, 401);
  const removed = await handler(request('/api/auth/password', { method: 'DELETE', cookies: [cookieFrom(changed, 'rsvp_session')] }));
  assert.equal(removed.statusCode, 200);
  assert.equal(ddb.get({ pk: `GUEST#${profile.guestId}`, sk: 'PASSWORD' }), undefined);
});

test('an RSVP can explicitly record no available dates', async () => {
  const profile = guest();
  const { handler } = makeHandler({ items: [profile] });
  const session = signToken({ type: 'session', guestId: profile.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const response = await handler(request('/api/rsvp', {
    method: 'PUT', cookies: [`rsvp_session=${session}`], body: {
      availableDays: [], noAvailability: true, guestCount: 1, mealTypes: ['dinner'],
      preferenceType: 'families', restaurantChoice: 'Por decidir', dietaryRestrictions: '',
    },
  }));
  assert.equal(response.statusCode, 200);
  assert.equal(JSON.parse(response.body).response.noAvailability, true);
});

test('only an admin session can manage restaurant choices', async () => {
  const admin = guest({ isAdmin: true });
  const { handler } = makeHandler({ items: [admin] });
  const session = signToken({ type: 'session', guestId: admin.guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const saved = await handler(request('/api/admin/settings', { method: 'PUT', cookies: [`rsvp_session=${session}`], body: { restaurantChoices: ['A Tasca', 'O Pátio'], triviaQuestions: [{ question: 'Quem organiza?', answers: ['Antonio'] }] } }));
  assert.equal(saved.statusCode, 200);
  assert.deepEqual(JSON.parse(saved.body).restaurantChoices, ['A Tasca', 'O Pátio']);
  assert.equal(JSON.parse(saved.body).triviaQuestions[0].question, 'Quem organiza?');
  assert.equal(JSON.parse(saved.body).useTrivia, true);
  const nonAdmin = await makeHandler({ items: [guest()] }).handler(request('/api/admin/settings', { cookies: [`rsvp_session=${session}`] }));
  assert.equal(nonAdmin.statusCode, 403);
});

test('trivia is served from event settings, not Lambda constants', async () => {
  const settings = { pk: 'EVENT#DEFAULT', sk: 'SETTINGS', entityType: 'eventSettings', useTrivia: true, triviaQuestions: [{ id: 'q1', question: 'Pergunta configurada?', answers: ['sim'] }] };
  const { handler } = makeHandler({ items: [settings] });
  const question = await handler(request('/api/trivia/question'));
  const payload = JSON.parse(question.body);
  assert.equal(payload.question, 'Pergunta configurada?');
  const answer = await handler(request('/api/trivia/answer', { method: 'POST', body: { challenge: payload.challenge, answer: 'sim' } }));
  assert.equal(answer.statusCode, 200);
});

test('guest directory rejects missing CAPTCHA gate and accepts a valid Turnstile token', async () => {
  const { handler } = makeHandler();
  const rejected = await handler(request('/api/guests', { cookies: [] }));
  assert.equal(rejected.statusCode, 403);
  assert.equal(JSON.parse(rejected.body).error, 'captcha_required');
  const accepted = await handler({ ...request('/api/guests', {
    cookies: [
      `rsvp_captcha=${signToken({ type: 'captcha', exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
      `rsvp_trivia=${signToken({ type: 'trivia', answered: true, exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
    ],
  }), rawQueryString: 'q=ton' });
  assert.equal(accepted.statusCode, 200);
});

test('serves static files, SPA fallback, HEAD, and method constraints', async () => {
  const { handler, requests } = makeHandler({
    objects: {
      'index.html': '<h1>RSVP</h1>',
      'app.abcdef123456.js': 'console.log("ok")',
    },
  });
  const asset = await handler(request('/app.abcdef123456.js'));
  assert.equal(asset.statusCode, 200);
  assert.equal(asset.headers['cache-control'], 'public, max-age=31536000, immutable');
  assert.equal(Buffer.from(asset.body, 'base64').toString(), 'console.log("ok")');

  const page = await handler(request('/my-rsvp'));
  assert.equal(page.statusCode, 200);
  assert.deepEqual(requests.slice(-2), ['my-rsvp', 'index.html']);

  const head = await handler(request('/', { method: 'HEAD' }));
  assert.equal(head.body, '');
  const postStatic = await handler(request('/', { method: 'POST' }));
  assert.equal(postStatic.statusCode, 405);
});

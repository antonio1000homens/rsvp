import assert from 'node:assert/strict';
import test from 'node:test';
import { tokenHash } from '../shared/identity.mjs';
import {
  contentTypeFor,
  createHandler,
  safeObjectKey,
  secretsMatch,
  signToken,
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
      }
      for (const operation of input.TransactItems) {
        if (operation.Put) this.items.set(keyOf(operation.Put.Item), structuredClone(operation.Put.Item));
        if (operation.Update) {
          const current = this.get(operation.Update.Key);
          const expressionValues = operation.Update.ExpressionAttributeValues;
          if (expressionValues[':used']) {
            current.status = 'used';
            current.usedAt = expressionValues[':now'];
          }
          if (expressionValues[':next'] !== undefined) {
            current.counter = expressionValues[':next'];
            current.lastUsedAt = expressionValues[':now'];
          }
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
  let randomCounter = 1;
  const handler = createHandler({
    s3,
    ssm,
    ddb,
    webauthn,
    env,
    now: () => fixedNow,
    randomBytes: () => Buffer.alloc(32, randomCounter++),
    turnstileValidate: async () => ({ success: true, action: 'guest-directory', hostname: 'calcada2026.pt' }),
  });
  return { handler, requests, ddb };
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
  const response = await handler(request('/api/guests'));
  assert.equal(response.statusCode, 200);
  const serialized = response.body;
  assert.deepEqual(JSON.parse(serialized), { guests: [{ id: guest().guestId, nickname: 'Toninho', registrationRequired: false }] });
  assert.doesNotMatch(serialized, /351911111111|contact-pepper/);
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
  const response = await handler({ ...request('/api/guests'), rawQueryString: 'group=family' });
  assert.deepEqual(JSON.parse(response.body), { guests: [{ id: guest().guestId, nickname: 'Toninho', registrationRequired: false }] });
  const rejected = await handler({ ...request('/api/guests'), rawQueryString: 'group=missing' });
  assert.equal(rejected.statusCode, 404);
});

test('an authenticated guest can save RSVP choices and the trivia-gated summary is aggregate-only', async () => {
  const { handler } = makeHandler({ items: [guest()] });
  const session = signToken({ type: 'session', guestId: guest().guestId, sessionVersion: 1, exp: fixedNow + 600 }, values['/rsvp/session-secret']);
  const response = await handler(request('/api/rsvp', {
    method: 'PUT',
    cookies: [`rsvp_session=${session}`],
    body: {
      availableDays: ['19 December 2026', '21 December 2026'], guestCount: 2, mealTypes: ['dinner', 'drinks'],
      restaurantChoice: 'Tasquinha', dietaryRestrictions: 'Vegetariano',
    },
  }));
  assert.equal(response.statusCode, 200);
  const own = await handler(request('/api/rsvp', { cookies: [`rsvp_session=${session}`] }));
  assert.equal(JSON.parse(own.body).response.dietaryRestrictions, 'Vegetariano');
  const summary = await handler(request('/api/rsvp/summary'));
  const serialized = summary.body;
  assert.deepEqual(JSON.parse(serialized).byDay, { '19 December 2026': 2, '20 December 2026': 0, '21 December 2026': 2, '22 December 2026': 0, '23 December 2026': 0 });
  assert.doesNotMatch(serialized, /Vegetariano/);
});

test('the phone webhook saves an RSVP only for its verified WhatsApp sender', async () => {
  const profile = guest({ sender: 'António Costa', identityStatus: 'confirmed' });
  const { handler, ddb } = makeHandler({ items: [profile] });
  const message = `RSVP ${Buffer.from(JSON.stringify({
    availableDays: ['19 December 2026'], guestCount: 2, mealTypes: ['dinner'],
    restaurantChoice: 'Por decidir', dietaryRestrictions: 'Vegetariano',
  })).toString('base64url')}`;
  const response = await handler(request('/api/phone/rsvp', {
    method: 'POST', cookies: [], headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: 'Antonio Costa', message },
  }));
  assert.equal(response.statusCode, 204);
  assert.deepEqual(ddb.get({ pk: `RSVP#${profile.guestId}`, sk: 'RESPONSE' }).availableDays, ['19 December 2026']);
  const rejected = await handler(request('/api/phone/rsvp', {
    method: 'POST', cookies: [], headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: 'Outra Pessoa', message },
  }));
  assert.equal(rejected.statusCode, 403);
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
  const accepted = await handler(request('/api/guests', {
    cookies: [
      `rsvp_captcha=${signToken({ type: 'captcha', exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
      `rsvp_trivia=${signToken({ type: 'trivia', answered: true, exp: fixedNow + 600 }, values['/rsvp/session-secret'])}`,
    ],
  }));
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

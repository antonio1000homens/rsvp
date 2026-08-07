import assert from 'node:assert/strict';
import test from 'node:test';
import { contactLookupFor, tokenHash } from '../shared/identity.mjs';
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
  '/rsvp/contact-pepper': 'contact-pepper',
  '/rsvp/phone-webhook-secret': 'phone-webhook-secret',
  '/rsvp/validation-secret': 'validation-secret',
  '/rsvp/whatsapp-number': '+351910000000',
  '/rsvp/turnstile-site-key': '0x4AAAAA-test-site-key',
  '/rsvp/turnstile-secret': 'turnstile-secret',
};

const env = {
  ORIGIN_SECRET_PARAMETER: '/rsvp/origin-secret',
  SESSION_SECRET_PARAMETER: '/rsvp/session-secret',
  CONTACT_PEPPER_PARAMETER: '/rsvp/contact-pepper',
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
  contactLookup: contactLookupFor('+351911111111', values['/rsvp/contact-pepper']),
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
  const directory = {
    pk: 'DIRECTORY', sk: 'NICKNAME#toninho', guestId: guest().guestId, nickname: 'Toninho',
  };
  const { handler } = makeHandler({ items: [directory, guest()] });
  const response = await handler(request('/api/guests'));
  assert.equal(response.statusCode, 200);
  const serialized = response.body;
  assert.deepEqual(JSON.parse(serialized), { guests: [{ id: guest().guestId, nickname: 'Toninho' }] });
  assert.doesNotMatch(serialized, /contactLookup|351911111111|contact-pepper/);
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

test('first login creates a five-minute WhatsApp URL without storing the raw nonce', async () => {
  const profile = guest();
  const { handler, ddb } = makeHandler({ items: [profile] });
  const response = await handler(request('/api/auth/start', {
    method: 'POST', body: { guestId: profile.guestId },
  }));
  assert.equal(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.equal(body.mode, 'whatsapp');
  assert.equal(body.expiresAt, fixedNow + 300);
  const url = new URL(body.whatsappUrl);
  assert.equal(url.hostname, 'wa.me');
  assert.equal(url.pathname, '/351910000000');
  assert.match(url.searchParams.get('text'), /^LOGIN [A-Za-z0-9_-]{43} [A-Za-z0-9_-]{43}$/);
  assert.doesNotMatch(response.body, /351911111111/);
  const nonce = url.searchParams.get('text').split(' ')[2];
  assert.ok(ddb.get({ pk: `WHATSAPP#${tokenHash(nonce)}`, sk: 'CHALLENGE' }));
  assert.doesNotMatch(JSON.stringify([...ddb.items.values()]), new RegExp(nonce));
  assert.match(cookieFrom(response, 'rsvp_bootstrap'), /^rsvp_bootstrap=/);
  assert.match(response.cookies.join(' '), /HttpOnly; Secure; SameSite=Lax/);
});

test('phone webhook requires its bearer secret, exact sender, and rejects replay', async () => {
  const profile = guest();
  const { handler } = makeHandler({ items: [profile] });
  const started = await handler(request('/api/auth/start', {
    method: 'POST', body: { guestId: profile.guestId },
  }));
  const message = new URL(JSON.parse(started.body).whatsappUrl).searchParams.get('text');

  const unauthorized = await handler(request('/api/phone/approve', {
    method: 'POST', body: { sender: '+351911111111', message },
  }));
  assert.equal(unauthorized.statusCode, 401);

  const mismatch = await handler(request('/api/phone/approve', {
    method: 'POST',
    headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: '+351922222222', message },
  }));
  assert.equal(mismatch.statusCode, 400);
  assert.equal(JSON.parse(mismatch.body).error, 'sender_mismatch');

  const approved = await handler(request('/api/phone/approve', {
    method: 'POST',
    headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: '+351 911 111 111', message },
  }));
  assert.equal(approved.statusCode, 204);

  const replay = await handler(request('/api/phone/approve', {
    method: 'POST',
    headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: '+351911111111', message },
  }));
  assert.equal(replay.statusCode, 409);
});

test('approved WhatsApp flow registers a passkey, starts a session, and then uses passkey-first login', async () => {
  const profile = guest();
  const { handler, ddb } = makeHandler({ items: [profile] });
  const started = await handler(request('/api/auth/start', {
    method: 'POST', body: { guestId: profile.guestId },
  }));
  const bootstrapCookie = cookieFrom(started, 'rsvp_bootstrap');
  const message = new URL(JSON.parse(started.body).whatsappUrl).searchParams.get('text');
  await handler(request('/api/phone/approve', {
    method: 'POST',
    headers: { authorization: 'Bearer phone-webhook-secret' },
    body: { sender: '+351911111111', message },
  }));

  const status = await handler(request('/api/auth/whatsapp/status', { cookies: [bootstrapCookie] }));
  assert.deepEqual(JSON.parse(status.body), { status: 'approved' });

  const options = await handler(request('/api/auth/passkeys/register/options', {
    method: 'POST', cookies: [bootstrapCookie], body: {},
  }));
  assert.equal(options.statusCode, 200);
  const webauthnCookie = cookieFrom(options, 'rsvp_webauthn');
  const registered = await handler(request('/api/auth/passkeys/register/verify', {
    method: 'POST',
    cookies: [bootstrapCookie, webauthnCookie],
    body: { credential: { id: 'credential-one', response: {} } },
  }));
  assert.equal(registered.statusCode, 200);
  assert.ok(ddb.get({ pk: `GUEST#${profile.guestId}`, sk: 'CREDENTIAL#credential-one' }));
  const sessionCookie = cookieFrom(registered, 'rsvp_session');

  const session = await handler(request('/api/session', { cookies: [sessionCookie] }));
  assert.deepEqual(JSON.parse(session.body), { authenticated: true, nickname: 'Toninho' });

  const loginStart = await handler(request('/api/auth/start', {
    method: 'POST', body: { guestId: profile.guestId },
  }));
  assert.equal(JSON.parse(loginStart.body).mode, 'passkey');
  const loginCookie = cookieFrom(loginStart, 'rsvp_webauthn');
  const login = await handler(request('/api/auth/passkeys/login/verify', {
    method: 'POST',
    cookies: [loginCookie],
    body: { credential: { id: 'credential-one', response: {} } },
  }));
  assert.equal(login.statusCode, 200);
  assert.equal(ddb.get({ pk: `GUEST#${profile.guestId}`, sk: 'CREDENTIAL#credential-one' }).counter, 1);

  const replay = await handler(request('/api/auth/passkeys/login/verify', {
    method: 'POST',
    cookies: [loginCookie],
    body: { credential: { id: 'credential-one', response: {} } },
  }));
  assert.equal(replay.statusCode, 410);
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

import assert from 'node:assert/strict';
import test from 'node:test';
import { contentTypeFor, createHandler, safeObjectKey, secretsMatch } from '../lambda/index.mjs';

const env = {
  ORIGIN_SECRET_PARAMETER: '/rsvp/origin-secret',
  SITE_BUCKET: 'rsvp-test-site',
};

const request = (path = '/', secret = 'correct-secret', method = 'GET') => ({
  rawPath: path,
  headers: { 'x-rsvp-origin-secret': secret },
  requestContext: { http: { method, path } },
});

const makeHandler = (objects = {}) => {
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
  const ssm = { send: async () => ({ Parameter: { Value: 'correct-secret' } }) };
  return { handler: createHandler({ s3, ssm, env }), requests };
};

test('safeObjectKey normalizes valid paths and rejects traversal', () => {
  assert.equal(safeObjectKey('/'), 'index.html');
  assert.equal(safeObjectKey('/assets/app.js'), 'assets/app.js');
  assert.equal(safeObjectKey('/admin/'), 'admin/index.html');
  assert.equal(safeObjectKey('/%2e%2e/private'), null);
  assert.equal(safeObjectKey('/bad%2f..%2fsecret'), null);
  assert.equal(safeObjectKey('/bad%encoding'), null);
  assert.equal(safeObjectKey('/windows\\path'), null);
});

test('origin secrets are compared safely', () => {
  assert.equal(secretsMatch('same', 'same'), true);
  assert.equal(secretsMatch('short', 'longer'), false);
  assert.equal(secretsMatch('', 'secret'), false);
});

test('content types are constrained to known extensions', () => {
  assert.equal(contentTypeFor('index.html'), 'text/html; charset=utf-8');
  assert.equal(contentTypeFor('app.abcdef123456.js'), 'text/javascript; charset=utf-8');
  assert.equal(contentTypeFor('unknown.bin'), 'application/octet-stream');
});

test('rejects requests without the origin secret before accessing S3', async () => {
  const { handler, requests } = makeHandler({ 'index.html': 'secret page' });
  const response = await handler(request('/', 'wrong-secret'));
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

test('API routes return a structured placeholder', async () => {
  const { handler } = makeHandler();
  const response = await handler(request('/api/auth/login', 'correct-secret', 'POST'));
  assert.equal(response.statusCode, 501);
  assert.equal(JSON.parse(response.body).error, 'not_implemented');
});

test('serves static files with immutable caching and defensive headers', async () => {
  const { handler } = makeHandler({ 'app.abcdef123456.js': 'console.log("ok")' });
  const response = await handler(request('/app.abcdef123456.js'));
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'public, max-age=31536000, immutable');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(Buffer.from(response.body, 'base64').toString(), 'console.log("ok")');
});

test('uses index.html as the SPA fallback but not for missing assets', async () => {
  const { handler, requests } = makeHandler({ 'index.html': '<h1>RSVP</h1>' });
  const page = await handler(request('/my-rsvp'));
  assert.equal(page.statusCode, 200);
  assert.deepEqual(requests, ['my-rsvp', 'index.html']);

  const asset = await handler(request('/missing.js'));
  assert.equal(asset.statusCode, 404);
});

test('HEAD responses contain no object body', async () => {
  const { handler } = makeHandler({ 'index.html': '<h1>RSVP</h1>' });
  const response = await handler(request('/', 'correct-secret', 'HEAD'));
  assert.equal(response.statusCode, 200);
  assert.equal(response.body, '');
});

test('rejects unsupported methods for static paths', async () => {
  const { handler } = makeHandler({ 'index.html': '<h1>RSVP</h1>' });
  const response = await handler(request('/', 'correct-secret', 'POST'));
  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, 'GET, HEAD');
});


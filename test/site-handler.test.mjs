import assert from 'node:assert/strict';
import test from 'node:test';
import { contentTypeFor, createSiteHandler, safeObjectKey } from '../lambda/site.mjs';

const env = { SITE_BUCKET: 'rsvp-test-site', ORIGIN_SECRET_PARAMETER: '/rsvp/origin-secret' };
const request = (path, options = {}) => ({ rawPath: path, headers: { 'x-rsvp-origin-secret': options.secret || 'correct-secret' }, requestContext: { http: { method: options.method || 'GET', path } } });
const makeHandler = (objects = {}) => {
  const requests = [];
  const s3 = { send: async (command) => {
    const key = command.input.Key; requests.push(key);
    if (!(key in objects)) { const error = new Error('missing'); error.name = 'NoSuchKey'; throw error; }
    return { Body: Buffer.from(objects[key]) };
  } };
  return { handler: createSiteHandler({ s3, ssm: { send: async () => ({ Parameter: { Value: 'correct-secret' } }) }, env }), requests };
};

test('site handler protects direct access, serves assets, and falls back to the SPA', async () => {
  const { handler, requests } = makeHandler({ 'index.html': '<h1>RSVP</h1>', 'app.abcdef123456.js': 'console.log("ok")' });
  assert.equal((await handler(request('/', { secret: 'wrong-secret' }))).statusCode, 403);
  assert.deepEqual(requests, []);
  const asset = await handler(request('/app.abcdef123456.js'));
  assert.equal(asset.headers['cache-control'], 'public, max-age=31536000, immutable');
  assert.equal(Buffer.from(asset.body, 'base64').toString(), 'console.log("ok")');
  const page = await handler(request('/my-rsvp'));
  assert.equal(Buffer.from(page.body, 'base64').toString(), '<h1>RSVP</h1>');
  assert.deepEqual(requests.slice(-2), ['my-rsvp', 'index.html']);
  assert.equal((await handler(request('/', { method: 'POST' }))).statusCode, 405);
});

test('site path and content type handling is constrained', () => {
  assert.equal(safeObjectKey('/assets/app.js'), 'assets/app.js');
  assert.equal(safeObjectKey('/%2e%2e/private'), null);
  assert.equal(contentTypeFor('index.html'), 'text/html; charset=utf-8');
  assert.equal(contentTypeFor('unknown.bin'), 'application/octet-stream');
});

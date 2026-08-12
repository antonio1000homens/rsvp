import assert from 'node:assert/strict';
import test from 'node:test';
import { originForPath, proxyRequest, validatedOrigin } from '../cloudflare/worker.mjs';

const env = {
  API_ORIGIN_URL: 'https://api.lambda-url.eu-west-2.on.aws/',
  SITE_ORIGIN_URL: 'https://site.lambda-url.eu-west-2.on.aws/',
  ORIGIN_SECRET: 'server-side-secret',
};

test('accepts only the expected HTTPS Lambda origin', () => {
  assert.ok(validatedOrigin(env.API_ORIGIN_URL));
  assert.equal(validatedOrigin('http://example.lambda-url.eu-west-2.on.aws/'), null);
  assert.equal(validatedOrigin('https://example.lambda-url.us-east-1.on.aws/'), null);
  assert.equal(validatedOrigin('https://lambda-url.eu-west-2.on.aws.attacker.example/'), null);
  assert.equal(validatedOrigin('not a URL'), null);
});

test('redirects plain HTTP to HTTPS without contacting the origin', async () => {
  let called = false;
  const response = await proxyRequest(
    new Request('http://calcada2026.pt/rsvp?guest=1'),
    env,
    async () => { called = true; },
  );
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://calcada2026.pt/rsvp?guest=1');
  assert.equal(called, false);
});

test('redirects www to the canonical passkey origin', async () => {
  let called = false;
  const response = await proxyRequest(
    new Request('https://www.calcada2026.pt/login?guest=1'),
    env,
    async () => { called = true; },
  );
  assert.equal(response.status, 308);
  assert.equal(response.headers.get('location'), 'https://calcada2026.pt/login?guest=1');
  assert.equal(called, false);
});

test('replaces a client-supplied origin secret and preserves path and query', async () => {
  let observed;
  const response = await proxyRequest(
    new Request('https://calcada2026.pt/api/example?value=1', {
      headers: { 'x-rsvp-origin-secret': 'attacker-value' },
    }),
    env,
    async (url, init) => {
      observed = { url: String(url), init };
      return new Response('{"ok":true}', {
        status: 200,
        headers: { 'content-type': 'application/json', 'x-amzn-trace-id': 'private-trace' },
      });
    },
  );

  assert.equal(observed.url, 'https://api.lambda-url.eu-west-2.on.aws/api/example?value=1');
  assert.equal(observed.init.headers.get('x-rsvp-origin-secret'), 'server-side-secret');
  assert.equal(observed.init.headers.get('x-forwarded-host'), 'calcada2026.pt');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-amzn-trace-id'), null);
  assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000; includeSubDomains');
});

test('selects isolated API and site origins by path', () => {
  assert.equal(originForPath('/api/link/bootstrap', env), env.API_ORIGIN_URL);
  assert.equal(originForPath('/health', env), env.API_ORIGIN_URL);
  assert.equal(originForPath('/assets/app.js', env), env.SITE_ORIGIN_URL);
});

test('forwards request bodies without logging or parsing them', async () => {
  let body;
  const response = await proxyRequest(
    new Request('https://calcada2026.pt/api/rsvp', { method: 'POST', body: '{"attending":true}' }),
    env,
    async (_url, init) => {
      body = await new Response(init.body).text();
      return new Response(null, { status: 204 });
    },
  );
  assert.equal(body, '{"attending":true}');
  assert.equal(response.status, 204);
});

test('fails closed for missing configuration or origin failures', async () => {
  const missing = await proxyRequest(new Request('https://calcada2026.pt/'), {}, async () => new Response());
  assert.equal(missing.status, 502);

  const failed = await proxyRequest(new Request('https://calcada2026.pt/'), env, async () => {
    throw new Error('network failure');
  });
  assert.equal(failed.status, 502);
  assert.deepEqual(await failed.json(), { error: 'origin_unavailable' });
});

import { timingSafeEqual } from 'node:crypto';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';

const BASE_HEADERS = Object.freeze({
  'content-security-policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});

const CONTENT_TYPES = Object.freeze({
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
});

const jsonResponse = (statusCode, payload, extraHeaders = {}) => ({
  statusCode,
  headers: {
    ...BASE_HEADERS,
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    ...extraHeaders,
  },
  body: JSON.stringify(payload),
});

const headerValue = (headers = {}, wanted) => {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === wanted);
  return key ? String(headers[key]) : '';
};

export const secretsMatch = (provided, expected) => {
  if (!provided || !expected) return false;
  const providedBuffer = Buffer.from(provided, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  return providedBuffer.length === expectedBuffer.length && timingSafeEqual(providedBuffer, expectedBuffer);
};

export const safeObjectKey = (rawPath) => {
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath || '/');
  } catch {
    return null;
  }

  if (!decoded.startsWith('/') || decoded.includes('\\') || decoded.includes('\0')) return null;
  const segments = decoded.split('/').filter(Boolean);
  if (segments.some((segment) => segment === '.' || segment === '..')) return null;
  if (segments.length === 0) return 'index.html';

  const key = segments.join('/');
  return decoded.endsWith('/') ? `${key}/index.html` : key;
};

export const contentTypeFor = (key) => {
  const dot = key.lastIndexOf('.');
  return dot === -1 ? 'application/octet-stream' : CONTENT_TYPES[key.slice(dot).toLowerCase()] || 'application/octet-stream';
};

const bodyToBuffer = async (body) => {
  if (!body) return Buffer.alloc(0);
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (typeof body.transformToByteArray === 'function') return Buffer.from(await body.transformToByteArray());

  const chunks = [];
  for await (const chunk of body) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
};

const isMissingObject = (error) =>
  error?.name === 'NoSuchKey' || error?.name === 'NotFound' || error?.$metadata?.httpStatusCode === 404;

export const createHandler = ({
  s3 = new S3Client({}),
  ssm = new SSMClient({}),
  env = process.env,
} = {}) => {
  let originSecretPromise;

  const getOriginSecret = () => {
    originSecretPromise ??= ssm.send(new GetParameterCommand({
      Name: env.ORIGIN_SECRET_PARAMETER,
      WithDecryption: true,
    })).then((result) => result.Parameter?.Value || '');
    return originSecretPromise;
  };

  const fetchObject = async (key) => {
    const result = await s3.send(new GetObjectCommand({ Bucket: env.SITE_BUCKET, Key: key }));
    return bodyToBuffer(result.Body);
  };

  return async (event = {}) => {
    const expectedSecret = await getOriginSecret().catch(() => '');
    const providedSecret = headerValue(event.headers, 'x-rsvp-origin-secret');
    if (!secretsMatch(providedSecret, expectedSecret)) {
      return jsonResponse(403, { error: 'forbidden' });
    }

    const rawPath = event.rawPath || event.requestContext?.http?.path || '/';
    const method = event.requestContext?.http?.method || event.httpMethod || 'GET';

    if (rawPath === '/health') {
      return jsonResponse(200, { status: 'ok' });
    }

    if (rawPath === '/api' || rawPath.startsWith('/api/')) {
      return jsonResponse(501, {
        error: 'not_implemented',
        message: 'The RSVP API is not available yet.',
      });
    }

    if (method !== 'GET' && method !== 'HEAD') {
      return jsonResponse(405, { error: 'method_not_allowed' }, { allow: 'GET, HEAD' });
    }

    const key = safeObjectKey(rawPath);
    if (!key) return jsonResponse(400, { error: 'invalid_path' });

    let resolvedKey = key;
    let contents;
    try {
      contents = await fetchObject(resolvedKey);
    } catch (error) {
      const spaCandidate = !key.split('/').at(-1).includes('.');
      if (!isMissingObject(error) || !spaCandidate) {
        return jsonResponse(isMissingObject(error) ? 404 : 500, {
          error: isMissingObject(error) ? 'not_found' : 'internal_error',
        });
      }

      resolvedKey = 'index.html';
      try {
        contents = await fetchObject(resolvedKey);
      } catch (fallbackError) {
        return jsonResponse(isMissingObject(fallbackError) ? 404 : 500, {
          error: isMissingObject(fallbackError) ? 'not_found' : 'internal_error',
        });
      }
    }

    const immutable = /\.[a-f0-9]{12}\.[a-z0-9]+$/i.test(resolvedKey);
    return {
      statusCode: 200,
      headers: {
        ...BASE_HEADERS,
        'cache-control': immutable ? 'public, max-age=31536000, immutable' : 'no-cache',
        'content-type': contentTypeFor(resolvedKey),
      },
      isBase64Encoded: true,
      body: method === 'HEAD' ? '' : contents.toString('base64'),
    };
  };
};

export const handler = createHandler();


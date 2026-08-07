import { createHmac, randomBytes as nodeRandomBytes, randomUUID } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  contactLookupFor,
  fromBase64Url,
  normalizeE164,
  normalizeNickname,
  normalizePhoneLast4,
  safeEqual,
  toBase64Url,
  tokenHash,
} from '../shared/identity.mjs';

const BASE_HEADERS = Object.freeze({
  'content-security-policy': "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com",
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

const MAX_JSON_BYTES = 64 * 1024;
const WHATSAPP_TTL_SECONDS = 5 * 60;
const WEBAUTHN_TTL_SECONDS = 5 * 60;
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const CAPTCHA_TTL_SECONDS = 15 * 60;
const LOGIN_MESSAGE = /^LOGIN ([A-Za-z0-9_-]{43}) ([A-Za-z0-9_-]{43})$/;
const VALIDATION_MESSAGE = /^VALIDATION ([A-Za-z0-9_-]+) ([A-Za-z0-9_-]{43})$/;
const GUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TRIVIA_QUESTIONS = Object.freeze([
  { id: 'policia', question: 'Quem é o polícia?', answers: ['rui', 'checa'] },
  { id: 'vacas', question: 'Um dos irmãos Vacas', answers: ['rui', 'goncalo'] },
]);

const jsonResponse = (statusCode, payload, { headers = {}, cookies = [] } = {}) => ({
  statusCode,
  headers: {
    ...BASE_HEADERS,
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    ...headers,
  },
  ...(cookies.length > 0 ? { cookies } : {}),
  body: JSON.stringify(payload),
});

const emptyResponse = (statusCode, { cookies = [] } = {}) => ({
  statusCode,
  headers: { ...BASE_HEADERS, 'cache-control': 'no-store' },
  ...(cookies.length > 0 ? { cookies } : {}),
  body: '',
});

const headerValue = (headers = {}, wanted) => {
  const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === wanted.toLowerCase());
  return key ? String(headers[key]) : '';
};

const cookieValue = (event, wanted) => {
  const candidates = [
    ...(Array.isArray(event.cookies) ? event.cookies : []),
    ...headerValue(event.headers, 'cookie').split(';'),
  ];
  for (const candidate of candidates) {
    const [name, ...parts] = String(candidate).trim().split('=');
    if (name === wanted) return parts.join('=');
  }
  return '';
};

const setCookie = (name, value, maxAge) =>
  `${name}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
const clearCookie = (name) => setCookie(name, '', 0);

const unixNow = () => Math.floor(Date.now() / 1000);

class ApiError extends Error {
  constructor(statusCode, code, message = code) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export const secretsMatch = safeEqual;

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

export const signToken = (payload, secret) => {
  const encoded = toBase64Url(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
};

export const verifyToken = (value, secret, now = unixNow()) => {
  const [encoded, signature, extra] = String(value || '').split('.');
  if (!encoded || !signature || extra) return null;
  const expected = createHmac('sha256', secret).update(encoded).digest('base64url');
  if (!safeEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return Number.isInteger(payload.exp) && payload.exp >= now ? payload : null;
  } catch {
    return null;
  }
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

const parseJsonBody = (event) => {
  const contents = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64')
    : Buffer.from(event.body || '', 'utf8');
  if (contents.length > MAX_JSON_BYTES) throw new ApiError(413, 'payload_too_large');
  if (contents.length === 0) return {};
  try {
    const parsed = JSON.parse(contents.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid');
    return parsed;
  } catch {
    throw new ApiError(400, 'invalid_json');
  }
};

const validGuestId = (value) => {
  const guestId = String(value || '');
  if (!GUEST_ID.test(guestId)) throw new ApiError(400, 'invalid_guest');
  return guestId;
};

const conditionalFailure = (error) =>
  error?.name === 'ConditionalCheckFailedException' || error?.name === 'TransactionCanceledException';

const normalizeTriviaAnswer = (value) => String(value || '').normalize('NFKD')
  .replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pt-PT').trim();

export const triviaAnswerMatches = (answer, acceptedAnswers) => {
  const normalized = normalizeTriviaAnswer(answer);
  return acceptedAnswers.some((accepted) => normalized.includes(normalizeTriviaAnswer(accepted)));
};

export const createHandler = ({
  s3 = new S3Client({}),
  ssm = new SSMClient({}),
  ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), {
    marshallOptions: { removeUndefinedValues: true },
  }),
  webauthn = {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
  },
  env = process.env,
  now = unixNow,
  randomBytes = nodeRandomBytes,
  turnstileValidate = async (token, secret, remoteIp) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ secret, response: token, ...(remoteIp ? { remoteip: remoteIp } : {}) }),
        signal: controller.signal,
      });
      return await response.json();
    } catch {
      return { success: false };
    } finally {
      clearTimeout(timeout);
    }
  },
} = {}) => {
  const secretPromises = new Map();

  const getParameter = (name, withDecryption = true, cache = true) => {
    if (!name) return Promise.resolve('');
    if (!cache) {
      return ssm.send(new GetParameterCommand({ Name: name, WithDecryption: withDecryption }))
        .then((result) => result.Parameter?.Value || '');
    }
    const cacheKey = `${name}:${withDecryption}`;
    if (!secretPromises.has(cacheKey)) {
      secretPromises.set(cacheKey, ssm.send(new GetParameterCommand({
        Name: name,
        WithDecryption: withDecryption,
      })).then((result) => result.Parameter?.Value || ''));
    }
    return secretPromises.get(cacheKey);
  };

  const getOriginSecret = () => getParameter(env.ORIGIN_SECRET_PARAMETER);
  const getSessionSecret = () => getParameter(env.SESSION_SECRET_PARAMETER);
  const getContactPepper = () => getParameter(env.CONTACT_PEPPER_PARAMETER);
  const getPhoneWebhookSecret = () => getParameter(env.PHONE_WEBHOOK_SECRET_PARAMETER, true, false);
  const getValidationSecret = () => getParameter(env.VALIDATION_SECRET_PARAMETER, true, false);
  const getWhatsappNumber = () => getParameter(env.WHATSAPP_NUMBER_PARAMETER, false);
  const getTurnstileSiteKey = () => getParameter(env.TURNSTILE_SITE_KEY_PARAMETER, false, false).catch(() => '');
  const getTurnstileSecret = () => getParameter(env.TURNSTILE_SECRET_PARAMETER, true, false).catch(() => '');

  const fetchObject = async (key) => {
    const result = await s3.send(new GetObjectCommand({ Bucket: env.SITE_BUCKET, Key: key }));
    return bodyToBuffer(result.Body);
  };

  const getGuest = async (guestId) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `GUEST#${guestId}`, sk: 'PROFILE' },
      ConsistentRead: true,
    }));
    if (!result.Item?.enabled) throw new ApiError(404, 'guest_not_found');
    return result.Item;
  };

  const getCredentials = async (guestId) => {
    const result = await ddb.send(new QueryCommand({
      TableName: env.RSVP_TABLE,
      KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
      ExpressionAttributeValues: {
        ':pk': `GUEST#${guestId}`,
        ':prefix': 'CREDENTIAL#',
      },
      ConsistentRead: true,
    }));
    return result.Items || [];
  };

  const makeSignedCookie = async (name, payload, ttl) => {
    const secret = await getSessionSecret();
    if (!secret) throw new ApiError(503, 'authentication_unavailable');
    return setCookie(name, signToken({ ...payload, exp: now() + ttl }, secret), ttl);
  };

  const readSignedCookie = async (event, name) => {
    const secret = await getSessionSecret();
    if (!secret) return null;
    return verifyToken(cookieValue(event, name), secret, now());
  };

  const issueSessionCookie = async (guest) => makeSignedCookie('rsvp_session', {
    type: 'session',
    guestId: guest.guestId,
    sessionVersion: Number(guest.sessionVersion || 1),
  }, SESSION_TTL_SECONDS);

  const readCaptchaGate = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_captcha');
    return token?.type === 'captcha';
  };

  const readTriviaGate = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_trivia');
    return token?.type === 'trivia' && token.answered === true;
  };

  const requireTriviaGate = async (event) => {
    if (!(await readCaptchaGate(event))) throw new ApiError(403, 'captcha_required');
    if (!(await readTriviaGate(event))) throw new ApiError(403, 'trivia_required');
  };

  const triviaQuestion = async (event) => {
    await requireCaptchaGate(event);
    const question = TRIVIA_QUESTIONS[Math.floor(Math.random() * TRIVIA_QUESTIONS.length)];
    const cookie = await makeSignedCookie('rsvp_trivia_challenge', {
      type: 'trivia-challenge', questionId: question.id,
    }, CAPTCHA_TTL_SECONDS);
    const challenge = cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';'));
    return jsonResponse(200, { question: question.question, challenge });
  };

  const triviaAnswer = async (event) => {
    await requireCaptchaGate(event);
    const body = parseJsonBody(event);
    const challenge = verifyToken(body.challenge, await getSessionSecret(), now());
    const question = TRIVIA_QUESTIONS.find((candidate) => candidate.id === challenge?.questionId);
    if (!question || challenge?.type !== 'trivia-challenge' || !triviaAnswerMatches(body.answer, question.answers)) {
      throw new ApiError(403, 'trivia_incorrect');
    }
    return jsonResponse(200, { verified: true }, {
      cookies: [await makeSignedCookie('rsvp_trivia', { type: 'trivia', answered: true }, CAPTCHA_TTL_SECONDS)],
    });
  };

  const requireCaptchaGate = async (event) => {
    if (await readCaptchaGate(event)) return [];
    const token = headerValue(event.headers, 'x-turnstile-token');
    if (!token || token.length > 2048) throw new ApiError(403, 'captcha_required');
    const secret = await getTurnstileSecret();
    if (!secret) throw new ApiError(503, 'captcha_unavailable');
    const result = await turnstileValidate(token, secret, headerValue(event.headers, 'cf-connecting-ip'));
    if (!result?.success || (result.action && result.action !== 'guest-directory') ||
        (result.hostname && result.hostname !== (env.TURNSTILE_HOSTNAME || 'calcada2026.pt'))) {
      throw new ApiError(403, 'captcha_failed');
    }
    return [await makeSignedCookie('rsvp_captcha', { type: 'captcha' }, CAPTCHA_TTL_SECONDS)];
  };

  const readSessionGuest = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_session');
    if (token?.type !== 'session' || !GUEST_ID.test(String(token.guestId || ''))) return null;
    try {
      const guest = await getGuest(token.guestId);
      return Number(guest.sessionVersion || 1) === Number(token.sessionVersion) ? guest : null;
    } catch {
      return null;
    }
  };

  const getWhatsappChallenge = async (nonce) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `WHATSAPP#${tokenHash(nonce)}`, sk: 'CHALLENGE' },
      ConsistentRead: true,
    }));
    return result.Item || null;
  };

  const startWhatsapp = async (guest) => {
    let appNumber;
    try {
      appNumber = normalizeE164(await getWhatsappNumber());
    } catch {
      throw new ApiError(503, 'whatsapp_unavailable');
    }
    const nonce = toBase64Url(randomBytes(32));
    const expiresAt = now() + WHATSAPP_TTL_SECONDS;
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `WHATSAPP#${tokenHash(nonce)}`,
        sk: 'CHALLENGE',
        entityType: 'whatsappChallenge',
        guestId: guest.guestId,
        expectedContactLookup: guest.contactLookup,
        status: 'pending',
        expiresAt,
        createdAt: now(),
      },
      ConditionExpression: 'attribute_not_exists(pk)',
    }));

    const message = `LOGIN ${guest.contactLookup} ${nonce}`;
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', message);
    const cookie = await makeSignedCookie('rsvp_bootstrap', {
      type: 'whatsapp', guestId: guest.guestId, nonce,
    }, WHATSAPP_TTL_SECONDS);
    return jsonResponse(200, {
      mode: 'whatsapp',
      whatsappUrl: whatsappUrl.toString(),
      expiresAt,
    }, { cookies: [cookie, clearCookie('rsvp_webauthn')] });
  };

  const createWebauthnFlow = async (guestId, purpose, options) => {
    const nonce = toBase64Url(randomBytes(32));
    const expiresAt = now() + WEBAUTHN_TTL_SECONDS;
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `WEBAUTHN#${tokenHash(nonce)}`,
        sk: 'CHALLENGE',
        entityType: 'webauthnChallenge',
        guestId,
        purpose,
        status: 'pending',
        expiresAt,
      },
      ConditionExpression: 'attribute_not_exists(pk)',
    }));
    const cookie = await makeSignedCookie('rsvp_webauthn', {
      type: 'webauthn', purpose, guestId, challenge: options.challenge, nonce,
    }, WEBAUTHN_TTL_SECONDS);
    return cookie;
  };

  const getWebauthnFlow = async (event, purpose) => {
    const token = await readSignedCookie(event, 'rsvp_webauthn');
    if (token?.type !== 'webauthn' || token.purpose !== purpose || !GUEST_ID.test(String(token.guestId || ''))) {
      throw new ApiError(401, 'invalid_authentication_challenge');
    }
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `WEBAUTHN#${tokenHash(token.nonce)}`, sk: 'CHALLENGE' },
      ConsistentRead: true,
    }));
    const item = result.Item;
    if (!item || item.status !== 'pending' || item.expiresAt < now() || item.guestId !== token.guestId || item.purpose !== purpose) {
      throw new ApiError(410, 'authentication_challenge_expired');
    }
    return { token, item };
  };

  const bootstrapGuest = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_bootstrap');
    if (token?.type !== 'whatsapp' || !GUEST_ID.test(String(token.guestId || ''))) return null;
    const challenge = await getWhatsappChallenge(token.nonce);
    if (!challenge || challenge.status !== 'approved' || challenge.expiresAt < now() || challenge.guestId !== token.guestId) return null;
    return getGuest(token.guestId);
  };

  const authorizedRegistrationGuest = async (event) => {
    const sessionGuest = await readSessionGuest(event);
    if (sessionGuest) return sessionGuest;
    const guest = await bootstrapGuest(event);
    if (guest) return guest;
    const token = await readSignedCookie(event, 'rsvp_registration');
    if (token?.type === 'registration') {
      const challenge = await getRegistrationChallenge(token.nonce);
      if (challenge?.status === 'created' && challenge.guestId && challenge.expiresAt >= now()) return getGuest(challenge.guestId);
    }
    throw new ApiError(401, 'whatsapp_approval_required');
  };

  const listGuests = async () => {
    const result = await ddb.send(new QueryCommand({
      TableName: env.RSVP_TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': 'DIRECTORY' },
      ProjectionExpression: 'guestId, nickname',
    }));
    const guests = (result.Items || [])
      .map(({ guestId, nickname }) => ({ id: guestId, nickname }))
      .sort((left, right) => left.nickname.localeCompare(right.nickname));
    return jsonResponse(200, { guests });
  };

  const authStart = async (event) => {
    await requireCaptchaGate(event);
    const { guestId: requestedGuestId } = parseJsonBody(event);
    const guest = await getGuest(validGuestId(requestedGuestId));
    const credentials = await getCredentials(guest.guestId);
    if (credentials.length === 0) return startWhatsapp(guest);

    const options = await webauthn.generateAuthenticationOptions({
      rpID: env.WEBAUTHN_RP_ID,
      userVerification: 'required',
      allowCredentials: credentials.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports || [],
      })),
    });
    const cookie = await createWebauthnFlow(guest.guestId, 'login', options);
    return jsonResponse(200, { mode: 'passkey', options }, { cookies: [cookie] });
  };

  const whatsappStart = async (event) => {
    await requireCaptchaGate(event);
    const { guestId: requestedGuestId } = parseJsonBody(event);
    return startWhatsapp(await getGuest(validGuestId(requestedGuestId)));
  };

  const whatsappStatus = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_bootstrap');
    if (token?.type !== 'whatsapp') {
      return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_bootstrap')] });
    }
    const challenge = await getWhatsappChallenge(token.nonce);
    if (!challenge || challenge.expiresAt < now()) {
      return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_bootstrap')] });
    }
    return jsonResponse(200, { status: challenge.status === 'approved' ? 'approved' : 'pending' });
  };

  const getRegistrationChallenge = async (nonce) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE' },
      ConsistentRead: true,
    }));
    return result.Item || null;
  };

  const startFriendRegistration = async (event) => {
    await requireCaptchaGate(event);
    const body = parseJsonBody(event);
    let nickname;
    let phone;
    try {
      nickname = normalizeNickname(body.name);
      phone = normalizeE164(body.phone);
    } catch (error) {
      throw new ApiError(400, 'invalid_registration', error.message);
    }
    const nonce = toBase64Url(randomBytes(32));
    const expiresAt = now() + WHATSAPP_TTL_SECONDS;
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `REGISTRATION#${tokenHash(nonce)}`,
        sk: 'CHALLENGE',
        entityType: 'registrationChallenge',
        nickname: nickname.display,
        nicknameLookup: nickname.lookup,
        last4: phone.slice(-4),
        status: 'pending',
        expiresAt,
        createdAt: now(),
      },
      ConditionExpression: 'attribute_not_exists(pk)',
    }));
    let appNumber;
    try {
      appNumber = normalizeE164(await getWhatsappNumber());
    } catch {
      throw new ApiError(503, 'whatsapp_unavailable');
    }
    const payload = Buffer.from(JSON.stringify({ name: nickname.display, number: last4, nonce }), 'utf8').toString('base64url');
    const validationSecret = await getValidationSecret();
    if (!validationSecret) throw new ApiError(503, 'validation_unavailable');
    const signature = createHmac('sha256', validationSecret).update(payload, 'utf8').digest('base64url');
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', `VALIDATION ${payload} ${signature}`);
    const cookie = await makeSignedCookie('rsvp_registration', { type: 'registration', nonce }, WHATSAPP_TTL_SECONDS);
    return jsonResponse(200, { mode: 'registration', whatsappUrl: whatsappUrl.toString(), expiresAt }, { cookies: [cookie] });
  };

  const registrationStatus = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_registration');
    if (token?.type !== 'registration') return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_registration')] });
    const challenge = await getRegistrationChallenge(token.nonce);
    if (!challenge || challenge.expiresAt < now()) return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_registration')] });
    return jsonResponse(200, { status: challenge.status === 'created' ? 'created' : 'pending' });
  };

  const approvePhoneWebhook = async (event) => {
    const authorization = headerValue(event.headers, 'authorization');
    const expectedSecret = await getPhoneWebhookSecret();
    const providedSecret = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!safeEqual(providedSecret, expectedSecret)) throw new ApiError(401, 'unauthorized');

    const { sender, message } = parseJsonBody(event);
    let normalizedSender;
    try {
      normalizedSender = normalizeE164(sender);
    } catch {
      throw new ApiError(400, 'invalid_sender');
    }
    const match = LOGIN_MESSAGE.exec(String(message || ''));
    if (!match) throw new ApiError(400, 'invalid_login_message');
    const [, claimedLookup, nonce] = match;
    const pepper = await getContactPepper();
    const senderLookup = contactLookupFor(normalizedSender, pepper);
    if (!safeEqual(senderLookup, claimedLookup)) throw new ApiError(400, 'sender_mismatch');

    const key = { pk: `WHATSAPP#${tokenHash(nonce)}`, sk: 'CHALLENGE' };
    const existing = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: key,
      ConsistentRead: true,
    }));
    const challenge = existing.Item;
    if (!challenge || !safeEqual(challenge.expectedContactLookup, senderLookup)) throw new ApiError(400, 'invalid_login_message');
    if (challenge.expiresAt < now()) throw new ApiError(410, 'login_challenge_expired');
    if (challenge.status !== 'pending') throw new ApiError(409, 'login_challenge_already_used');

    try {
      await ddb.send(new UpdateCommand({
        TableName: env.RSVP_TABLE,
        Key: key,
        UpdateExpression: 'SET #status = :approved, approvedAt = :now',
        ConditionExpression: '#status = :pending AND expiresAt >= :now AND expectedContactLookup = :lookup',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':approved': 'approved', ':pending': 'pending', ':now': now(), ':lookup': senderLookup,
        },
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'login_challenge_already_used');
      throw error;
    }
    return emptyResponse(204);
  };

  const registerPhoneWebhook = async (event) => {
    const authorization = headerValue(event.headers, 'authorization');
    const expectedSecret = await getPhoneWebhookSecret();
    const providedSecret = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!safeEqual(providedSecret, expectedSecret)) throw new ApiError(401, 'unauthorized');
    const { sender, message } = parseJsonBody(event);
    let normalizedSender;
    try { normalizedSender = normalizeE164(sender); } catch { throw new ApiError(400, 'invalid_sender'); }
    const match = VALIDATION_MESSAGE.exec(String(message || ''));
    if (!match) throw new ApiError(400, 'invalid_validation_message');
    const [, payloadEncoded, signature] = match;
    const validationSecret = await getValidationSecret();
    if (!validationSecret) throw new ApiError(503, 'validation_unavailable');
    const expectedSignature = createHmac('sha256', validationSecret).update(payloadEncoded, 'utf8').digest('base64url');
    if (!safeEqual(signature, expectedSignature)) throw new ApiError(400, 'invalid_validation_signature');
    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
      if (!payload || typeof payload !== 'object') throw new Error('invalid');
    } catch { throw new ApiError(400, 'invalid_validation_message'); }
    let nickname;
    let last4;
    try { nickname = normalizeNickname(payload.name); last4 = normalizePhoneLast4(payload.number); } catch { throw new ApiError(400, 'invalid_validation_message'); }
    if (normalizedSender.slice(-4) !== last4 || typeof payload.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(payload.nonce)) {
      throw new ApiError(400, 'sender_mismatch');
    }
    const key = { pk: `REGISTRATION#${tokenHash(payload.nonce)}`, sk: 'CHALLENGE' };
    const existing = await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: key, ConsistentRead: true }));
    const challenge = existing.Item;
    if (!challenge || challenge.status !== 'pending' || challenge.expiresAt < now() || challenge.nicknameLookup !== nickname.lookup || challenge.last4 !== last4) {
      throw new ApiError(challenge?.status === 'created' ? 409 : 410, 'registration_challenge_unavailable');
    }
    const pepper = await getContactPepper();
    const contactLookup = contactLookupFor(normalizedSender, pepper);
    const guestId = randomUUID();
    try {
      await ddb.send(new TransactWriteCommand({ TransactItems: [
        { Update: { TableName: env.RSVP_TABLE, Key: key, UpdateExpression: 'SET #status = :created, guestId = :guestId, contactLookup = :lookup, approvedAt = :now', ConditionExpression: '#status = :pending AND expiresAt >= :now', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':created': 'created', ':pending': 'pending', ':now': now(), ':guestId': guestId, ':lookup': contactLookup } } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${guestId}`, sk: 'PROFILE', entityType: 'guest', guestId, nickname: nickname.display, contactLookup, enabled: true, sessionVersion: 1, createdAt: now() }, ConditionExpression: 'attribute_not_exists(pk)' } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: 'DIRECTORY', sk: `NICKNAME#${nickname.lookup}`, entityType: 'directory', guestId, nickname: nickname.display }, ConditionExpression: 'attribute_not_exists(pk)' } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: `CONTACT#${contactLookup}`, sk: 'LOOKUP', entityType: 'contactLock', guestId }, ConditionExpression: 'attribute_not_exists(pk)' } },
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'registration_unavailable');
      throw error;
    }
    return emptyResponse(204);
  };

  const registrationOptions = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    const credentials = await getCredentials(guest.guestId);
    const options = await webauthn.generateRegistrationOptions({
      rpName: env.WEBAUTHN_RP_NAME || 'Calçada 2026 RSVP',
      rpID: env.WEBAUTHN_RP_ID,
      userID: Buffer.from(guest.guestId, 'utf8'),
      userName: guest.guestId,
      userDisplayName: guest.nickname,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports || [],
      })),
    });
    const cookie = await createWebauthnFlow(guest.guestId, 'register', options);
    return jsonResponse(200, { options }, { cookies: [cookie] });
  };

  const registrationVerify = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    const { token, item } = await getWebauthnFlow(event, 'register');
    if (token.guestId !== guest.guestId) throw new ApiError(401, 'invalid_authentication_challenge');
    const { credential } = parseJsonBody(event);
    if (!credential?.id) throw new ApiError(400, 'invalid_passkey');

    let verification;
    try {
      verification = await webauthn.verifyRegistrationResponse({
        response: credential,
        expectedChallenge: token.challenge,
        expectedOrigin: env.WEBAUTHN_EXPECTED_ORIGIN,
        expectedRPID: env.WEBAUTHN_RP_ID,
        requireUserVerification: true,
      });
    } catch {
      throw new ApiError(400, 'passkey_verification_failed');
    }
    if (!verification.verified || !verification.registrationInfo?.credential) {
      throw new ApiError(400, 'passkey_verification_failed');
    }
    const registered = verification.registrationInfo.credential;
    const credentialId = registered.id;
    try {
      await ddb.send(new TransactWriteCommand({
        TransactItems: [
          {
            Update: {
              TableName: env.RSVP_TABLE,
              Key: { pk: item.pk, sk: item.sk },
              UpdateExpression: 'SET #status = :used, usedAt = :now',
              ConditionExpression: '#status = :pending AND expiresAt >= :now',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: { ':used': 'used', ':pending': 'pending', ':now': now() },
            },
          },
          {
            Put: {
              TableName: env.RSVP_TABLE,
              Item: {
                pk: `GUEST#${guest.guestId}`,
                sk: `CREDENTIAL#${credentialId}`,
                entityType: 'passkey',
                credentialId,
                publicKey: toBase64Url(registered.publicKey),
                counter: Number(registered.counter || 0),
                transports: registered.transports || credential.response?.transports || [],
                deviceType: verification.registrationInfo.credentialDeviceType,
                backedUp: Boolean(verification.registrationInfo.credentialBackedUp),
                createdAt: now(),
              },
              ConditionExpression: 'attribute_not_exists(pk)',
            },
          },
        ],
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'passkey_or_challenge_already_used');
      throw error;
    }
    const sessionCookie = await issueSessionCookie(guest);
    return jsonResponse(200, { authenticated: true, nickname: guest.nickname }, {
      cookies: [sessionCookie, clearCookie('rsvp_bootstrap'), clearCookie('rsvp_registration'), clearCookie('rsvp_webauthn')],
    });
  };

  const loginVerify = async (event) => {
    const { token, item } = await getWebauthnFlow(event, 'login');
    const guest = await getGuest(token.guestId);
    const { credential } = parseJsonBody(event);
    if (!credential?.id) throw new ApiError(400, 'invalid_passkey');
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `GUEST#${guest.guestId}`, sk: `CREDENTIAL#${credential.id}` },
      ConsistentRead: true,
    }));
    const stored = result.Item;
    if (!stored) throw new ApiError(400, 'passkey_verification_failed');

    let verification;
    try {
      verification = await webauthn.verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: token.challenge,
        expectedOrigin: env.WEBAUTHN_EXPECTED_ORIGIN,
        expectedRPID: env.WEBAUTHN_RP_ID,
        credential: {
          id: stored.credentialId,
          publicKey: fromBase64Url(stored.publicKey),
          counter: Number(stored.counter || 0),
          transports: stored.transports || [],
        },
        requireUserVerification: true,
      });
    } catch {
      throw new ApiError(400, 'passkey_verification_failed');
    }
    if (!verification.verified) throw new ApiError(400, 'passkey_verification_failed');
    try {
      await ddb.send(new TransactWriteCommand({
        TransactItems: [
          {
            Update: {
              TableName: env.RSVP_TABLE,
              Key: { pk: item.pk, sk: item.sk },
              UpdateExpression: 'SET #status = :used, usedAt = :now',
              ConditionExpression: '#status = :pending AND expiresAt >= :now',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: { ':used': 'used', ':pending': 'pending', ':now': now() },
            },
          },
          {
            Update: {
              TableName: env.RSVP_TABLE,
              Key: { pk: stored.pk, sk: stored.sk },
              UpdateExpression: 'SET #counter = :next, lastUsedAt = :now',
              ConditionExpression: '#counter = :previous',
              ExpressionAttributeNames: { '#counter': 'counter' },
              ExpressionAttributeValues: {
                ':next': Number(verification.authenticationInfo.newCounter || 0),
                ':previous': Number(stored.counter || 0),
                ':now': now(),
              },
            },
          },
        ],
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'passkey_or_challenge_already_used');
      throw error;
    }
    return jsonResponse(200, { authenticated: true, nickname: guest.nickname }, {
      cookies: [await issueSessionCookie(guest), clearCookie('rsvp_webauthn')],
    });
  };

  const sessionStatus = async (event) => {
    const guest = await readSessionGuest(event);
    return jsonResponse(200, guest
      ? { authenticated: true, nickname: guest.nickname }
      : { authenticated: false },
    );
  };

  const api = async (event, path, method) => {
    if (path === '/api/captcha/config' && method === 'GET') {
      const siteKey = await getTurnstileSiteKey();
      if (!siteKey) throw new ApiError(503, 'captcha_unavailable');
      return jsonResponse(200, { siteKey });
    }
    if (path === '/api/trivia/question' && method === 'GET') return triviaQuestion(event);
    if (path === '/api/trivia/answer' && method === 'POST') return triviaAnswer(event);
    if (path === '/api/guests' && method === 'GET') {
      await requireTriviaGate(event);
      const captchaCookies = [];
      const response = await listGuests();
      if (captchaCookies.length > 0) response.cookies = captchaCookies;
      return response;
    }
    if (path === '/api/auth/start' && method === 'POST') return authStart(event);
    if (path === '/api/auth/whatsapp/start' && method === 'POST') return whatsappStart(event);
    if (path === '/api/auth/whatsapp/status' && method === 'GET') return whatsappStatus(event);
    if (path === '/api/phone/approve' && method === 'POST') return approvePhoneWebhook(event);
    if (path === '/api/register/start' && method === 'POST') return startFriendRegistration(event);
    if (path === '/api/register/status' && method === 'GET') return registrationStatus(event);
    if (path === '/api/phone/register' && method === 'POST') return registerPhoneWebhook(event);
    if (path === '/api/auth/passkeys/register/options' && method === 'POST') return registrationOptions(event);
    if (path === '/api/auth/passkeys/register/verify' && method === 'POST') return registrationVerify(event);
    if (path === '/api/auth/passkeys/login/verify' && method === 'POST') return loginVerify(event);
    if (path === '/api/session' && method === 'GET') return sessionStatus(event);
    if (path === '/api/auth/logout' && method === 'POST') {
      return jsonResponse(200, { authenticated: false }, {
        cookies: [clearCookie('rsvp_session'), clearCookie('rsvp_bootstrap'), clearCookie('rsvp_registration'), clearCookie('rsvp_webauthn')],
      });
    }
    throw new ApiError(404, 'not_found');
  };

  return async (event = {}) => {
    const expectedSecret = await getOriginSecret().catch(() => '');
    const providedSecret = headerValue(event.headers, 'x-rsvp-origin-secret');
    if (!safeEqual(providedSecret, expectedSecret)) return jsonResponse(403, { error: 'forbidden' });

    const rawPath = event.rawPath || event.requestContext?.http?.path || '/';
    const method = event.requestContext?.http?.method || event.httpMethod || 'GET';

    if (rawPath === '/health') return jsonResponse(200, { status: 'ok' });
    if (rawPath === '/api' || rawPath.startsWith('/api/')) {
      try {
        return await api(event, rawPath, method);
      } catch (error) {
        if (error instanceof ApiError) {
          return jsonResponse(error.statusCode, { error: error.code, message: error.message });
        }
        return jsonResponse(500, { error: 'internal_error' });
      }
    }

    if (method !== 'GET' && method !== 'HEAD') {
      return jsonResponse(405, { error: 'method_not_allowed' }, { headers: { allow: 'GET, HEAD' } });
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

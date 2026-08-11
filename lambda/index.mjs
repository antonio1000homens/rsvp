import { createHmac, randomBytes as nodeRandomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { SendMessageCommand, SQSClient } from '@aws-sdk/client-sqs';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  fromBase64Url,
  normalizeContactName,
  normalizeE164,
  normalizeNickname,
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
const WHATSAPP_TTL_SECONDS = 30 * 60;
const PENDING_SUBMISSION_TTL_SECONDS = 24 * 60 * 60;
const WEBAUTHN_TTL_SECONDS = 5 * 60;
const SESSION_TTL_SECONDS = 24 * 60 * 60;
const ADMIN_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const CAPTCHA_TTL_SECONDS = 15 * 60;
const ACCESS_LINK_TTL_SECONDS = 30 * 24 * 60 * 60;
const ACCESS_LINK_AUTH_TTL_SECONDS = 10 * 60;
const GUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GROUP_ID = /^[a-z0-9][a-z0-9-]{0,62}$/;
const CONTACT_REQUEST_NUMBER = '+447810354233';

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

const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;
const PASSWORD_KEYLEN = 64;

const passwordText = (value) => typeof value === 'string' ? value : '';

export const validatePassword = (value) => {
  const password = passwordText(value);
  const length = [...password].length;
  if (length < PASSWORD_MIN_LENGTH || length > PASSWORD_MAX_LENGTH) throw new ApiError(400, 'invalid_password');
  return password;
};

export const hashPassword = (value) => {
  const password = validatePassword(value);
  const salt = nodeRandomBytes(16).toString('base64url');
  const derived = scryptSync(password, Buffer.from(salt, 'base64url'), PASSWORD_KEYLEN, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$8$1$${salt}$${derived.toString('base64url')}`;
};

export const verifyPassword = (value, encoded) => {
  const password = passwordText(value);
  const parts = String(encoded || '').split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, expectedEncoded] = parts;
  const expected = Buffer.from(expectedEncoded, 'base64url');
  if (!expected.length || !salt || !/^\d+$/.test(n) || !/^\d+$/.test(r) || !/^\d+$/.test(p)) return false;
  try {
    const actual = scryptSync(password, Buffer.from(salt, 'base64url'), expected.length, { N: Number(n), r: Number(r), p: Number(p) });
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
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

const validGroupId = (value) => {
  const groupId = String(value || '');
  if (!GROUP_ID.test(groupId)) throw new ApiError(400, 'invalid_group');
  return groupId;
};

const availabilityDays = (env) => {
  const days = String(env.RSVP_DAYS || '19 December 2026,20 December 2026,21 December 2026,22 December 2026,23 December 2026').split(',').map((day) => day.trim()).filter(Boolean);
  if (days.length !== 5 || new Set(days).size !== 5 || days.some((day) => day.length > 80)) throw new ApiError(503, 'rsvp_configuration_unavailable');
  return days;
};

const responseChoices = (body, days) => {
  const availableDays = Array.isArray(body.availableDays) ? [...new Set(body.availableDays.map(String))] : [];
  const noAvailability = body.noAvailability === true || body.noAvailability === 'true' || body.noAvailability === 'on';
  const mealTypes = Array.isArray(body.mealTypes) ? [...new Set(body.mealTypes.map(String))] : [];
  const mealPreference = String(body.mealPreference || (mealTypes.length === 1 ? mealTypes[0] : mealTypes.length ? 'any' : ''));
  const guestCount = Number(body.guestCount);
  const preferenceType = String(body.preferenceType || body.attendanceType || 'families');
  const dietaryRestrictions = String(body.dietaryRestrictions || '').trim();
  const restaurantChoices = [...new Set((Array.isArray(body.restaurantChoices) ? body.restaurantChoices : [body.restaurantChoice])
    .filter((choice) => choice !== undefined && choice !== null)
    .map((choice) => String(choice).trim().replace(/\s+/g, ' '))
    .filter(Boolean))];
  const proposedRestaurantChoices = [...new Set((Array.isArray(body.proposedRestaurantChoices) ? body.proposedRestaurantChoices : [body.proposedRestaurantChoice])
    .filter((choice) => choice !== undefined && choice !== null)
    .map((choice) => String(choice).trim().replace(/\s+/g, ' '))
    .filter(Boolean))];
  if (availableDays.some((day) => !days.includes(day)) || (!availableDays.length && !noAvailability)) throw new ApiError(400, 'invalid_availability');
  if (!['lunch', 'dinner', 'drinks', 'any'].includes(mealPreference)) throw new ApiError(400, 'invalid_meal_preference');
  if (!Number.isInteger(guestCount) || guestCount < 1 || guestCount > 12) throw new ApiError(400, 'invalid_guest_count');
  if (!['adults', 'plusOnes', 'families'].includes(preferenceType)) throw new ApiError(400, 'invalid_preference_type');
  if (dietaryRestrictions.length > 500 || restaurantChoices.length > 20 || proposedRestaurantChoices.length > 5 || [...restaurantChoices, ...proposedRestaurantChoices].some((choice) => choice.length < 2 || choice.length > 120)) throw new ApiError(400, 'invalid_preferences');
  return { availableDays, noAvailability, mealTypes: mealPreference === 'any' ? ['any'] : [mealPreference], mealPreference, guestCount, preferenceType, dietaryRestrictions, restaurantChoices, proposedRestaurantChoices };
};

const storedRestaurantChoices = (response) => {
  if (Array.isArray(response?.restaurantChoices)) return response.restaurantChoices;
  return response?.restaurantChoice ? [response.restaurantChoice] : [];
};

const storedProposedRestaurantChoices = (response) => Array.isArray(response?.proposedRestaurantChoices) ? response.proposedRestaurantChoices : [];

const validateRestaurantChoices = (choices, configuredChoices) => {
  if (configuredChoices.length && choices.some((choice) => !configuredChoices.includes(choice))) throw new ApiError(400, 'invalid_restaurant_choice');
};

const conditionalFailure = (error) =>
  error?.name === 'ConditionalCheckFailedException' || error?.name === 'TransactionCanceledException';

const normalizeTriviaAnswer = (value) => String(value || '').normalize('NFKD')
  .replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('pt-PT').trim();

export const triviaAnswerMatches = (answer, acceptedAnswers) => {
  const normalized = normalizeTriviaAnswer(answer);
  return acceptedAnswers.some((accepted) => normalized.includes(normalizeTriviaAnswer(accepted)));
};

const validateTriviaQuestions = (raw) => {
  if (!Array.isArray(raw) || raw.length > 20) throw new ApiError(400, 'invalid_trivia_questions');
  return raw.map((item, index) => {
    const question = String(item?.question || '').trim().replace(/\s+/g, ' ');
    const answers = Array.isArray(item?.answers) ? [...new Set(item.answers.map((answer) => String(answer).trim()).filter(Boolean))] : [];
    if (!question || question.length > 240 || answers.length < 1 || answers.length > 8 || answers.some((answer) => answer.length > 120)) {
      throw new ApiError(400, 'invalid_trivia_questions');
    }
    return { id: `q${index + 1}`, question, answers };
  });
};

export const createHandler = ({
  s3 = new S3Client({}),
  ssm = new SSMClient({}),
  sqs = new SQSClient({}),
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
  const notifySlack = async (payload) => {
    try {
      const webhook = await getParameter(env.SLACK_WEBHOOK_PARAMETER);
      if (!webhook) return;
      await fetch(webhook, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text: `RSVP ${payload.event}`, attachments: [{ color: '#2eb886', text: Object.entries(payload).filter(([key]) => key !== 'event').map(([key, value]) => `*${key}:* ${typeof value === 'object' ? JSON.stringify(value) : value}`).join('\n') }] }) });
    } catch (error) { console.error(JSON.stringify({ event: 'slack_notification_failed', error: error?.message || 'unknown_error' })); }
  };

  const getOriginSecret = () => getParameter(env.ORIGIN_SECRET_PARAMETER);
  const getSessionSecret = () => getParameter(env.SESSION_SECRET_PARAMETER);
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

  const getPasswordCredential = async (guestId) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `GUEST#${guestId}`, sk: 'PASSWORD' },
      ConsistentRead: true,
    }));
    return result.Item || null;
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
  }, guest.isAdmin === true ? ADMIN_SESSION_TTL_SECONDS : SESSION_TTL_SECONDS);

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
    const settings = await eventSettings();
    if (!settings.useTrivia || !(settings.triviaQuestions || []).length) return;
    if (!(await readTriviaGate(event))) throw new ApiError(403, 'trivia_required');
  };

  const triviaQuestion = async (event) => {
    const captchaCookies = await requireCaptchaGate(event);
    const settings = await eventSettings();
    const questions = settings.triviaQuestions || [];
    if (!settings.useTrivia || !questions.length) return jsonResponse(200, { enabled: false }, { cookies: captchaCookies });
    const question = questions[Math.floor(Math.random() * questions.length)];
    const cookie = await makeSignedCookie('rsvp_trivia_challenge', {
      type: 'trivia-challenge', questionId: question.id,
    }, CAPTCHA_TTL_SECONDS);
    const challenge = cookie.slice(cookie.indexOf('=') + 1, cookie.indexOf(';'));
    return jsonResponse(200, { enabled: true, question: question.question, challenge }, { cookies: captchaCookies });
  };

  const triviaAnswer = async (event) => {
    await requireCaptchaGate(event);
    const body = parseJsonBody(event);
    const challenge = verifyToken(body.challenge, await getSessionSecret(), now());
    const question = ((await eventSettings()).triviaQuestions || []).find((candidate) => candidate.id === challenge?.questionId);
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

  const accessLinkGuest = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_access_link');
    if (token?.type !== 'guest-access-link' || !GUEST_ID.test(String(token.guestId || ''))) return null;
    return getGuest(token.guestId).catch(() => null);
  };

  const requireGuestEntry = async (event, guestId) => {
    const linkedGuest = await accessLinkGuest(event);
    if (linkedGuest?.guestId === guestId) return;
    const sessionGuest = await readSessionGuest(event);
    if (sessionGuest?.isAdmin === true) return;
    await requireTriviaGate(event);
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

  const authorizedRegistrationGuest = async (event) => {
    const sessionGuest = await readSessionGuest(event);
    if (sessionGuest) return sessionGuest;
    const token = await readSignedCookie(event, 'rsvp_registration');
    if (token?.type === 'registration') {
      const challenge = await getRegistrationChallenge(token.nonce);
      if (challenge?.status === 'created' && challenge.guestId && challenge.expiresAt >= now()) return getGuest(challenge.guestId);
    }
    throw new ApiError(401, 'whatsapp_approval_required');
  };

  const getGroup = async (groupId) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `GROUP#${groupId}`, sk: 'PROFILE' },
      ConsistentRead: true,
    }));
    if (!result.Item?.enabled || result.Item.entityType !== 'group') throw new ApiError(404, 'group_not_found');
    return result.Item;
  };

  const listGroups = async () => {
    const result = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :group AND enabled = :enabled',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':group': 'group', ':enabled': true },
      ExpressionAttributeNames: { '#name': 'name' },
      ProjectionExpression: 'groupId, #name',
    }));
    const groups = (result.Items || []).map(({ groupId, name }) => ({ id: groupId, name }))
      .sort((left, right) => left.name.localeCompare(right.name));
    return jsonResponse(200, { groups });
  };

  const listGuests = async (groupId = '', query = '') => {
    let search;
    if (String(query).trim()) {
      try { search = normalizeContactName(query); } catch { throw new ApiError(400, 'invalid_guest_search'); }
    } else {
      search = { lookup: '' };
    }
    let profiles;
    if (groupId) {
      await getGroup(validGroupId(groupId));
      const result = await ddb.send(new QueryCommand({
        TableName: env.RSVP_TABLE,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
        ExpressionAttributeValues: { ':pk': `GROUP#${groupId}`, ':prefix': 'MEMBER#' },
        ConsistentRead: false,
      }));
      profiles = await Promise.all((result.Items || []).map(({ guestId }) => getGuest(guestId).catch(() => null)));
    } else {
      const result = await ddb.send(new ScanCommand({
        TableName: env.RSVP_TABLE,
        FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled',
        ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true },
        ProjectionExpression: 'guestId, nickname, identityStatus',
      }));
      profiles = result.Items || [];
    }
    const visibleProfiles = profiles.filter((profile) => {
      if (!profile) return false;
      try {
        return normalizeContactName(profile.nickname.replace(/ — Por confirmar$/, '')).lookup.includes(search.lookup);
      } catch { return false; }
    });
    const profileById = new Map(visibleProfiles.map((profile) => [profile.guestId, profile]));
    const guests = [];
    const rendered = new Set();
    for (const profile of visibleProfiles) {
      if (rendered.has(profile.guestId)) continue;
      const marker = await guestLink(profile.guestId);
      const other = marker?.status === 'active'
        ? (profileById.get(marker.otherGuestId) || await getGuest(marker.otherGuestId).catch(() => null))
        : null;
      if (other && !rendered.has(other.guestId)) {
        const members = [profile, other].sort((left, right) => left.nickname.localeCompare(right.nickname)).map(({ guestId, nickname, identityStatus }) => ({
          id: guestId,
          nickname: nickname.replace(/ — Por confirmar$/, ''),
          registrationRequired: identityStatus === 'unconfirmed' || nickname.endsWith(' — Por confirmar'),
          ...(identityStatus === 'to_add' ? { configurationRequired: true } : {}),
        }));
        guests.push({ id: members[0].id, nickname: members.map((member) => member.nickname).join(' & '), linked: true, members });
        rendered.add(profile.guestId); rendered.add(other.guestId);
        continue;
      }
      rendered.add(profile.guestId);
      guests.push({
        id: profile.guestId,
        nickname: profile.nickname.replace(/ — Por confirmar$/, ''),
        registrationRequired: profile.identityStatus === 'unconfirmed' || profile.nickname.endsWith(' — Por confirmar'),
        ...(profile.identityStatus === 'to_add' ? { configurationRequired: true } : {}),
      });
    }
    guests.sort((left, right) => left.nickname.localeCompare(right.nickname));
    return jsonResponse(200, { guests: query.trim() ? guests.slice(0, 10) : guests });
  };

  const rsvpForGuest = async (guestId) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `RSVP#${guestId}`, sk: 'RESPONSE' },
      ConsistentRead: true,
    }));
    return result.Item || null;
  };

  const guestLink = async (guestId) => {
    const result = await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${guestId}`, sk: 'LINK' }, ConsistentRead: true }));
    return result.Item || null;
  };

  const linkRequest = async (linkId) => {
    const result = await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: `LINK#${linkId}`, sk: 'REQUEST' }, ConsistentRead: true }));
    return result.Item || null;
  };

  const linkWhatsappUrl = async (request) => {
    const appNumber = normalizeE164(await getWhatsappNumber());
    const signedMessage = `LINK link=${request.linkId}&contact=${encodeURIComponent(request.targetNickname)}&nonce=${request.nonce}`;
    const signature = createHmac('sha256', await getValidationSecret()).update(signedMessage, 'utf8').digest('base64url');
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', `${signedMessage}&sig=${signature}`);
    return whatsappUrl.toString();
  };

  const linkState = async (guestId) => {
    const marker = await guestLink(guestId);
    if (!marker) return { status: 'none' };
    const request = await linkRequest(marker.linkId);
    if (!request) return { status: 'none' };
    const other = await getGuest(marker.otherGuestId).catch(() => null);
    const state = { status: request.status, linkId: request.linkId, requesterId: request.requesterId, targetId: request.targetId, other: other ? { id: other.guestId, nickname: other.nickname.replace(/ — Por confirmar$/, '') } : null };
    if (request.status === 'pending') state.whatsappUrl = await linkWhatsappUrl(request);
    return state;
  };

  const eventSettings = async () => {
    const result = await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: 'EVENT#DEFAULT', sk: 'SETTINGS' }, ConsistentRead: true }));
    return result.Item || {};
  };

  const rsvpConfig = async () => {
    const settings = await eventSettings();
    return { days: availabilityDays(env), restaurantChoices: settings.restaurantChoices || [] };
  };

  const requireAdmin = async (event) => {
    const guest = await readSessionGuest(event);
    if (!guest) throw new ApiError(401, 'authentication_required');
    if (!guest.isAdmin) throw new ApiError(403, 'admin_required');
    return guest;
  };

  const getRsvp = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    const response = await rsvpForGuest(guest.guestId);
    return jsonResponse(200, { ...(await rsvpConfig()), response: response ? {
      availableDays: response.availableDays, noAvailability: response.noAvailability === true, mealTypes: response.mealTypes, mealPreference: response.mealPreference, guestCount: response.guestCount,
      preferenceType: response.preferenceType || (response.attendanceType === 'adults' ? 'adults' : 'families'), dietaryRestrictions: response.dietaryRestrictions, restaurantChoices: storedRestaurantChoices(response),
      proposedRestaurantChoices: storedProposedRestaurantChoices(response),
    } : null });
  };

  const saveRsvp = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    const config = await rsvpConfig();
    const choices = responseChoices(parseJsonBody(event), config.days);
    validateRestaurantChoices(choices.restaurantChoices, config.restaurantChoices);
    const marker = await guestLink(guest.guestId);
    const items = [{ Put: { TableName: env.RSVP_TABLE, Item: { pk: `RSVP#${guest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: guest.guestId, ...choices, updatedAt: now() } } }];
    if (marker?.status === 'active') items.push({ Put: { TableName: env.RSVP_TABLE, Item: { pk: `RSVP#${marker.otherGuestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: marker.otherGuestId, ...choices, updatedAt: now() } } });
    await ddb.send(items.length === 1 ? new PutCommand(items[0].Put) : new TransactWriteCommand({ TransactItems: items }));
    if (env.SUMMARY_QUEUE_URL) {
      await sqs.send(new SendMessageCommand({
        QueueUrl: env.SUMMARY_QUEUE_URL,
        MessageBody: JSON.stringify({ activity: { type: 'rsvp_saved', nickname: String(guest.nickname || '').replace(/ — Por confirmar$/, '') } }),
      }));
    }
    return jsonResponse(200, { saved: true, ...config, response: choices });
  };

  const linkCandidates = async (event) => {
    const sessionGuest = await readSessionGuest(event);
    if (!sessionGuest) throw new ApiError(401, 'authentication_required');
    const result = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true },
      ProjectionExpression: 'guestId, nickname, identityStatus',
    }));
    const candidates = (result.Items || [])
      .filter((item) => item.guestId !== sessionGuest.guestId && item.identityStatus !== 'to_add')
      .map((item) => ({ id: item.guestId, nickname: String(item.nickname || '').replace(/ — Por confirmar$/, '') }))
      .sort((left, right) => left.nickname.localeCompare(right.nickname));
    return jsonResponse(200, { candidates });
  };

  const createLink = async (event) => {
    const requester = await readSessionGuest(event);
    if (!requester) throw new ApiError(401, 'authentication_required');
    const body = parseJsonBody(event);
    const target = await getGuest(validGuestId(body.targetGuestId));
    if (target.guestId === requester.guestId || target.identityStatus === 'to_add') throw new ApiError(400, 'invalid_link_target');
    if (await guestLink(requester.guestId) || await guestLink(target.guestId)) throw new ApiError(409, 'member_already_linked');
    const linkId = randomUUID();
    const nonce = toBase64Url(randomBytes(32));
    const response = await rsvpForGuest(requester.guestId);
    const createdAt = now();
    const request = { pk: `LINK#${linkId}`, sk: 'REQUEST', entityType: 'memberLink', linkId, requesterId: requester.guestId, targetId: target.guestId, requesterNickname: requester.nickname, targetNickname: target.nickname.replace(/ — Por confirmar$/, ''), nonce, status: 'pending', createdAt, ...(response ? { response: { ...response, pk: undefined, sk: undefined } } : {}) };
    try {
      await ddb.send(new TransactWriteCommand({ TransactItems: [
        { Put: { TableName: env.RSVP_TABLE, Item: request, ConditionExpression: 'attribute_not_exists(pk)' } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${requester.guestId}`, sk: 'LINK', entityType: 'memberLink', linkId, otherGuestId: target.guestId, status: 'pending' }, ConditionExpression: 'attribute_not_exists(pk)' } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${target.guestId}`, sk: 'LINK', entityType: 'memberLink', linkId, otherGuestId: requester.guestId, status: 'pending' }, ConditionExpression: 'attribute_not_exists(pk)' } },
      ] }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'member_already_linked');
      throw error;
    }
    return jsonResponse(200, { ...(await linkState(requester.guestId)) });
  };

  const removeLink = async (event) => {
    const body = parseJsonBody(event);
    const sessionGuest = await readSessionGuest(event);
    let request;
    if (sessionGuest && !body.linkId) {
      const marker = await guestLink(sessionGuest.guestId);
      request = marker ? await linkRequest(marker.linkId) : null;
    } else {
      await requireAdmin(event);
      if (typeof body.linkId !== 'string' || !body.linkId) throw new ApiError(400, 'invalid_link');
      request = await linkRequest(body.linkId);
    }
    if (!request || !['pending', 'active'].includes(request.status)) throw new ApiError(404, 'link_not_found');
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Delete: { TableName: env.RSVP_TABLE, Key: { pk: `LINK#${request.linkId}`, sk: 'REQUEST' }, ConditionExpression: 'attribute_exists(pk)' } },
      { Delete: { TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${request.requesterId}`, sk: 'LINK' } } },
      { Delete: { TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${request.targetId}`, sk: 'LINK' } } },
    ] }));
    return jsonResponse(200, { status: 'none' });
  };

  const startWhatsappRsvp = async (event) => {
    const body = parseJsonBody(event);
    if (body.retry !== true) await requireTriviaGate(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const config = await rsvpConfig();
    const retrieval = body.mode === 'retrieve';
    const existingResponse = retrieval ? await rsvpForGuest(guest.guestId) : null;
    if (retrieval && !existingResponse) throw new ApiError(409, 'registration_required');
    const recovery = body.mode === 'recover';
    const response = retrieval || recovery ? null : responseChoices(body, config.days);
    if (response) validateRestaurantChoices(response.restaurantChoices, config.restaurantChoices);
    const settings = await eventSettings();
    const whatsappVerificationRequired = settings.useWhatsappVerification !== false && env.WHATSAPP_VERIFICATION_REQUIRED !== 'false';
    if (response && !whatsappVerificationRequired) {
      const timestamp = now();
      await ddb.send(new TransactWriteCommand({ TransactItems: [
        { Update: { TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${guest.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET identityStatus = :confirmed, updatedAt = :now', ConditionExpression: 'enabled = :enabled', ExpressionAttributeValues: { ':confirmed': 'confirmed', ':enabled': true, ':now': timestamp } } },
        { Put: { TableName: env.RSVP_TABLE, Item: { pk: `RSVP#${guest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: guest.guestId, ...response, updatedAt: timestamp } } },
      ] }));
      const notification = { event: 'rsvp_submission_persisted', guestId: guest.guestId, nickname: String(guest.nickname || '').replace(/ — Por confirmar$/, ''), response, wouldStoreResponse: true, storedResponse: true, persistence: 'rsvp_response' };
      console.info(JSON.stringify(notification));
      void notifySlack(notification);
      if (env.SUMMARY_QUEUE_URL) await sqs.send(new SendMessageCommand({ QueueUrl: env.SUMMARY_QUEUE_URL, MessageBody: JSON.stringify({ activity: { type: 'rsvp_saved', nickname: String(guest.nickname || '').replace(/ — Por confirmar$/, '') } }) }));
      return jsonResponse(200, { mode: 'bypass' }, { cookies: [await issueSessionCookie({ ...guest, identityStatus: 'confirmed' })] });
    }
    const pendingKey = { pk: `GUEST#${guest.guestId}`, sk: 'PENDING_REGISTRATION' };
    const pending = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: pendingKey, ConsistentRead: true }))).Item;
    if (pending?.expiresAt >= now()) {
      if (!pending.nonce) throw new ApiError(409, 'registration_already_pending');
      await ddb.send(new UpdateCommand({
        TableName: env.RSVP_TABLE,
        Key: { pk: `REGISTRATION#${tokenHash(pending.nonce)}`, sk: 'CHALLENGE' },
        UpdateExpression: 'REMOVE lastError, lastErrorAt',
        ConditionExpression: '#status = :pending',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':pending': 'pending' },
      }));
      let appNumber;
      try { appNumber = normalizeE164(await getWhatsappNumber()); } catch { throw new ApiError(503, 'whatsapp_unavailable'); }
      const signedMessage = `contact=${encodeURIComponent(String(guest.nickname || '').replace(/ — Por confirmar$/, ''))}&nonce=${pending.nonce}`;
      const signature = createHmac('sha256', await getValidationSecret()).update(signedMessage, 'utf8').digest('base64url');
      const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
      whatsappUrl.searchParams.set('text', `VALIDATION ${signedMessage}&sig=${signature}`);
      return jsonResponse(200, { mode: pending.purpose || 'register', whatsappUrl: whatsappUrl.toString(), expiresAt: pending.validationExpiresAt }, { cookies: [await makeSignedCookie('rsvp_registration', { type: 'registration', nonce: pending.nonce }, PENDING_SUBMISSION_TTL_SECONDS)] });
    }
    const sender = normalizeContactName(guest.sender || guest.nickname);
    const nonce = toBase64Url(randomBytes(32));
    const validationExpiresAt = now() + WHATSAPP_TTL_SECONDS;
    const expiresAt = now() + PENDING_SUBMISSION_TTL_SECONDS;
    const purpose = retrieval ? 'retrieve' : recovery ? 'recover' : 'register';
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: env.RSVP_TABLE, Item: { ...pendingKey, entityType: 'pendingRegistration', guestId: guest.guestId, nonce, sender: sender.display, senderLookup: sender.lookup, publicNameLookup: normalizeContactName(String(guest.nickname || '').replace(/ — Por confirmar$/, '')).lookup, ...(response ? { response } : {}), purpose, validationExpiresAt, expiresAt, createdAt: now() }, ConditionExpression: 'attribute_not_exists(pk) OR expiresAt < :now', ExpressionAttributeValues: { ':now': now() } } },
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE', entityType: 'registrationChallenge', guestId: guest.guestId, sender: sender.display, senderLookup: sender.lookup, publicNameLookup: normalizeContactName(String(guest.nickname || '').replace(/ — Por confirmar$/, '')).lookup, ...(response ? { response } : {}), purpose, nonce, pendingRegistration: true, status: 'pending', validationExpiresAt, expiresAt, createdAt: now() }, ConditionExpression: 'attribute_not_exists(pk)' } },
    ] }));
    if (response) { const notification = { event: 'rsvp_submission_staged', guestId: guest.guestId, nickname: String(guest.nickname || '').replace(/ — Por confirmar$/, ''), response, wouldStoreResponse: true, storedResponse: false, persistence: 'registration_challenge', expiresAt }; console.info(JSON.stringify(notification)); void notifySlack(notification); }
    let appNumber;
    try { appNumber = normalizeE164(await getWhatsappNumber()); } catch { throw new ApiError(503, 'whatsapp_unavailable'); }
    const signedMessage = `contact=${encodeURIComponent(String(guest.nickname || '').replace(/ — Por confirmar$/, ''))}&nonce=${nonce}`;
    const signature = createHmac('sha256', await getValidationSecret()).update(signedMessage, 'utf8').digest('base64url');
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', `VALIDATION ${signedMessage}&sig=${signature}`);
    return jsonResponse(200, { mode: purpose, whatsappUrl: whatsappUrl.toString(), expiresAt: validationExpiresAt }, { cookies: [await makeSignedCookie('rsvp_registration', { type: 'registration', nonce }, PENDING_SUBMISSION_TTL_SECONDS)] });
  };

  const rsvpSummary = async () => {
    const { days, restaurantChoices: configuredRestaurants } = await rsvpConfig();
    const result = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'entityType = :response',
      ExpressionAttributeValues: { ':response': 'rsvpResponse' },
      ProjectionExpression: 'guestId, availableDays, mealTypes, mealPreference, guestCount, restaurantChoices, restaurantChoice',
    }));
    const responses = result.Items || [];
    const profilesResult = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true },
      ProjectionExpression: 'guestId, nickname',
    }));
    const nicknames = new Map((profilesResult.Items || []).map((profile) => [profile.guestId, String(profile.nickname || '').replace(/ — Por confirmar$/, '')]));
    const responseLinks = new Map(await Promise.all(responses.map(async (response) => [response.guestId, await guestLink(response.guestId)])));
    const displayNames = new Map(nicknames);
    for (const response of responses) {
      const marker = responseLinks.get(response.guestId);
      if (marker?.status === 'active' && nicknames.has(marker.otherGuestId)) {
        displayNames.set(response.guestId, [nicknames.get(response.guestId), nicknames.get(marker.otherGuestId)].sort().join(' & '));
      }
    }
    const byDay = Object.fromEntries(days.map((day) => [day, 0]));
    const byMeal = { lunch: 0, dinner: 0, drinks: 0, any: 0 };
    const dayVoters = Object.fromEntries(days.map((day) => [day, []]));
    const mealVoters = Object.fromEntries(Object.keys(byMeal).map((meal) => [meal, []]));
    const restaurantNames = [...configuredRestaurants];
    for (const response of responses) for (const restaurant of storedProposedRestaurantChoices(response)) if (!restaurantNames.includes(restaurant)) restaurantNames.push(restaurant);
    const restaurants = Object.fromEntries(restaurantNames.map((restaurant) => [restaurant, 0]));
    const restaurantVoters = Object.fromEntries(restaurantNames.map((restaurant) => [restaurant, []]));
    let guests = 0;
    for (const response of responses) {
      const marker = responseLinks.get(response.guestId);
      if (marker?.status === 'active' && response.guestId > marker.otherGuestId) continue;
      const guestCount = Number(response.guestCount || 0);
      guests += guestCount;
      const nickname = displayNames.get(response.guestId);
      for (const day of response.availableDays || []) if (day in byDay) {
        byDay[day] += guestCount;
        if (nickname && !dayVoters[day].some((voter) => voter.nickname === nickname)) dayVoters[day].push({ nickname, guestCount });
      }
      for (const meal of response.mealPreference ? [response.mealPreference] : response.mealTypes || []) if (meal in byMeal) {
        byMeal[meal] += guestCount;
        if (nickname && !mealVoters[meal].some((voter) => voter.nickname === nickname)) mealVoters[meal].push({ nickname, guestCount });
      }
      for (const restaurant of [...storedRestaurantChoices(response), ...storedProposedRestaurantChoices(response)]) {
        restaurants[restaurant] = (restaurants[restaurant] || 0) + Number(response.guestCount || 0);
        const nickname = displayNames.get(response.guestId);
        if (nickname && !restaurantVoters[restaurant]?.some((voter) => voter.nickname === nickname)) {
          (restaurantVoters[restaurant] ||= []).push({ nickname, guestCount: Number(response.guestCount || 0) });
        }
      }
    }
    const aiSummary = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: 'EVENT#DEFAULT', sk: 'AI_SUMMARY' }, ConsistentRead: true }))).Item;
    return jsonResponse(200, { responses: responses.length, guests, byDay, byMeal, dayVoters, mealVoters, restaurantChoices: restaurantNames, restaurants, restaurantVoters, ...(aiSummary?.narrative ? { narrative: aiSummary.narrative, narrativeGeneratedAt: aiSummary.generatedAt } : {}) });
  };

  const adminSettings = async (event) => {
    await requireAdmin(event);
    const settings = await eventSettings();
    return jsonResponse(200, { ...(await rsvpConfig()), triviaQuestions: settings.triviaQuestions || [], useTrivia: Boolean(settings.useTrivia), useWhatsappVerification: settings.useWhatsappVerification !== false });
  };

  const adminSummary = async (event) => {
    await requireAdmin(event);
    const summary = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: 'EVENT#DEFAULT', sk: 'AI_SUMMARY' }, ConsistentRead: true }))).Item;
    return jsonResponse(200, { narrative: summary?.narrative || '', generatedAt: summary?.generatedAt || null, lastActivity: summary?.lastActivity || null });
  };

  const saveAdminSummary = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    if (typeof body.narrative !== 'string' || body.narrative.length > 600 || /<[^>]+>/.test(body.narrative)) throw new ApiError(400, 'invalid_summary_narrative');
    const narrative = body.narrative.replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
    const key = { pk: 'EVENT#DEFAULT', sk: 'AI_SUMMARY' };
    if (!narrative) {
      await ddb.send(new DeleteCommand({ TableName: env.RSVP_TABLE, Key: key }));
      return jsonResponse(200, { saved: true, narrative: '' });
    }
    const existing = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: key, ConsistentRead: true }))).Item || {};
    await ddb.send(new PutCommand({ TableName: env.RSVP_TABLE, Item: { ...existing, ...key, entityType: 'aiSummary', narrative, editedAt: now() } }));
    return jsonResponse(200, { saved: true, narrative });
  };

  const saveAdminSettings = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const restaurantChoices = Array.isArray(body.restaurantChoices) ? [...new Set(body.restaurantChoices.map((choice) => String(choice).trim().replace(/\s+/g, ' ')).filter(Boolean))] : null;
    if (!restaurantChoices || restaurantChoices.length > 20 || restaurantChoices.some((choice) => choice.length > 120)) throw new ApiError(400, 'invalid_restaurant_choices');
    const triviaQuestions = validateTriviaQuestions(body.triviaQuestions);
    const existing = await eventSettings();
    const useTrivia = !(existing.triviaQuestions || []).length && triviaQuestions.length
      ? true
      : Boolean(body.useTrivia) && triviaQuestions.length > 0;
    const useWhatsappVerification = body.useWhatsappVerification !== false;
    await ddb.send(new PutCommand({ TableName: env.RSVP_TABLE, Item: { pk: 'EVENT#DEFAULT', sk: 'SETTINGS', entityType: 'eventSettings', restaurantChoices, triviaQuestions, useTrivia, useWhatsappVerification, updatedAt: now() } }));
    return jsonResponse(200, { saved: true, ...(await rsvpConfig()), triviaQuestions, useTrivia, useWhatsappVerification });
  };

  const adminGroups = async (event) => {
    await requireAdmin(event);
    const groups = JSON.parse((await listGroups()).body).groups;
    const withCounts = await Promise.all(groups.map(async (group) => {
      const members = await ddb.send(new QueryCommand({ TableName: env.RSVP_TABLE, KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)', ExpressionAttributeValues: { ':pk': `GROUP#${group.id}`, ':prefix': 'MEMBER#' }, Select: 'COUNT' }));
      return { ...group, members: Number(members.Count || 0) };
    }));
    return jsonResponse(200, { groups: withCounts });
  };

  const adminGuests = async (event) => {
    await requireAdmin(event);
    const [result, pendingResult] = await Promise.all([ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true },
      ProjectionExpression: 'guestId, nickname, sender, identityStatus, lastRegistrationApprovedAt',
    })), ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :pending AND entityType = :pendingType',
      ExpressionAttributeValues: { ':pending': 'PENDING_REGISTRATION', ':pendingType': 'pendingRegistration' },
      ProjectionExpression: 'guestId, validationExpiresAt, expiresAt, entityType',
    }))]);
    const pendingByGuest = new Map((pendingResult.Items || [])
      .filter((item) => item.entityType === 'pendingRegistration' && item.expiresAt >= now())
      .map((item) => [item.guestId, item]));
    const guests = (result.Items || []).map((guest) => ({
      id: guest.guestId,
      nickname: String(guest.nickname || '').replace(/ — Por confirmar$/, ''),
      sender: String(guest.sender || ''),
      identityStatus: guest.identityStatus || 'unconfirmed',
      lastRegistrationApprovedAt: guest.lastRegistrationApprovedAt || null,
      pendingRegistration: pendingByGuest.has(guest.guestId),
      validationExpiresAt: pendingByGuest.get(guest.guestId)?.validationExpiresAt || null,
    })).sort((left, right) => left.nickname.localeCompare(right.nickname));
    return jsonResponse(200, { guests });
  };

  const createGuestAccessLink = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const token = toBase64Url(nodeRandomBytes(32));
    const hash = tokenHash(token);
    const expiresAt = now() + ACCESS_LINK_TTL_SECONDS;
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `ACCESS_LINK#${hash}`, sk: 'LINK', entityType: 'guestAccessLink', guestId: guest.guestId, tokenHash: hash, expiresAt, createdAt: now() }, ConditionExpression: 'attribute_not_exists(pk)' } },
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${guest.guestId}`, sk: 'ACCESS_LINK', entityType: 'guestAccessLinkPointer', tokenHash: hash, expiresAt, createdAt: now() } } },
    ] }));
    const siteOrigin = new URL(env.WEBAUTHN_EXPECTED_ORIGIN || 'https://calcada2026.pt').origin;
    return jsonResponse(200, { link: `${siteOrigin}/?access=${encodeURIComponent(token)}`, expiresAt });
  };

  const reissueGuestRegistration = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const pendingKey = { pk: `GUEST#${guest.guestId}`, sk: 'PENDING_REGISTRATION' };
    const pending = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: pendingKey, ConsistentRead: true }))).Item;
    if (!pending || pending.expiresAt < now()) throw new ApiError(404, 'pending_submission_not_found');
    const sender = normalizeContactName(pending.sender || guest.sender || guest.nickname);
    const nonce = toBase64Url(randomBytes(32));
    const validationExpiresAt = now() + WHATSAPP_TTL_SECONDS;
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Update: { TableName: env.RSVP_TABLE, Key: pendingKey, UpdateExpression: 'SET nonce = :nonce, sender = :sender, senderLookup = :senderLookup, validationExpiresAt = :validationExpiresAt, lastReissuedAt = :now', ConditionExpression: 'expiresAt >= :now', ExpressionAttributeValues: { ':nonce': nonce, ':sender': sender.display, ':senderLookup': sender.lookup, ':validationExpiresAt': validationExpiresAt, ':now': now() } } },
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE', entityType: 'registrationChallenge', guestId: guest.guestId, sender: sender.display, senderLookup: sender.lookup, publicNameLookup: normalizeContactName(String(guest.nickname || '').replace(/ — Por confirmar$/, '')).lookup, ...(pending.response ? { response: pending.response } : {}), purpose: pending.purpose || 'register', nonce, pendingRegistration: true, status: 'pending', validationExpiresAt, expiresAt: pending.expiresAt, createdAt: now(), reissuedBy: 'admin' }, ConditionExpression: 'attribute_not_exists(pk)' } },
    ] }));
    let appNumber;
    try { appNumber = normalizeE164(await getWhatsappNumber()); } catch { throw new ApiError(503, 'whatsapp_unavailable'); }
    const signedMessage = `nome=${encodeURIComponent(String(guest.nickname || '').replace(/ — Por confirmar$/, ''))}&nonce=${nonce}`;
    const signature = createHmac('sha256', await getValidationSecret()).update(signedMessage, 'utf8').digest('base64url');
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', `VALIDATION ${signedMessage}&sig=${signature}`);
    return jsonResponse(200, { whatsappUrl: whatsappUrl.toString(), expiresAt: validationExpiresAt });
  };

  const recoverGuestRegistration = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const pendingKey = { pk: `GUEST#${guest.guestId}`, sk: 'PENDING_REGISTRATION' };
    const pending = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: pendingKey, ConsistentRead: true }))).Item;
    if (!pending || pending.expiresAt < now()) throw new ApiError(404, 'pending_submission_not_found');
    const challengeKey = { pk: `REGISTRATION#${tokenHash(pending.nonce)}`, sk: 'CHALLENGE' };
    const token = toBase64Url(nodeRandomBytes(32));
    const hash = tokenHash(token);
    const expiresAt = now() + ACCESS_LINK_TTL_SECONDS;
    const actions = [
      { Update: { TableName: env.RSVP_TABLE, Key: challengeKey, UpdateExpression: 'SET #status = :created, approvedAt = :now, recoveredByAdmin = :true', ConditionExpression: '#status = :pending', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':created': 'created', ':pending': 'pending', ':now': now(), ':true': true } } },
      { Delete: { TableName: env.RSVP_TABLE, Key: pendingKey, ConditionExpression: 'nonce = :nonce', ExpressionAttributeValues: { ':nonce': pending.nonce } } },
      { Update: { TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${guest.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET identityStatus = :confirmed, lastRegistrationApprovedAt = :now, updatedAt = :now', ConditionExpression: 'enabled = :enabled', ExpressionAttributeValues: { ':confirmed': 'confirmed', ':enabled': true, ':now': now() } } },
    ];
    if (pending.response) actions.push({ Put: { TableName: env.RSVP_TABLE, Item: { pk: `RSVP#${guest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: guest.guestId, ...pending.response, updatedAt: now() } } });
    actions.push(
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `ACCESS_LINK#${hash}`, sk: 'LINK', entityType: 'guestAccessLink', guestId: guest.guestId, tokenHash: hash, expiresAt, createdAt: now(), recoveredByAdmin: true }, ConditionExpression: 'attribute_not_exists(pk)' } },
      { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${guest.guestId}`, sk: 'ACCESS_LINK', entityType: 'guestAccessLinkPointer', tokenHash: hash, expiresAt, createdAt: now() } } },
    );
    try { await ddb.send(new TransactWriteCommand({ TransactItems: actions })); } catch (error) { if (conditionalFailure(error)) throw new ApiError(409, 'registration_recovery_unavailable'); throw error; }
    const siteOrigin = new URL(env.WEBAUTHN_EXPECTED_ORIGIN || 'https://calcada2026.pt').origin;
    return jsonResponse(200, { link: `${siteOrigin}/?access=${encodeURIComponent(token)}`, expiresAt, recovered: true });
  };

  const resetGuestVote = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const marker = await guestLink(guest.guestId);
    const guestIds = marker?.status === 'active'
      ? [guest.guestId, marker.otherGuestId]
      : [guest.guestId];
    await ddb.send(guestIds.length === 1
      ? new DeleteCommand({ TableName: env.RSVP_TABLE, Key: { pk: `RSVP#${guest.guestId}`, sk: 'RESPONSE' } })
      : new TransactWriteCommand({ TransactItems: guestIds.map((guestId) => ({
        Delete: { TableName: env.RSVP_TABLE, Key: { pk: `RSVP#${guestId}`, sk: 'RESPONSE' } },
      })) }));
    return jsonResponse(200, { reset: true, guestIds });
  };

  const consumeGuestAccessLink = async (event) => {
    const body = parseJsonBody(event);
    const token = String(body.token || '');
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new ApiError(400, 'invalid_access_link');
    const hash = tokenHash(token);
    const link = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: `ACCESS_LINK#${hash}`, sk: 'LINK' }, ConsistentRead: true }))).Item;
    if (!link || link.expiresAt < now() || !safeEqual(link.tokenHash, hash)) throw new ApiError(410, 'access_link_expired');
    const pointer = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${link.guestId}`, sk: 'ACCESS_LINK' }, ConsistentRead: true }))).Item;
    if (!pointer || pointer.expiresAt < now() || !safeEqual(pointer.tokenHash, hash)) throw new ApiError(410, 'access_link_expired');
    const guest = await getGuest(link.guestId);
    const [credentials, passwordCredential] = await Promise.all([getCredentials(guest.guestId), getPasswordCredential(guest.guestId)]);
    if (credentials.length === 0 && !passwordCredential) {
      return jsonResponse(200, { mode: 'session', guest: { id: guest.guestId, nickname: guest.nickname } }, { cookies: [await issueSessionCookie(guest)] });
    }
    return jsonResponse(200, { mode: 'credentials', guest: { id: guest.guestId, nickname: guest.nickname } }, {
      cookies: [await makeSignedCookie('rsvp_access_link', { type: 'guest-access-link', guestId: guest.guestId }, ACCESS_LINK_AUTH_TTL_SECONDS)],
    });
  };

  const saveAdminGuest = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    let nickname;
    let sender;
    try {
      nickname = normalizeNickname(body.nickname);
      sender = normalizeContactName(body.sender);
    } catch { throw new ApiError(400, 'invalid_guest_names'); }
    const duplicate = (await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND enabled = :enabled AND nicknameLookup = :lookup',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':enabled': true, ':lookup': nickname.lookup },
      ProjectionExpression: 'guestId',
    }))).Items?.find((item) => item.guestId !== guest.guestId);
    if (duplicate) throw new ApiError(409, 'duplicate_guest_nickname');
    const identityStatus = guest.identityStatus === 'to_add' ? 'unconfirmed' : guest.identityStatus;
    await ddb.send(new PutCommand({ TableName: env.RSVP_TABLE, Item: { ...guest, nickname: nickname.display, nicknameLookup: nickname.lookup, sender: sender.display, senderLookup: sender.lookup, identityStatus, updatedAt: now() } }));
    const pendingKey = { pk: `GUEST#${guest.guestId}`, sk: 'PENDING_REGISTRATION' };
    const pending = (await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: pendingKey, ConsistentRead: true }))).Item;
    if (pending?.nonce && pending.expiresAt >= now()) {
      await ddb.send(new UpdateCommand({ TableName: env.RSVP_TABLE, Key: pendingKey, UpdateExpression: 'SET sender = :sender, senderLookup = :senderLookup', ExpressionAttributeValues: { ':sender': sender.display, ':senderLookup': sender.lookup } }));
      await ddb.send(new UpdateCommand({ TableName: env.RSVP_TABLE, Key: { pk: `REGISTRATION#${tokenHash(pending.nonce)}`, sk: 'CHALLENGE' }, UpdateExpression: 'SET sender = :sender, senderLookup = :senderLookup REMOVE lastError, lastErrorAt', ConditionExpression: '#status = :pending', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':sender': sender.display, ':senderLookup': sender.lookup, ':pending': 'pending' } }));
    }
    return jsonResponse(200, { saved: true, guest: { id: guest.guestId, nickname: nickname.display, sender: sender.display, identityStatus: guest.identityStatus || 'unconfirmed' } });
  };

  const addAdminGuest = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    let nickname;
    let sender;
    try {
      nickname = normalizeNickname(body.nickname);
      sender = normalizeContactName(body.sender);
    } catch { throw new ApiError(400, 'invalid_guest_names'); }
    const existing = (await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND nicknameLookup = :lookup',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':lookup': nickname.lookup },
    }))).Items?.[0];
    if (existing?.enabled) throw new ApiError(409, 'duplicate_guest_nickname');
    const timestamp = now();
    const guestId = existing?.guestId || randomUUID();
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        ...(existing || {}), pk: `GUEST#${guestId}`, sk: 'PROFILE', entityType: 'guest', guestId,
        nickname: nickname.display, nicknameLookup: nickname.lookup, sender: sender.display, senderLookup: sender.lookup,
        identityStatus: existing?.identityStatus === 'confirmed' ? 'confirmed' : 'unconfirmed', enabled: true,
        sessionVersion: Number(existing?.sessionVersion || 1) + (existing ? 1 : 0), createdAt: existing?.createdAt || timestamp, updatedAt: timestamp,
      },
    }));
    return jsonResponse(200, { saved: true, guest: { id: guestId, nickname: nickname.display, sender: sender.display } });
  };

  const removeAdminGuest = async (event) => {
    await requireAdmin(event);
    const body = parseJsonBody(event);
    const guest = await getGuest(validGuestId(body.guestId));
    const marker = await guestLink(guest.guestId);
    const guestIds = marker?.status === 'active' ? [guest.guestId, marker.otherGuestId] : [guest.guestId];
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Put: { TableName: env.RSVP_TABLE, Item: { ...guest, enabled: false, sessionVersion: Number(guest.sessionVersion || 1) + 1, updatedAt: now() } } },
      ...guestIds.map((guestId) => ({ Delete: { TableName: env.RSVP_TABLE, Key: { pk: `RSVP#${guestId}`, sk: 'RESPONSE' } } })),
    ] }));
    return jsonResponse(200, { removed: true, guestId: guest.guestId, resetGuestIds: guestIds });
  };

  const requestNewContact = async (event) => {
    await requireTriviaGate(event);
    const body = parseJsonBody(event);
    let name;
    try {
      name = normalizeContactName(body.name);
    } catch (error) {
      throw new ApiError(400, 'invalid_contact_details', error.message);
    }
    const guestId = randomUUID();
    const nowValue = now();
    try {
      await ddb.send(new TransactWriteCommand({
        TransactItems: [
          { Put: { TableName: env.RSVP_TABLE, Item: { pk: `CONTACT_REQUEST#${name.lookup}`, sk: 'UNIQUE', entityType: 'contactRequestUnique', guestId, createdAt: nowValue }, ConditionExpression: 'attribute_not_exists(pk)' } },
          { Put: { TableName: env.RSVP_TABLE, Item: { pk: `GUEST#${guestId}`, sk: 'PROFILE', entityType: 'guest', guestId, nickname: name.display, nicknameLookup: name.lookup, sender: name.display, identityStatus: 'to_add', enabled: true, sessionVersion: 1, createdAt: nowValue, updatedAt: nowValue }, ConditionExpression: 'attribute_not_exists(pk)' } },
        ],
      }));
    } catch (error) {
      if (conditionalFailure(error)) throw new ApiError(409, 'contact_already_requested');
      throw error;
    }
    const whatsappUrl = new URL(`https://wa.me/${CONTACT_REQUEST_NUMBER.slice(1)}`);
    whatsappUrl.searchParams.set('text', `Ola Antonio, eu sou o ${name.display} e este e o meu numero de whatsapp. podes-me adicionar a pagina.`);
    return jsonResponse(200, { status: 'to_add', whatsappUrl: whatsappUrl.toString() });
  };

  const validationMismatchReport = async (event) => {
    await requireTriviaGate(event);
    const token = await readSignedCookie(event, 'rsvp_registration');
    if (token?.type !== 'registration') throw new ApiError(409, 'validation_report_unavailable');
    const challenge = await getRegistrationChallenge(token.nonce);
    if (!challenge || challenge.status !== 'pending' || challenge.expiresAt < now()) throw new ApiError(410, 'validation_report_expired');
    const guest = await getGuest(challenge.guestId);
    const response = challenge.response || {};
    const lines = [
      'RSVP-IMPORT',
      `Dias: ${Array.isArray(response.availableDays) ? response.availableDays.join(', ') : ''}`,
      `Pessoas: ${response.guestCount || ''}`,
      `Preferência: ${response.preferenceType || ''}`,
      `Refeições: ${Array.isArray(response.mealTypes) ? response.mealTypes.join(', ') : ''}`,
      `Restaurantes: ${Array.isArray(response.restaurantChoices) ? response.restaurantChoices.join(', ') : ''}`,
      `Outros restaurantes: ${Array.isArray(response.proposedRestaurantChoices) ? response.proposedRestaurantChoices.join(' | ') : ''}`,
      `Restrições alimentares: ${response.dietaryRestrictions || ''}`,
    ];
    const message = `Ola Antonio, eu sou ${String(guest.nickname || '').replace(/ — Por confirmar$/, '')} e o contacto esta configurado como ${challenge.sender || ''}. O sistema nao reconhece.\n\n${lines.join('\n')}`;
    const whatsappUrl = new URL(`https://wa.me/${CONTACT_REQUEST_NUMBER.slice(1)}`);
    whatsappUrl.searchParams.set('text', message);
    return jsonResponse(200, { whatsappUrl: whatsappUrl.toString() });
  };

  const passwordSet = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    const body = parseJsonBody(event);
    const password = validatePassword(body.password);
    if (password !== body.confirmPassword) throw new ApiError(400, 'password_confirmation_mismatch');
    const existing = await getPasswordCredential(guest.guestId);
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `GUEST#${guest.guestId}`,
        sk: 'PASSWORD',
        entityType: 'passwordCredential',
        passwordHash: hashPassword(password),
        createdAt: existing?.createdAt || now(),
        updatedAt: now(),
      },
    }));
    const sessionCookie = await issueSessionCookie(guest);
    return jsonResponse(200, { saved: true, passwordConfigured: true, nickname: guest.nickname }, {
      cookies: [sessionCookie, clearCookie('rsvp_access_link'), clearCookie('rsvp_registration'), clearCookie('rsvp_webauthn')],
    });
  };

  const passwordRemove = async (event) => {
    const guest = await authorizedRegistrationGuest(event);
    await ddb.send(new DeleteCommand({ TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${guest.guestId}`, sk: 'PASSWORD' } }));
    return jsonResponse(200, { removed: true, passwordConfigured: false });
  };

  const passwordLogin = async (event) => {
    const body = parseJsonBody(event);
    const guestId = validGuestId(body.guestId);
    await requireGuestEntry(event, guestId);
    const guest = await getGuest(guestId);
    const credential = await getPasswordCredential(guest.guestId);
    if (!credential || !verifyPassword(body.password, credential.passwordHash)) throw new ApiError(401, 'password_verification_failed');
    return jsonResponse(200, { authenticated: true, nickname: guest.nickname }, {
      cookies: [await issueSessionCookie(guest), clearCookie('rsvp_access_link'), clearCookie('rsvp_registration'), clearCookie('rsvp_webauthn')],
    });
  };

  const authStart = async (event) => {
    const { guestId: requestedGuestId } = parseJsonBody(event);
    const guestId = validGuestId(requestedGuestId);
    await requireGuestEntry(event, guestId);
    const guest = await getGuest(guestId);
    const credentials = await getCredentials(guest.guestId);
    const passwordCredential = await getPasswordCredential(guest.guestId);
    if (credentials.length === 0 && !passwordCredential) {
      const hasResponse = Boolean(await rsvpForGuest(guest.guestId));
      return jsonResponse(200, { mode: hasResponse ? 'whatsapp-retrieve' : 'whatsapp-rsvp', methods: { passkey: false, password: false }, ...(await rsvpConfig()) });
    }
    let options;
    let cookies = [];
    if (credentials.length > 0) {
      options = await webauthn.generateAuthenticationOptions({
        rpID: env.WEBAUTHN_RP_ID,
        userVerification: 'required',
        allowCredentials: credentials.map((credential) => ({
          id: credential.credentialId,
          transports: credential.transports || [],
        })),
      });
      cookies = [await createWebauthnFlow(guest.guestId, 'login', options)];
    }
    const methods = { passkey: credentials.length > 0, password: Boolean(passwordCredential) };
    return jsonResponse(200, {
      mode: methods.passkey && methods.password ? 'credentials' : methods.passkey ? 'passkey' : 'password',
      methods,
      ...(options ? { options } : {}),
    }, { cookies });
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
    const guest = await getGuest(validGuestId(body.guestId));
    if (guest.identityStatus !== 'unconfirmed' && !guest.nickname.endsWith(' — Por confirmar')) {
      throw new ApiError(409, 'registration_not_required');
    }
    const displayName = guest.nickname.replace(/ — Por confirmar$/, '');
    const senderName = normalizeContactName(guest.sender || displayName);
    const nonce = toBase64Url(randomBytes(32));
    const expiresAt = now() + WHATSAPP_TTL_SECONDS;
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `REGISTRATION#${tokenHash(nonce)}`,
        sk: 'CHALLENGE',
        entityType: 'registrationChallenge',
        guestId: guest.guestId,
        sender: senderName.display,
        senderLookup: senderName.lookup,
        publicNameLookup: normalizeContactName(displayName).lookup,
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
    const publicName = encodeURIComponent(displayName);
    const signedMessage = `contact=${publicName}&nonce=${nonce}`;
    const validationSecret = await getValidationSecret();
    if (!validationSecret) throw new ApiError(503, 'validation_unavailable');
    const signature = createHmac('sha256', validationSecret).update(signedMessage, 'utf8').digest('base64url');
    const whatsappUrl = new URL(`https://wa.me/${appNumber.slice(1)}`);
    whatsappUrl.searchParams.set('text', `VALIDATION ${signedMessage}&sig=${signature}`);
    const cookie = await makeSignedCookie('rsvp_registration', { type: 'registration', nonce }, WHATSAPP_TTL_SECONDS);
    return jsonResponse(200, { mode: 'registration', whatsappUrl: whatsappUrl.toString(), expiresAt }, { cookies: [cookie] });
  };

  const registrationStatus = async (event) => {
    const token = await readSignedCookie(event, 'rsvp_registration');
    if (token?.type !== 'registration') return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_registration')] });
    const challenge = await getRegistrationChallenge(token.nonce);
    if (!challenge || challenge.expiresAt < now()) return jsonResponse(200, { status: 'expired' }, { cookies: [clearCookie('rsvp_registration')] });
    return jsonResponse(200, { status: challenge.status === 'created' ? 'created' : challenge.lastError || 'pending' });
  };

  const registerPhoneWebhook = async (event) => {
    const authorization = headerValue(event.headers, 'authorization');
    const expectedSecret = await getPhoneWebhookSecret();
    const providedSecret = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    if (!safeEqual(providedSecret, expectedSecret)) throw new ApiError(401, 'unauthorized');
    const { sender, message } = parseJsonBody(event);
    if (typeof sender !== 'string' || sender.length > 240 || typeof message !== 'string' || message.length > 4096) throw new ApiError(400, 'invalid_phone_message');
    if (!env.PHONE_QUEUE_URL) throw new ApiError(503, 'phone_queue_unavailable');
    try {
      await sqs.send(new SendMessageCommand({ QueueUrl: env.PHONE_QUEUE_URL, MessageBody: JSON.stringify({ sender, message, receivedAt: now() }) }));
    } catch { throw new ApiError(503, 'phone_queue_unavailable'); }
    return emptyResponse(202);
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
      cookies: [await issueSessionCookie(guest), clearCookie('rsvp_access_link'), clearCookie('rsvp_webauthn')],
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
    if (path === '/api/contact/request' && method === 'POST') return requestNewContact(event);
    if (path === '/api/groups' && method === 'GET') {
      await requireCaptchaGate(event);
      return listGroups();
    }
    if (path === '/api/guests' && method === 'GET') {
      await requireCaptchaGate(event);
      const captchaCookies = [];
      const groupId = new URLSearchParams(event.rawQueryString || '').get('group') || '';
      const query = new URLSearchParams(event.rawQueryString || '').get('q') || '';
      const response = await listGuests(groupId, query);
      if (captchaCookies.length > 0) response.cookies = captchaCookies;
      return response;
    }
    if (path === '/api/rsvp/summary' && method === 'GET') {
      if (!(await readSessionGuest(event))) await requireCaptchaGate(event);
      return rsvpSummary();
    }
    if (path === '/api/rsvp' && method === 'GET') return getRsvp(event);
    if (path === '/api/rsvp' && method === 'PUT') return saveRsvp(event);
    if (path === '/api/link/candidates' && method === 'GET') return linkCandidates(event);
    if (path === '/api/link' && method === 'GET') {
      const sessionGuest = await readSessionGuest(event);
      if (!sessionGuest) throw new ApiError(401, 'authentication_required');
      return jsonResponse(200, await linkState(sessionGuest.guestId));
    }
    if (path === '/api/link' && method === 'POST') return createLink(event);
    if (path === '/api/link' && method === 'DELETE') return removeLink(event);
    if (path === '/api/rsvp/whatsapp/start' && method === 'POST') return startWhatsappRsvp(event);
    if (path === '/api/rsvp/validation-report' && method === 'POST') return validationMismatchReport(event);
    if (path === '/api/admin/settings' && method === 'GET') return adminSettings(event);
    if (path === '/api/admin/settings' && method === 'PUT') return saveAdminSettings(event);
    if (path === '/api/admin/summary' && method === 'GET') return adminSummary(event);
    if (path === '/api/admin/summary' && method === 'PUT') return saveAdminSummary(event);
    if (path === '/api/admin/groups' && method === 'GET') return adminGroups(event);
    if (path === '/api/admin/guests' && method === 'GET') return adminGuests(event);
    if (path === '/api/admin/guests' && method === 'PUT') return saveAdminGuest(event);
    if (path === '/api/admin/guests' && method === 'POST') return addAdminGuest(event);
    if (path === '/api/admin/guests' && method === 'DELETE') return removeAdminGuest(event);
    if (path === '/api/admin/guests/access-link' && method === 'POST') return createGuestAccessLink(event);
    if (path === '/api/admin/guests/reissue-registration' && method === 'POST') return reissueGuestRegistration(event);
    if (path === '/api/admin/guests/recover-registration' && method === 'POST') return recoverGuestRegistration(event);
    if (path === '/api/admin/guests/reset-vote' && method === 'POST') return resetGuestVote(event);
    if (path === '/api/access-link/consume' && method === 'POST') return consumeGuestAccessLink(event);
    if (path === '/api/auth/start' && method === 'POST') return authStart(event);
    if (path === '/api/auth/password/login' && method === 'POST') return passwordLogin(event);
    if (path === '/api/auth/password' && method === 'POST') return passwordSet(event);
    if (path === '/api/auth/password' && method === 'DELETE') return passwordRemove(event);
    if (path === '/api/register/start' && method === 'POST') return startFriendRegistration(event);
    if (path === '/api/register/status' && method === 'GET') return registrationStatus(event);
    if (path === '/api/phone/register' && method === 'POST') return registerPhoneWebhook(event);
    if (path === '/api/auth/passkeys/register/options' && method === 'POST') return registrationOptions(event);
    if (path === '/api/auth/passkeys/register/verify' && method === 'POST') return registrationVerify(event);
    if (path === '/api/auth/passkeys/login/verify' && method === 'POST') return loginVerify(event);
    if (path === '/api/session' && method === 'GET') return sessionStatus(event);
    if (path === '/api/auth/logout' && method === 'POST') {
      return jsonResponse(200, { authenticated: false }, {
        cookies: [clearCookie('rsvp_session'), clearCookie('rsvp_bootstrap'), clearCookie('rsvp_access_link'), clearCookie('rsvp_registration'), clearCookie('rsvp_webauthn')],
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
        console.error(JSON.stringify({ event: 'api_internal_error', path: rawPath, method, error: error?.message || String(error) }));
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

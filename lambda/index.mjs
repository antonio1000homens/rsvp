import { createHmac, randomBytes as nodeRandomBytes, randomUUID } from 'node:crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  TransactWriteCommand,
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
const WHATSAPP_TTL_SECONDS = 5 * 60;
const WEBAUTHN_TTL_SECONDS = 5 * 60;
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const CAPTCHA_TTL_SECONDS = 15 * 60;
const VALIDATION_MESSAGE = /^VALIDATION contact=([^&\s]+)&nonce=([A-Za-z0-9_-]{43})&sig=([A-Za-z0-9_-]{43})$/;
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
  const mealTypes = Array.isArray(body.mealTypes) ? [...new Set(body.mealTypes.map(String))] : [];
  const guestCount = Number(body.guestCount);
  const dietaryRestrictions = String(body.dietaryRestrictions || '').trim();
  const restaurantChoice = String(body.restaurantChoice || '').trim().replace(/\s+/g, ' ');
  if (!availableDays.length || !availableDays.every((day) => days.includes(day))) throw new ApiError(400, 'invalid_availability');
  if (!mealTypes.length || !mealTypes.every((type) => ['lunch', 'dinner', 'drinks'].includes(type))) throw new ApiError(400, 'invalid_meal_types');
  if (!Number.isInteger(guestCount) || guestCount < 1 || guestCount > 12) throw new ApiError(400, 'invalid_guest_count');
  if (dietaryRestrictions.length > 500 || restaurantChoice.length < 2 || restaurantChoice.length > 120) throw new ApiError(400, 'invalid_preferences');
  return { availableDays, mealTypes, guestCount, dietaryRestrictions, restaurantChoice };
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
    return jsonResponse(200, { question: question.question, challenge }, { cookies: captchaCookies });
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

  const listGuests = async (groupId = '') => {
    let profiles;
    if (groupId) {
      await getGroup(validGroupId(groupId));
      const result = await ddb.send(new QueryCommand({
        TableName: env.RSVP_TABLE,
        KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
        ExpressionAttributeValues: { ':pk': `GROUP#${groupId}`, ':prefix': 'MEMBER#' },
        ConsistentRead: true,
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
    const guests = profiles.filter(Boolean)
      .filter(({ identityStatus }) => identityStatus !== 'to_add')
      .map(({ guestId, nickname, identityStatus }) => ({
        id: guestId,
        nickname: nickname.replace(/ — Por confirmar$/, ''),
        registrationRequired: identityStatus === 'unconfirmed' || nickname.endsWith(' — Por confirmar'),
      }))
      .sort((left, right) => left.nickname.localeCompare(right.nickname));
    return jsonResponse(200, { guests });
  };

  const rsvpForGuest = async (guestId) => {
    const result = await ddb.send(new GetCommand({
      TableName: env.RSVP_TABLE,
      Key: { pk: `RSVP#${guestId}`, sk: 'RESPONSE' },
      ConsistentRead: true,
    }));
    return result.Item || null;
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
    const guest = await readSessionGuest(event);
    if (!guest) throw new ApiError(401, 'authentication_required');
    const response = await rsvpForGuest(guest.guestId);
    return jsonResponse(200, { ...(await rsvpConfig()), response: response ? {
      availableDays: response.availableDays, mealTypes: response.mealTypes, guestCount: response.guestCount,
      dietaryRestrictions: response.dietaryRestrictions, restaurantChoice: response.restaurantChoice,
    } : null });
  };

  const saveRsvp = async (event) => {
    const guest = await readSessionGuest(event);
    if (!guest) throw new ApiError(401, 'authentication_required');
    const config = await rsvpConfig();
    const choices = responseChoices(parseJsonBody(event), config.days);
    if (config.restaurantChoices.length && !config.restaurantChoices.includes(choices.restaurantChoice)) throw new ApiError(400, 'invalid_restaurant_choice');
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: { pk: `RSVP#${guest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: guest.guestId, ...choices, updatedAt: now() },
    }));
    return jsonResponse(200, { saved: true, ...config, response: choices });
  };

  const rsvpSummary = async () => {
    const { days } = await rsvpConfig();
    const result = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'entityType = :response',
      ExpressionAttributeValues: { ':response': 'rsvpResponse' },
      ProjectionExpression: 'availableDays, mealTypes, guestCount, restaurantChoice',
    }));
    const responses = result.Items || [];
    const byDay = Object.fromEntries(days.map((day) => [day, 0]));
    const byMeal = { lunch: 0, dinner: 0, drinks: 0 };
    const restaurants = {};
    let guests = 0;
    for (const response of responses) {
      guests += Number(response.guestCount || 0);
      for (const day of response.availableDays || []) if (day in byDay) byDay[day] += Number(response.guestCount || 0);
      for (const meal of response.mealTypes || []) if (meal in byMeal) byMeal[meal] += Number(response.guestCount || 0);
      if (response.restaurantChoice) restaurants[response.restaurantChoice] = (restaurants[response.restaurantChoice] || 0) + Number(response.guestCount || 0);
    }
    return jsonResponse(200, { responses: responses.length, guests, byDay, byMeal, restaurants });
  };

  const adminSettings = async (event) => {
    await requireAdmin(event);
    const settings = await eventSettings();
    return jsonResponse(200, { ...(await rsvpConfig()), triviaQuestions: settings.triviaQuestions || [], useTrivia: Boolean(settings.useTrivia) });
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
    await ddb.send(new PutCommand({ TableName: env.RSVP_TABLE, Item: { pk: 'EVENT#DEFAULT', sk: 'SETTINGS', entityType: 'eventSettings', restaurantChoices, triviaQuestions, useTrivia, updatedAt: now() } }));
    return jsonResponse(200, { saved: true, ...(await rsvpConfig()), triviaQuestions, useTrivia });
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

  const requestNewContact = async (event) => {
    await requireTriviaGate(event);
    const body = parseJsonBody(event);
    let name;
    try {
      name = normalizeContactName(body.name);
    } catch (error) {
      throw new ApiError(400, 'invalid_contact_details', error.message);
    }
    const existing = await ddb.send(new ScanCommand({
      TableName: env.RSVP_TABLE,
      FilterExpression: 'sk = :profile AND entityType = :guest AND nicknameLookup = :nicknameLookup AND enabled = :enabled',
      ExpressionAttributeValues: { ':profile': 'PROFILE', ':guest': 'guest', ':nicknameLookup': name.lookup, ':enabled': true },
      ProjectionExpression: 'guestId',
    }));
    if (existing.Items?.length) throw new ApiError(409, 'contact_already_requested');
    const guestId = randomUUID();
    const nowValue = now();
    await ddb.send(new PutCommand({
      TableName: env.RSVP_TABLE,
      Item: {
        pk: `GUEST#${guestId}`, sk: 'PROFILE', entityType: 'guest', guestId,
        nickname: name.display, nicknameLookup: name.lookup, sender: name.display,
        identityStatus: 'to_add', enabled: true, sessionVersion: 1,
        createdAt: nowValue, updatedAt: nowValue,
      },
      ConditionExpression: 'attribute_not_exists(pk)',
    }));
    const whatsappUrl = new URL(`https://wa.me/${CONTACT_REQUEST_NUMBER.slice(1)}`);
    whatsappUrl.searchParams.set('text', `Ola Antonio, eu sou o ${name.display} e este e o meu numero de whatsapp. podes-me adicionar a pagina.`);
    return jsonResponse(200, { status: 'to_add', whatsappUrl: whatsappUrl.toString() });
  };

  const authStart = async (event) => {
    await requireCaptchaGate(event);
    const { guestId: requestedGuestId } = parseJsonBody(event);
    const guest = await getGuest(validGuestId(requestedGuestId));
    if (guest.identityStatus === 'unconfirmed' || guest.nickname.endsWith(' — Por confirmar')) {
      throw new ApiError(409, 'registration_required');
    }
    const credentials = await getCredentials(guest.guestId);
    if (credentials.length === 0) throw new ApiError(409, 'passkey_required');

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
    const contact = encodeURIComponent(senderName.display);
    const signedMessage = `contact=${contact}&nonce=${nonce}`;
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
    let normalizedSender;
    try { normalizedSender = normalizeContactName(sender); } catch { throw new ApiError(400, 'invalid_sender'); }
    const match = VALIDATION_MESSAGE.exec(String(message || ''));
    if (!match) throw new ApiError(400, 'invalid_validation_message');
    const [, encodedContact, nonce, signature] = match;
    const validationSecret = await getValidationSecret();
    if (!validationSecret) throw new ApiError(503, 'validation_unavailable');
    const signedMessage = `contact=${encodedContact}&nonce=${nonce}`;
    const expectedSignature = createHmac('sha256', validationSecret).update(signedMessage, 'utf8').digest('base64url');
    if (!safeEqual(signature, expectedSignature)) throw new ApiError(400, 'invalid_validation_signature');
    let decodedSender;
    try { decodedSender = normalizeContactName(decodeURIComponent(encodedContact)); } catch { throw new ApiError(400, 'invalid_validation_message'); }
    const key = { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE' };
    const existing = await ddb.send(new GetCommand({ TableName: env.RSVP_TABLE, Key: key, ConsistentRead: true }));
    const challenge = existing.Item;
    if (!challenge || challenge.status !== 'pending' || challenge.expiresAt < now()) {
      throw new ApiError(challenge?.status === 'created' ? 409 : 410, 'registration_challenge_unavailable');
    }
    if (challenge.senderLookup !== decodedSender.lookup || normalizedSender.lookup !== challenge.senderLookup) {
      await ddb.send(new UpdateCommand({
        TableName: env.RSVP_TABLE,
        Key: key,
        UpdateExpression: 'SET lastError = :error, lastErrorAt = :now REMOVE approvedAt',
        ConditionExpression: '#status = :pending AND expiresAt >= :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':error': 'sender_mismatch', ':pending': 'pending', ':now': now() },
      }));
      // The webhook was processed successfully. The mismatch is an expected
      // business outcome, so Tasker must not treat it as an HTTP failure.
      return emptyResponse(204);
    }
    const selectedGuest = await getGuest(challenge.guestId);
    try {
      await ddb.send(new TransactWriteCommand({ TransactItems: [
        { Update: { TableName: env.RSVP_TABLE, Key: key, UpdateExpression: 'SET #status = :created, approvedAt = :now', ConditionExpression: '#status = :pending AND expiresAt >= :now', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':created': 'created', ':pending': 'pending', ':now': now() } } },
        { Update: { TableName: env.RSVP_TABLE, Key: { pk: `GUEST#${selectedGuest.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET identityStatus = :confirmed, sender = :sender, updatedAt = :now', ConditionExpression: 'enabled = :enabled AND (identityStatus = :unconfirmed OR begins_with(nickname, :pendingPrefix))', ExpressionAttributeValues: { ':confirmed': 'confirmed', ':unconfirmed': 'unconfirmed', ':enabled': true, ':sender': decodedSender.display, ':pendingPrefix': selectedGuest.nickname.replace(/ — Por confirmar$/i, ''), ':now': now() } } },
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
    if (path === '/api/contact/request' && method === 'POST') return requestNewContact(event);
    if (path === '/api/groups' && method === 'GET') {
      await requireTriviaGate(event);
      return listGroups();
    }
    if (path === '/api/guests' && method === 'GET') {
      await requireTriviaGate(event);
      const captchaCookies = [];
      const groupId = new URLSearchParams(event.rawQueryString || '').get('group') || '';
      const response = await listGuests(groupId);
      if (captchaCookies.length > 0) response.cookies = captchaCookies;
      return response;
    }
    if (path === '/api/rsvp/summary' && method === 'GET') {
      await requireTriviaGate(event);
      return rsvpSummary();
    }
    if (path === '/api/rsvp' && method === 'GET') return getRsvp(event);
    if (path === '/api/rsvp' && method === 'PUT') return saveRsvp(event);
    if (path === '/api/admin/settings' && method === 'GET') return adminSettings(event);
    if (path === '/api/admin/settings' && method === 'PUT') return saveAdminSettings(event);
    if (path === '/api/admin/groups' && method === 'GET') return adminGroups(event);
    if (path === '/api/auth/start' && method === 'POST') return authStart(event);
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

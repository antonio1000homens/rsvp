import { createHmac } from 'node:crypto';
import { GetCommand, PutCommand, TransactWriteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { normalizeContactName, safeEqual, tokenHash } from '../shared/identity.mjs';

const VALIDATION_MESSAGE = /^VALIDATION (nome|contact)=([^&\s]+)&nonce=([A-Za-z0-9_-]{43})&sig=([A-Za-z0-9_-]{43})$/;
const LINK_MESSAGE = /^LINK link=([0-9a-f-]{36})&contact=([^&\s]+)&nonce=([A-Za-z0-9_-]{43})&sig=([A-Za-z0-9_-]{43})$/i;

const conditionalFailure = (error) =>
  error?.name === 'ConditionalCheckFailedException' || error?.name === 'TransactionCanceledException';

// Business outcomes are acknowledged by SQS. Only infrastructure failures throw
// and are retried/redriven by the queue.
export const processPhoneRegistration = async ({ sender, message, ddb, tableName, validationSecret, now, receivedAt = now, onConfirmedRegistration = null, onValidation = null }) => {
  const logValidation = (fields) => { const event = { event: 'validation_request', ...fields }; console.info(JSON.stringify(event)); if (onValidation) onValidation(event); };
  let normalizedSender;
  try { normalizedSender = normalizeContactName(sender); } catch { return 'invalid_sender'; }
  const match = VALIDATION_MESSAGE.exec(String(message || ''));
  const linkMatch = LINK_MESSAGE.exec(String(message || ''));
  if (!match && !linkMatch) return 'invalid_validation_message';
  if (linkMatch) return processMemberLink({ sender, match: linkMatch, ddb, tableName, validationSecret, now });
  const [, field, encodedName, nonce, signature] = match;
  const signedMessage = `${field}=${encodedName}&nonce=${nonce}`;
  const expectedSignature = createHmac('sha256', validationSecret).update(signedMessage, 'utf8').digest('base64url');
  if (!safeEqual(signature, expectedSignature)) {
    let displayName = '';
    try { displayName = decodeURIComponent(encodedName); } catch { /* keep it empty */ }
    logValidation({ sender, displayName, outcome: 'invalid_validation_signature', wouldStoreResponse: false, storedResponse: false });
    return 'invalid_validation_signature';
  }
  let decodedName;
  try { decodedName = normalizeContactName(decodeURIComponent(encodedName)); } catch { return 'invalid_validation_message'; }

  const key = { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE' };
  const challenge = (await ddb.send(new GetCommand({ TableName: tableName, Key: key, ConsistentRead: true }))).Item;
  const validationExpiresAt = Number(challenge?.validationExpiresAt || challenge?.expiresAt || 0);
  if (!challenge || challenge.status !== 'pending' || validationExpiresAt < receivedAt) {
    logValidation({ sender, displayName: decodedName.display, outcome: 'registration_challenge_unavailable', wouldStoreResponse: false, storedResponse: false });
    return 'registration_challenge_unavailable';
  }
  const selectedGuest = (await ddb.send(new GetCommand({
    TableName: tableName, Key: { pk: `GUEST#${challenge.guestId}`, sk: 'PROFILE' }, ConsistentRead: true,
  }))).Item;
  const nickname = selectedGuest?.nickname ? String(selectedGuest.nickname).replace(/ — Por confirmar$/, '') : '';
  const expectedPublicName = selectedGuest ? normalizeContactName(String(selectedGuest.nickname || '').replace(/ — Por confirmar$/, '')) : null;
  const messageMatchesGuest = field === 'nome'
    ? expectedPublicName?.lookup === decodedName.lookup
    : challenge.senderLookup === decodedName.lookup;
  if (!messageMatchesGuest || normalizedSender.lookup !== challenge.senderLookup) {
    try {
      await ddb.send(new UpdateCommand({
        TableName: tableName, Key: key,
        UpdateExpression: 'SET lastError = :error, lastErrorAt = :now REMOVE approvedAt',
        ConditionExpression: '#status = :pending AND expiresAt >= :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':error': 'sender_mismatch', ':pending': 'pending', ':now': now },
      }));
    } catch (error) { if (!conditionalFailure(error)) throw error; }
    logValidation({ sender, displayName: decodedName.display, nickname, expectedSender: challenge.sender, outcome: 'sender_mismatch', wouldStoreResponse: Boolean(challenge.response), storedResponse: false });
    return 'sender_mismatch';
  }
  if (!selectedGuest) {
    logValidation({ sender, displayName: decodedName.display, nickname, outcome: 'registration_unavailable', wouldStoreResponse: Boolean(challenge.response), storedResponse: false });
    return 'registration_unavailable';
  }
  try {
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Update: { TableName: tableName, Key: key, UpdateExpression: 'SET #status = :created, approvedAt = :now, receivedAt = :receivedAt', ConditionExpression: '#status = :pending AND (validationExpiresAt >= :receivedAt OR expiresAt >= :receivedAt)', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':created': 'created', ':pending': 'pending', ':now': now, ':receivedAt': receivedAt } } },
      ...(challenge.pendingRegistration ? [{ Delete: { TableName: tableName, Key: { pk: `GUEST#${selectedGuest.guestId}`, sk: 'PENDING_REGISTRATION' }, ConditionExpression: 'nonce = :nonce', ExpressionAttributeValues: { ':nonce': nonce } } }] : []),
      { Update: { TableName: tableName, Key: { pk: `GUEST#${selectedGuest.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET identityStatus = :confirmed, sender = :sender, senderLookup = :senderLookup, lastRegistrationApprovedAt = :now, updatedAt = :now', ConditionExpression: 'enabled = :enabled', ExpressionAttributeValues: { ':confirmed': 'confirmed', ':enabled': true, ':sender': normalizedSender.display, ':senderLookup': normalizedSender.lookup, ':now': now } } },
      ...(challenge.response ? [{ Put: { TableName: tableName, Item: { pk: `RSVP#${selectedGuest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: selectedGuest.guestId, ...challenge.response, updatedAt: now } } }] : []),
    ] }));
  } catch (error) {
    if (conditionalFailure(error)) {
      logValidation({ sender, displayName: decodedName.display, nickname, outcome: 'registration_unavailable', wouldStoreResponse: Boolean(challenge.response), storedResponse: false });
      return 'registration_unavailable';
    }
    throw error;
  }
  logValidation({ sender, displayName: decodedName.display, nickname, expectedSender: challenge.sender, outcome: 'created', wouldStoreResponse: Boolean(challenge.response), storedResponse: Boolean(challenge.response) });
  if (onConfirmedRegistration) await onConfirmedRegistration({ nickname: String(selectedGuest.nickname || '').replace(/ — Por confirmar$/, '') });
  return 'created';
};

const processMemberLink = async ({ sender, match, ddb, tableName, validationSecret, now }) => {
  let normalizedSender;
  try { normalizedSender = normalizeContactName(sender); } catch { return 'invalid_sender'; }
  const [, linkId, encodedContact, nonce, signature] = match;
  const signedMessage = `LINK link=${linkId}&contact=${encodedContact}&nonce=${nonce}`;
  const expectedSignature = createHmac('sha256', validationSecret).update(signedMessage, 'utf8').digest('base64url');
  if (!safeEqual(signature, expectedSignature)) return 'invalid_validation_signature';
  let targetName;
  try { targetName = normalizeContactName(decodeURIComponent(encodedContact)); } catch { return 'invalid_validation_message'; }
  const requestKey = { pk: `LINK#${linkId}`, sk: 'REQUEST' };
  const request = (await ddb.send(new GetCommand({ TableName: tableName, Key: requestKey, ConsistentRead: true }))).Item;
  if (!request || request.status !== 'pending' || request.nonce !== nonce || request.linkId !== linkId || request.targetNickname !== targetName.display) return 'link_unavailable';
  const target = (await ddb.send(new GetCommand({ TableName: tableName, Key: { pk: `GUEST#${request.targetId}`, sk: 'PROFILE' }, ConsistentRead: true }))).Item;
  if (!target?.enabled || normalizeContactName(target.sender || target.nickname).lookup !== normalizedSender.lookup) return 'sender_mismatch';
  const targetLink = { pk: `GUEST#${request.targetId}`, sk: 'LINK' };
  const requesterLink = { pk: `GUEST#${request.requesterId}`, sk: 'LINK' };
  const targetResponse = { pk: `RSVP#${request.targetId}`, sk: 'RESPONSE' };
  const requesterResponse = request.response || (await ddb.send(new GetCommand({
    TableName: tableName,
    Key: { pk: `RSVP#${request.requesterId}`, sk: 'RESPONSE' },
    ConsistentRead: true,
  }))).Item || null;
  const actions = [
    { Update: { TableName: tableName, Key: requestKey, UpdateExpression: 'SET #status = :active, approvedAt = :now', ConditionExpression: '#status = :pending', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':active': 'active', ':pending': 'pending', ':now': now } } },
    { Update: { TableName: tableName, Key: requesterLink, UpdateExpression: 'SET #status = :active', ConditionExpression: '#status = :pending', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':active': 'active', ':pending': 'pending' } } },
    { Update: { TableName: tableName, Key: targetLink, UpdateExpression: 'SET #status = :active', ConditionExpression: '#status = :pending', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':active': 'active', ':pending': 'pending' } } },
  ];
  if (requesterResponse) {
    actions.push({ Delete: { TableName: tableName, Key: targetResponse } });
    actions.push({ Put: { TableName: tableName, Item: { ...requesterResponse, pk: targetResponse.pk, sk: targetResponse.sk, entityType: 'rsvpResponse', guestId: request.targetId, updatedAt: now } } });
  }
  try {
    await ddb.send(new TransactWriteCommand({ TransactItems: actions }));
  } catch (error) {
    if (conditionalFailure(error)) return 'link_unavailable';
    throw error;
  }
  return 'linked';
};

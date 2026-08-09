import { createHmac } from 'node:crypto';
import { GetCommand, PutCommand, TransactWriteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { normalizeContactName, safeEqual, tokenHash } from '../shared/identity.mjs';

const VALIDATION_MESSAGE = /^VALIDATION contact=([^&\s]+)&nonce=([A-Za-z0-9_-]{43})&sig=([A-Za-z0-9_-]{43})$/;

const conditionalFailure = (error) =>
  error?.name === 'ConditionalCheckFailedException' || error?.name === 'TransactionCanceledException';

// Business outcomes are acknowledged by SQS. Only infrastructure failures throw
// and are retried/redriven by the queue.
export const processPhoneRegistration = async ({ sender, message, ddb, tableName, validationSecret, now }) => {
  let normalizedSender;
  try { normalizedSender = normalizeContactName(sender); } catch { return 'invalid_sender'; }
  const match = VALIDATION_MESSAGE.exec(String(message || ''));
  if (!match) return 'invalid_validation_message';
  const [, encodedContact, nonce, signature] = match;
  const signedMessage = `contact=${encodedContact}&nonce=${nonce}`;
  const expectedSignature = createHmac('sha256', validationSecret).update(signedMessage, 'utf8').digest('base64url');
  if (!safeEqual(signature, expectedSignature)) return 'invalid_validation_signature';
  let decodedSender;
  try { decodedSender = normalizeContactName(decodeURIComponent(encodedContact)); } catch { return 'invalid_validation_message'; }

  const key = { pk: `REGISTRATION#${tokenHash(nonce)}`, sk: 'CHALLENGE' };
  const challenge = (await ddb.send(new GetCommand({ TableName: tableName, Key: key, ConsistentRead: true }))).Item;
  if (!challenge || challenge.status !== 'pending' || challenge.expiresAt < now) return 'registration_challenge_unavailable';
  if (challenge.senderLookup !== decodedSender.lookup || normalizedSender.lookup !== challenge.senderLookup) {
    try {
      await ddb.send(new UpdateCommand({
        TableName: tableName, Key: key,
        UpdateExpression: 'SET lastError = :error, lastErrorAt = :now REMOVE approvedAt',
        ConditionExpression: '#status = :pending AND expiresAt >= :now',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':error': 'sender_mismatch', ':pending': 'pending', ':now': now },
      }));
    } catch (error) { if (!conditionalFailure(error)) throw error; }
    return 'sender_mismatch';
  }

  const selectedGuest = (await ddb.send(new GetCommand({
    TableName: tableName, Key: { pk: `GUEST#${challenge.guestId}`, sk: 'PROFILE' }, ConsistentRead: true,
  }))).Item;
  if (!selectedGuest) return 'registration_unavailable';
  try {
    await ddb.send(new TransactWriteCommand({ TransactItems: [
      { Update: { TableName: tableName, Key: key, UpdateExpression: 'SET #status = :created, approvedAt = :now', ConditionExpression: '#status = :pending AND expiresAt >= :now', ExpressionAttributeNames: { '#status': 'status' }, ExpressionAttributeValues: { ':created': 'created', ':pending': 'pending', ':now': now } } },
      { Delete: { TableName: tableName, Key: { pk: `GUEST#${selectedGuest.guestId}`, sk: 'PENDING_REGISTRATION' } } },
      { Update: { TableName: tableName, Key: { pk: `GUEST#${selectedGuest.guestId}`, sk: 'PROFILE' }, UpdateExpression: 'SET identityStatus = :confirmed, sender = :sender, updatedAt = :now', ConditionExpression: 'enabled = :enabled', ExpressionAttributeValues: { ':confirmed': 'confirmed', ':enabled': true, ':sender': decodedSender.display, ':now': now } } },
      ...(challenge.response ? [{ Put: { TableName: tableName, Item: { pk: `RSVP#${selectedGuest.guestId}`, sk: 'RESPONSE', entityType: 'rsvpResponse', guestId: selectedGuest.guestId, ...challenge.response, updatedAt: now } } }] : []),
    ] }));
  } catch (error) {
    if (conditionalFailure(error)) return 'registration_unavailable';
    throw error;
  }
  return 'created';
};

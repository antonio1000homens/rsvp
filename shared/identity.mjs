import { createHmac, createHash, timingSafeEqual } from 'node:crypto';

const E164 = /^\+[1-9]\d{7,14}$/;

export const normalizeE164 = (value) => {
  const normalized = String(value ?? '').trim().replace(/[\s()-]/g, '');
  if (!E164.test(normalized)) throw new Error('Phone numbers must use E.164 format, for example +351912345678.');
  return normalized;
};

export const normalizeNickname = (value) => {
  const display = String(value ?? '').normalize('NFKC').trim().replace(/\s+/g, ' ');
  if (display.length < 1 || display.length > 60) throw new Error('Nickname must contain between 1 and 60 characters.');
  if (/\p{C}/u.test(display)) throw new Error('Nickname contains unsupported control characters.');
  return { display, lookup: display.toLocaleLowerCase('en-US') };
};

export const normalizeContactName = (value) => {
  const nickname = normalizeNickname(value);
  return { ...nickname, lookup: nickname.lookup.normalize('NFKD').replace(/[\u0300-\u036f]/g, '') };
};

export const normalizePhoneLast4 = (value) => {
  const normalized = String(value ?? '').trim();
  if (!/^\d{4}$/.test(normalized)) throw new Error('Enter the last four phone digits.');
  return normalized;
};

export const toBase64Url = (value) => Buffer.from(value).toString('base64url');
export const fromBase64Url = (value) => new Uint8Array(Buffer.from(value, 'base64url'));

export const contactLookupFor = (phone, pepper) => {
  const normalized = normalizeE164(phone);
  if (!pepper) throw new Error('A contact pepper is required.');
  return createHmac('sha256', pepper).update(normalized, 'utf8').digest('base64url');
};

export const tokenHash = (value) => createHash('sha256').update(String(value), 'utf8').digest('base64url');

export const safeEqual = (left, right) => {
  if (!left || !right) return false;
  const leftBuffer = Buffer.from(String(left), 'utf8');
  const rightBuffer = Buffer.from(String(right), 'utf8');
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
};

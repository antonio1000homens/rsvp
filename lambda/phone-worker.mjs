import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { processPhoneRegistration } from './phone-registration.mjs';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
const ssm = new SSMClient({});
let validationSecret;

const secret = async () => {
  if (!validationSecret) validationSecret = (await ssm.send(new GetParameterCommand({ Name: process.env.VALIDATION_SECRET_PARAMETER, WithDecryption: true }))).Parameter?.Value;
  if (!validationSecret) throw new Error('validation_secret_unavailable');
  return validationSecret;
};

export const handler = async (event = {}) => {
  for (const record of event.Records || []) {
    let payload;
    try { payload = JSON.parse(record.body); } catch { continue; }
    if (!payload || typeof payload.sender !== 'string' || typeof payload.message !== 'string' || payload.sender.length > 240 || payload.message.length > 4096) continue;
    await processPhoneRegistration({ sender: payload.sender, message: payload.message, ddb, tableName: process.env.RSVP_TABLE, validationSecret: await secret(), now: Math.floor(Date.now() / 1000) });
  }
};

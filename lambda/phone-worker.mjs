import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { SendMessageCommand, SQSClient } from '@aws-sdk/client-sqs';
import { processPhoneRegistration } from './phone-registration.mjs';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
const ssm = new SSMClient({});
const sqs = new SQSClient({});
let validationSecret;

const secret = async () => {
  if (!validationSecret) validationSecret = (await ssm.send(new GetParameterCommand({ Name: process.env.VALIDATION_SECRET_PARAMETER, WithDecryption: true }))).Parameter?.Value;
  if (!validationSecret) throw new Error('validation_secret_unavailable');
  return validationSecret;
};

export const handler = async (event = {}) => {
  const batchItemFailures = [];
  for (const record of event.Records || []) {
    try {
      let payload;
      try { payload = JSON.parse(record.body); } catch { continue; }
      if (!payload || typeof payload.sender !== 'string' || typeof payload.message !== 'string' || payload.sender.length > 240 || payload.message.length > 4096) continue;
      if (payload.message.startsWith('VALIDATION ')) console.info(JSON.stringify({ event: 'validation_request_received', sender: payload.sender }));
      const activity = [];
      await processPhoneRegistration({ sender: payload.sender, message: payload.message, ddb, tableName: process.env.RSVP_TABLE, validationSecret: await secret(), now: Math.floor(Date.now() / 1000), onConfirmedRegistration: (registration) => activity.push(registration) });
      if (activity.length && process.env.SUMMARY_QUEUE_URL) {
        await sqs.send(new SendMessageCommand({ QueueUrl: process.env.SUMMARY_QUEUE_URL, MessageBody: JSON.stringify({ activity: { type: 'registration', nickname: activity[0].nickname } }) }));
      }
    } catch (error) {
      console.error(JSON.stringify({ event: 'phone_registration_processing_failed', error: error?.name || 'unknown_error', message: error?.message || 'unknown_error' }));
      if (record.messageId) batchItemFailures.push({ itemIdentifier: record.messageId });
      else throw new Error('sqs_record_missing_message_id');
    }
  }
  return { batchItemFailures };
};

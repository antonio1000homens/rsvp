import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, ScanCommand } from '@aws-sdk/lib-dynamodb';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { aggregateEventSummary, buildEventNarrativePrompt, generateEventNarrative } from './event-summary.mjs';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}), { marshallOptions: { removeUndefinedValues: true } });
const ssm = new SSMClient({});
let apiKey;

const geminiApiKey = async () => {
  if (!apiKey) apiKey = (await ssm.send(new GetParameterCommand({ Name: process.env.GEMINI_API_KEY_PARAMETER, WithDecryption: true }))).Parameter?.Value;
  if (!apiKey) throw new Error('gemini_api_key_unavailable');
  return apiKey;
};

export const processSummaryEvent = async ({ event, ddbClient = ddb, getApiKey = geminiApiKey, generate = generateEventNarrative, tableName = process.env.RSVP_TABLE, now = () => Math.floor(Date.now() / 1000) }) => {
  if (!event?.activity || !['registration', 'rsvp_saved'].includes(event.activity.type) || typeof event.activity.nickname !== 'string' || !event.activity.nickname.trim()) return;
  const [responses, settings] = await Promise.all([
    ddbClient.send(new ScanCommand({ TableName: tableName, ConsistentRead: true, FilterExpression: 'entityType = :response', ExpressionAttributeValues: { ':response': 'rsvpResponse' }, ProjectionExpression: 'availableDays, mealTypes, guestCount, restaurantChoices, restaurantChoice' })),
    ddbClient.send(new GetCommand({ TableName: tableName, ConsistentRead: true, Key: { pk: 'EVENT#DEFAULT', sk: 'SETTINGS' } })),
  ]);
  const summary = aggregateEventSummary({ responses: responses.Items || [], configuredRestaurants: settings.Item?.restaurantChoices || [] });
  const activity = { type: event.activity.type === 'registration' ? 'registration' : 'rsvp_saved', nickname: event.activity.nickname.trim() };
  const { narrative, model } = await generate({ apiKey: await getApiKey(), prompt: buildEventNarrativePrompt({ summary, activity }) });
  await ddbClient.send(new PutCommand({ TableName: tableName, Item: { pk: 'EVENT#DEFAULT', sk: 'AI_SUMMARY', entityType: 'aiSummary', narrative, model, generatedAt: now(), lastActivity: activity } }));
};

export const handler = async (event = {}) => {
  const batchItemFailures = [];
  for (const record of event.Records || []) {
    try { await processSummaryEvent({ event: JSON.parse(record.body) }); }
    catch (error) { console.error('event_summary_failed', error?.message); if (record.messageId) batchItemFailures.push({ itemIdentifier: record.messageId }); else throw error; }
  }
  return { batchItemFailures };
};

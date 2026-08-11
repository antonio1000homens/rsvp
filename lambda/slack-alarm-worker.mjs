import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';

const ssm = new SSMClient({});
let webhookPromise;

const webhookUrl = async (parameterName) => {
  webhookPromise ||= ssm.send(new GetParameterCommand({ Name: parameterName, WithDecryption: true }))
    .then((result) => String(result.Parameter?.Value || ''));
  return webhookPromise;
};

export const handler = async (event) => {
  const url = await webhookUrl(process.env.SLACK_WEBHOOK_PARAMETER);
  if (!url) throw new Error('slack_webhook_not_configured');
  for (const record of event.Records || []) {
    const message = JSON.parse(record.Sns?.Message || '{}');
    const alarm = message.AlarmName || 'CloudWatch alarm';
    const state = message.NewStateValue || 'UNKNOWN';
    const reason = message.NewStateReason || '';
    const region = message.Region || process.env.AWS_REGION || '';
    const colour = state === 'ALARM' ? '#d72b2b' : state === 'OK' ? '#2eb67d' : '#ecb22e';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ attachments: [{ color: colour, title: `[${state}] ${alarm}`, text: reason, fields: [{ title: 'Region', value: region, short: true }], footer: 'RSVP CloudWatch' }] }),
    });
    if (!response.ok) throw new Error(`slack_webhook_${response.status}`);
  }
};

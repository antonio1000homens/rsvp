import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

test('deployment script uses the scoped artifact prefix and protects the stack', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'rsvp-deploy-test-'));
  const log = join(directory, 'commands.log');
  const lambdaOutput = new URL('../dist/lambda/', import.meta.url);
  await mkdir(lambdaOutput, { recursive: true });
  let previousLambda;
  try {
    previousLambda = await readFile(new URL('index.mjs', lambdaOutput));
  } catch {
    previousLambda = null;
  }
  await writeFile(new URL('index.mjs', lambdaOutput), 'export const handler = async () => ({ statusCode: 200 });\n');
  t.after(async () => {
    if (previousLambda) await writeFile(new URL('index.mjs', lambdaOutput), previousLambda);
  });

  const commands = {
    npm: '#!/usr/bin/env bash\necho "npm $*" >>"$MOCK_LOG"\nexit 0\n',
    zip: '#!/usr/bin/env bash\necho "zip $*" >>"$MOCK_LOG"\ntouch "$2"\n',
    curl: '#!/usr/bin/env bash\nprintf 403\n',
    aws: `#!/usr/bin/env bash
echo "aws $*" >>"$MOCK_LOG"
case "$*" in
  *"OutputKey=='CloudFormationServiceRoleArn'"*) printf 'arn:aws:iam::123456789012:role/RsvpCloudFormationServiceRole\n' ;;
  *"OutputKey=='SiteBucketName'"*) printf 'rsvp-123456789012-eu-west-2-site\n' ;;
  *"ParameterKey=='SiteBucketName'"*) printf 'rsvp-123456789012-eu-west-2-eu-west-2-site\n' ;;
  *"sts get-caller-identity"*) printf '123456789012\n' ;;
  *"OutputKey=='FunctionUrl'"*) printf 'https://example.lambda-url.eu-west-2.on.aws/\\n' ;;
esac
exit 0
`,
  };

  for (const [name, body] of Object.entries(commands)) {
    const path = join(directory, name);
    await writeFile(path, body);
    await chmod(path, 0o755);
  }

  const result = spawnSync('bash', ['scripts/deploy-aws.sh'], {
    cwd: new URL('../', import.meta.url),
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      MOCK_LOG: log,
      GITHUB_ACTIONS: 'true',
      GITHUB_SHA: '0123456789abcdef',
      AWS_CLOUDFORMATION_ROLE_ARN: 'arn:aws:iam::123456789012:role/RsvpCloudFormationServiceRole',
    },
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);
  const calls = await readFile(log, 'utf8');
  assert.match(calls, /s3 cp .*s3:\/\/aws2022-lambda-code\/rsvp\/0123456789abcdef\/lambda\.zip/);
  assert.match(calls, /cloudformation deploy .*--role-arn arn:aws:iam::123456789012:role\/RsvpCloudFormationServiceRole/);
  assert.match(calls, /s3 sync .*rsvp-123456789012-eu-west-2-site/);
  assert.match(calls, /update-termination-protection .*--enable-termination-protection/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}${calls}`, /origin-secret.*[a-f0-9]{64}/i);
});

import { Command } from 'commander';
import { signRequest, FileKeyStore, type RequestLike } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { error, info } from '../utils/output.js';

export function createSignCommand(): Command {
  const cmd = new Command('sign');

  cmd
    .description('Sign an HTTP request')
    .argument('<url>', 'URL to sign')
    .option('--method <method>', 'HTTP method', 'GET')
    .option('--body <body>', 'Request body')
    .option('--header <key:value>', 'Add header (can be used multiple times)', collectHeaders, {} as Record<string, string>)
    .action(async (url, options) => {
      try {
        await signHttpRequest(url, options);
      } catch (err) {
        error(`Failed to sign request: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

function collectHeaders(value: string, previous: Record<string, string>): Record<string, string> {
  const [key, ...valueParts] = value.split(':');
  if (!key || valueParts.length === 0) {
    throw new Error(`Invalid header format: ${value}. Use key:value`);
  }
  previous[key.trim()] = valueParts.join(':').trim();
  return previous;
}

async function signHttpRequest(
  url: string,
  options: { method: string; body?: string; header: Record<string, string> }
): Promise<void> {
  const config = loadConfig();

  if (!config.activeDid) {
    error('No active identity. Run "fides init" first.');
    process.exit(1);
  }

  // Load keys
  const keyStore = new FileKeyStore();
  const keyPair = await keyStore.load(config.activeDid);

  if (!keyPair) {
    error(`Keys not found for DID: ${config.activeDid}`);
    process.exit(1);
  }

  // Create request object
  const request: RequestLike = {
    method: options.method.toUpperCase(),
    url,
    headers: { ...options.header },
  };

  if (options.body) {
    request.body = options.body;
  }

  // Sign request
  const signedRequest = await signRequest(request, keyPair.privateKey);

  // Print curl command
  console.log('');
  info('Signed request:');
  console.log('');

  let curlCmd = `curl -X ${signedRequest.method} ${signedRequest.url}`;

  for (const [key, value] of Object.entries(signedRequest.headers)) {
    curlCmd += ` \\\n  -H '${key}: ${value}'`;
  }

  if (signedRequest.body) {
    const bodyStr = typeof signedRequest.body === 'string'
      ? signedRequest.body
      : Buffer.from(signedRequest.body).toString('utf-8');
    curlCmd += ` \\\n  -d '${bodyStr}'`;
  }

  console.log(curlCmd);
  console.log('');
}

import { Command } from 'commander';
import { verifyRequest, DiscoveryClient, type RequestLike } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { success, error, info } from '../utils/output.js';

export function createVerifyCommand(): Command {
  const cmd = new Command('verify');

  cmd
    .description('Verify a signed HTTP request')
    .argument('<url>', 'URL to verify')
    .requiredOption('--signature <sig>', 'Signature header value')
    .requiredOption('--signature-input <input>', 'Signature-Input header value')
    .option('--method <method>', 'HTTP method', 'GET')
    .action(async (url, options) => {
      try {
        await verifyHttpRequest(url, options);
      } catch (err) {
        error(`Failed to verify request: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

async function verifyHttpRequest(
  url: string,
  options: { signature: string; signatureInput: string; method: string }
): Promise<void> {
  const config = loadConfig();

  // Extract keyId from signature-input
  const keyIdMatch = options.signatureInput.match(/keyid="([^"]+)"/);
  if (!keyIdMatch) {
    error('Could not extract keyid from Signature-Input header');
    process.exit(1);
  }
  const keyId = keyIdMatch[1];

  // Resolve public key
  const discoveryClient = new DiscoveryClient({ baseUrl: config.discoveryUrl });
  const identity = await discoveryClient.resolve(keyId);

  if (!identity) {
    error(`Could not resolve identity for keyid: ${keyId}`);
    process.exit(1);
  }

  const publicKey = Buffer.from(identity.publicKey, 'hex');

  // Reconstruct request
  const request: RequestLike = {
    method: options.method.toUpperCase(),
    url,
    headers: {
      'Signature': options.signature,
      'Signature-Input': options.signatureInput,
    },
  };

  // Verify
  const result = await verifyRequest(request, publicKey);

  console.log('');
  if (result.valid) {
    success('Signature is VALID');
    console.log('');
    info(`Key ID: ${result.keyId || keyId}`);
    info(`Algorithm: ${identity.algorithm}`);
  } else {
    error('Signature is INVALID');
    if (result.error) {
      console.log('');
      info(`Error: ${result.error}`);
    }
    process.exit(1);
  }
  console.log('');
}

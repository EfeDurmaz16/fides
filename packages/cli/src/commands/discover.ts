import { Command } from 'commander';
import { DiscoveryClient, TrustClient } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { error, info, formatScore } from '../utils/output.js';

export function createDiscoverCommand(): Command {
  const cmd = new Command('discover');

  cmd
    .description('Discover and resolve an agent identity')
    .argument('<agent-did-or-domain>', 'DID or domain to discover')
    .action(async (input) => {
      try {
        await discoverAgent(input);
      } catch (err) {
        error(`Failed to discover agent: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

async function discoverAgent(input: string): Promise<void> {
  const config = loadConfig();
  const discoveryClient = new DiscoveryClient({ baseUrl: config.discoveryUrl });

  // Resolve identity
  const identity = await discoveryClient.resolve(input);

  if (!identity) {
    error(`Could not resolve: ${input}`);
    process.exit(1);
  }

  console.log('');
  info(`DID: ${identity.did}`);

  const pubKeyHex = identity.publicKey;
  const displayKey = pubKeyHex.length > 32
    ? pubKeyHex.substring(0, 32) + '...'
    : pubKeyHex;
  info(`Public Key: ${displayKey}`);

  info(`Algorithm: ${identity.algorithm}`);

  if (identity.metadata) {
    info(`Metadata: ${JSON.stringify(identity.metadata)}`);
  }

  info(`Created At: ${identity.createdAt}`);

  if (identity.endpoints) {
    const endpoints = [];
    if (identity.endpoints.discovery) endpoints.push(`discovery: ${identity.endpoints.discovery}`);
    if (identity.endpoints.trust) endpoints.push(`trust: ${identity.endpoints.trust}`);
    if (endpoints.length > 0) {
      info(`Endpoints: ${endpoints.join(', ')}`);
    }
  }

  // Try to get trust score
  try {
    const trustClient = new TrustClient({ baseUrl: config.trustUrl });
    const score = await trustClient.getScore(identity.did);
    console.log('');
    info(`Trust Score: ${formatScore(score.score)}`);
    info(`Direct Trusters: ${score.directTrusters}`);
    info(`Transitive Trusters: ${score.transitiveTrusters}`);
    info(`Last Computed: ${score.lastComputed}`);
  } catch (err) {
    // Trust service might be offline, that's ok
  }

  console.log('');
}

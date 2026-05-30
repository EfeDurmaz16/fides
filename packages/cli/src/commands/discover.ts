import { Command } from 'commander';
import { DiscoveryClient, TrustClient } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { error, info, formatScore } from '../utils/output.js';
import { parseList, postJson, printResult } from './authority-utils.js';

const DISCOVERY_PROVIDERS = ['local', 'well-known', 'registry', 'relay', 'dht', 'federation'] as const
type DiscoveryProviderName = typeof DISCOVERY_PROVIDERS[number]

export function createDiscoverCommand(): Command {
  const cmd = new Command('discover');

  cmd
    .description('Discover agent identities or capability candidates')
    .argument('[agent-did-or-domain-or-intent]', 'DID/domain to resolve, or an intent when --capability is provided')
    .option('--capability <capability>', 'Capability to discover, e.g. invoice.reconcile')
    .option('--provider <provider>', 'Discovery provider: local, well-known, registry, relay, dht, federation, all', 'local')
    .option('--all-providers', 'Query all local agentd discovery providers')
    .option('--constraints <json>', 'Discovery constraints as a JSON object')
    .option('--supported-versions <versions>', 'Comma-separated FIDES protocol versions supported by the requester')
    .option('--required-versions <versions>', 'Comma-separated FIDES protocol versions required by the requester')
    .option('--agentd-url <url>', 'agentd base URL', process.env.FIDES_AGENTD_URL ?? 'http://localhost:7345')
    .option('--json', 'Print JSON only')
    .action(async (input, options) => {
      try {
        if (options.capability) {
          await discoverCapability(input, options);
          return;
        }
        if (!input) {
          throw new Error('agent DID/domain is required unless --capability is provided');
        }
        await discoverAgent(input);
      } catch (err) {
        error(`Failed to discover agent: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

async function discoverCapability(
  intent: string | undefined,
  options: {
    capability: string
    provider?: string
    allProviders?: boolean
    constraints?: string
    supportedVersions?: string
    requiredVersions?: string
    agentdUrl: string
    json?: boolean
  }
): Promise<void> {
  const providers = options.allProviders || options.provider === 'all'
    ? DISCOVERY_PROVIDERS
    : [normalizeProvider(options.provider ?? 'local')]
  const constraints = options.constraints ? parseObject(options.constraints, '--constraints') : undefined
  const query = {
    ...(intent ? { intent } : {}),
    capability: options.capability,
    ...(constraints ? { constraints } : {}),
    ...(options.supportedVersions ? { supported_versions: parseList(options.supportedVersions) } : {}),
    ...(options.requiredVersions ? { required_versions: parseList(options.requiredVersions) } : {}),
  }
  const results = await Promise.all(providers.map(async (provider) => {
    const path = provider === 'local' ? '/discover/local' : `/discover/${provider}`
    return {
      provider,
      result: await postJson(`${baseUrl(options.agentdUrl)}${path}`, query),
    }
  }))

  printResult('Discovery candidates:', {
    query,
    authorityGranted: false,
    results,
  }, options)
}

function normalizeProvider(provider: string): DiscoveryProviderName {
  if ((DISCOVERY_PROVIDERS as readonly string[]).includes(provider)) {
    return provider as DiscoveryProviderName
  }
  throw new Error(`unsupported discovery provider: ${provider}`)
}

function parseObject(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`)
  }
  return parsed as Record<string, unknown>
}

function baseUrl(url: string): string {
  return url.replace(/\/+$/, '')
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

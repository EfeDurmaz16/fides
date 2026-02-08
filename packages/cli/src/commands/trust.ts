import { Command } from 'commander';
import { createAttestation, TrustClient, FileKeyStore, TrustLevel } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { success, error, info } from '../utils/output.js';

export function createTrustCommand(): Command {
  const cmd = new Command('trust');

  cmd
    .description('Create a trust attestation for another agent')
    .argument('<agent-did>', 'DID of the agent to trust')
    .option('--level <level>', 'Trust level: none, low, medium, high, absolute, or 0-100', 'medium')
    .action(async (agentDid, options) => {
      try {
        await createTrust(agentDid, options);
      } catch (err) {
        error(`Failed to create trust attestation: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

function parseTrustLevel(level: string): number {
  const levelLower = level.toLowerCase();

  switch (levelLower) {
    case 'none':
      return TrustLevel.NONE;
    case 'low':
      return TrustLevel.LOW;
    case 'medium':
      return TrustLevel.MEDIUM;
    case 'high':
      return TrustLevel.HIGH;
    case 'absolute':
      return TrustLevel.ABSOLUTE;
    default:
      const numLevel = parseInt(level, 10);
      if (isNaN(numLevel) || numLevel < 0 || numLevel > 100) {
        throw new Error(`Invalid trust level: ${level}. Use none, low, medium, high, absolute, or 0-100`);
      }
      return numLevel;
  }
}

async function createTrust(agentDid: string, options: { level: string }): Promise<void> {
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

  // Parse trust level
  const trustLevel = parseTrustLevel(options.level);

  // Create attestation
  const attestation = await createAttestation(
    config.activeDid,
    agentDid,
    trustLevel,
    keyPair.privateKey
  );

  // Submit to trust service
  const trustClient = new TrustClient({ baseUrl: config.trustUrl });
  await trustClient.attest(
    config.activeDid,
    agentDid,
    trustLevel,
    attestation.signature
  );

  console.log('');
  success('Trust attestation created!');
  console.log('');
  info(`Attestation ID: ${attestation.id}`);
  info(`Issuer: ${config.activeDid}`);
  info(`Subject: ${agentDid}`);
  info(`Trust Level: ${trustLevel}`);
  info(`Signature: ${attestation.signature.substring(0, 32)}...`);
  console.log('');
}

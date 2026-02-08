import { Command } from 'commander';
import { FileKeyStore, TrustClient } from '@fides/sdk';
import { loadConfig } from '../utils/config.js';
import { error, formatTable, formatScore } from '../utils/output.js';

export function createStatusCommand(): Command {
  const cmd = new Command('status');

  cmd
    .description('Show current FIDES configuration and status')
    .action(async () => {
      try {
        await showStatus();
      } catch (err) {
        error(`Failed to get status: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

async function showStatus(): Promise<void> {
  const config = loadConfig();

  const rows: string[][] = [
    ['Discovery URL:', config.discoveryUrl],
    ['Trust URL:', config.trustUrl],
    ['Key Directory:', config.keyDir],
  ];

  if (config.activeDid) {
    rows.push(['Active DID:', config.activeDid]);

    // Try to load public key
    try {
      const keyStore = new FileKeyStore();
      const keyPair = await keyStore.load(config.activeDid);
      if (keyPair) {
        const pubKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
        const displayKey = pubKeyHex.length > 32
          ? pubKeyHex.substring(0, 32) + '...'
          : pubKeyHex;
        rows.push(['Public Key:', displayKey]);
      }
    } catch (err) {
      // Key loading failed, skip
    }

    // Try to get trust score
    try {
      const trustClient = new TrustClient({ baseUrl: config.trustUrl });
      const score = await trustClient.getScore(config.activeDid);
      rows.push(['Trust Score:', formatScore(score.score)]);
      rows.push(['Direct Trusters:', score.directTrusters.toString()]);
      rows.push(['Transitive Trusters:', score.transitiveTrusters.toString()]);
    } catch (err) {
      // Trust service might be offline
      rows.push(['Trust Score:', '(service unavailable)']);
    }
  } else {
    rows.push(['Active DID:', '(not initialized)']);
  }

  console.log('');
  formatTable(rows);
  console.log('');
}

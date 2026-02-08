import { Command } from 'commander';
import ora from 'ora';
import { generateKeyPair, generateDID, FileKeyStore, DiscoveryClient } from '@fides/sdk';
import { loadConfig, saveConfig } from '../utils/config.js';
import { success, error, info } from '../utils/output.js';

export function createInitCommand(): Command {
  const cmd = new Command('init');

  cmd
    .description('Initialize a new FIDES identity')
    .option('--name <name>', 'Agent name for metadata')
    .option('--passphrase <passphrase>', 'Passphrase to encrypt keys')
    .action(async (options) => {
      try {
        await initIdentity(options);
      } catch (err) {
        error(`Failed to initialize identity: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      }
    });

  return cmd;
}

async function initIdentity(options: { name?: string; passphrase?: string }): Promise<void> {
  const config = loadConfig();

  // Generate keypair
  const spinner = ora('Generating Ed25519 keypair...').start();
  const keyPair = await generateKeyPair();
  spinner.succeed('Keypair generated');

  // Generate DID
  spinner.start('Creating DID...');
  const did = generateDID(keyPair.publicKey);
  spinner.succeed(`DID created: ${did}`);

  // Store keys
  spinner.start('Storing keys...');
  const keyStore = new FileKeyStore({
    passphrase: options.passphrase,
    encrypt: !!options.passphrase,
  });
  await keyStore.save(did, keyPair);
  spinner.succeed(`Keys stored in ${config.keyDir}`);

  // Register with discovery service
  spinner.start('Registering with discovery service...');
  try {
    const discoveryClient = new DiscoveryClient({ baseUrl: config.discoveryUrl });
    const metadata = options.name ? { name: options.name } : undefined;
    await discoveryClient.register({
      did,
      publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
      metadata,
    });
    spinner.succeed('Registered with discovery service');
  } catch (err) {
    spinner.warn('Failed to register with discovery service (service may be offline)');
    info(`You can register later when the service is available`);
  }

  // Save config
  config.activeDid = did;
  saveConfig(config);

  // Print summary
  console.log('');
  success('Identity initialized successfully!');
  console.log('');
  info(`DID: ${did}`);
  info(`Public Key: ${Buffer.from(keyPair.publicKey).toString('hex')}`);
  info(`Key Location: ${config.keyDir}`);
}

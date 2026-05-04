import { Command } from 'commander'

export function createRuntimeCommand(): Command {
  const cmd = new Command('runtime')
    .description('Runtime attestation')

  cmd.command('attest')
    .description('Create a runtime attestation')
    .option('--provider <name>', 'TEE provider', 'mock-tee')
    .action((options) => {
      console.log(`Creating runtime attestation with provider: ${options.provider}`)
    })

  return cmd
}

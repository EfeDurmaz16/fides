import { Command } from 'commander'
import { resolveTxt } from 'node:dns/promises'
import { createDomainVerificationChallenge, verifyDomainDid } from '@fides/core'
import { error, info, success } from '../utils/output.js'

export function createIdentityCommand(): Command {
  const cmd = new Command('identity')
    .description('Identity verification utilities')

  const domain = cmd.command('domain')
    .description('Verify domain ownership for FIDES DIDs')

  domain.command('challenge')
    .description('Print the DNS TXT record required to bind a domain to a FIDES DID')
    .argument('<domain>', 'Domain to verify')
    .argument('<did>', 'FIDES DID to bind to the domain')
    .option('--json', 'Emit JSON output')
    .action((domainName, did, options) => {
      try {
        const challenge = createDomainVerificationChallenge(domainName, did)
        if (options.json) {
          console.log(JSON.stringify(challenge, null, 2))
          return
        }

        success('Domain verification challenge created')
        info(`Domain: ${challenge.domain}`)
        info(`Record Name: ${challenge.recordName}`)
        info(`Record Type: TXT`)
        info(`Record Value: ${challenge.recordValue}`)
      } catch (err) {
        error(`Failed to create domain verification challenge: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  domain.command('verify')
    .description('Resolve DNS TXT records and verify a domain-to-DID binding')
    .argument('<domain>', 'Domain to verify')
    .argument('<did>', 'Expected FIDES DID')
    .option('--json', 'Emit JSON output')
    .action(async (domainName, did, options) => {
      try {
        const result = await verifyDomainDid({
          domain: domainName,
          did,
          resolver: resolveTxt,
        })

        if (options.json) {
          console.log(JSON.stringify(result, null, 2))
        } else if (result.verified) {
          success(`Domain verified: ${result.domain}`)
          info(`DID: ${result.did}`)
          info(`Record Name: ${result.recordName}`)
        } else {
          error(`Domain verification failed: ${result.reason || 'unknown'}`)
          info(`Domain: ${result.domain}`)
          info(`DID: ${result.did}`)
          info(`Record Name: ${result.recordName}`)
        }

        if (!result.verified) {
          process.exitCode = 1
        }
      } catch (err) {
        error(`Failed to verify domain: ${err instanceof Error ? err.message : String(err)}`)
        process.exit(1)
      }
    })

  return cmd
}

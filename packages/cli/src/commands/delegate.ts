import { Command } from 'commander'
import { createDelegationToken } from '@fides/core'
import { parseJsonObject, parseList, printResult } from './authority-utils.js'

export function createDelegateCommand(): Command {
  const cmd = new Command('delegate')
    .description('Create DelegationToken authority grants')

  cmd.command('create')
    .description('Create an unsigned or externally signed DelegationToken')
    .requiredOption('--delegator <did>', 'Delegating principal DID')
    .requiredOption('--delegatee <did>', 'Delegate agent DID')
    .requiredOption('--capabilities <ids>', 'Comma-separated capability IDs')
    .option('--audience <values>', 'Comma-separated token audiences', 'agentd')
    .option('--expires-at <iso>', 'Absolute expiration timestamp')
    .option('--ttl-ms <ms>', 'Relative expiration in milliseconds', '3600000')
    .option('--max-actions <count>', 'Maximum actions allowed')
    .option('--max-spend <amount>', 'Maximum spend constraint')
    .option('--allowed-contexts <values>', 'Comma-separated allowed contexts')
    .option('--forbidden-contexts <values>', 'Comma-separated forbidden contexts')
    .option('--constraints-json <json>', 'Additional delegation constraints as JSON object')
    .option('--signature <hex>', 'Externally produced signature for the token')
    .option('--json', 'Print JSON only')
    .action(async (options) => {
      try {
        const expiresAt = options.expiresAt || new Date(Date.now() + Number(options.ttlMs)).toISOString()
        const constraints = {
          ...parseJsonObject(options.constraintsJson),
          ...(options.maxActions && { maxActions: Number(options.maxActions) }),
          ...(options.maxSpend && { maxSpend: options.maxSpend }),
          ...(options.allowedContexts && { allowedContexts: parseList(options.allowedContexts) }),
          ...(options.forbiddenContexts && { forbiddenContexts: parseList(options.forbiddenContexts) }),
        }

        const token = createDelegationToken({
          delegator: options.delegator,
          delegatee: options.delegatee,
          capabilities: parseList(options.capabilities),
          constraints,
          expiresAt,
          audience: parseList(options.audience),
        })

        printResult('DelegationToken:', {
          ...token,
          signature: options.signature ?? token.signature,
        }, options)
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}


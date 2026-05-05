import { Command } from 'commander'
import { evaluatePolicy, type PolicyBundle } from '@fides/policy'
import { readFileSync } from 'node:fs'

export function createPolicyCommand(): Command {
  const cmd = new Command('policy')
    .description('Policy evaluation')

  cmd.command('evaluate')
    .description('Evaluate a policy against context')
    .requiredOption('--bundle <path>', 'Policy bundle JSON file')
    .requiredOption('--context <json>', 'JSON context string or file path')
    .action((options) => {
      try {
        const bundle: PolicyBundle = JSON.parse(readFileSync(options.bundle, 'utf-8'))
        let context: Record<string, unknown>

        if (options.context.endsWith('.json')) {
          context = JSON.parse(readFileSync(options.context, 'utf-8'))
        } else {
          context = JSON.parse(options.context)
        }

        const result = evaluatePolicy(bundle, context)
        console.log(`Decision: ${result.decision}`)
        console.log(`Explanation: ${result.explanation.decision}`)
        console.log(`Matched rules: ${result.matchedRules.join(', ') || 'none'}`)
        console.log(`Factors:`)
        for (const f of result.explanation.factors) {
          console.log(`  - ${f.factor} (weight: ${f.weight}): ${f.description}`)
        }
      } catch (error) {
        console.error('Error:', error instanceof Error ? error.message : String(error))
        process.exit(1)
      }
    })

  return cmd
}

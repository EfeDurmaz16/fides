import { Command } from 'commander'

export function createPolicyCommand(): Command {
  const cmd = new Command('policy')
    .description('Policy evaluation')

  cmd.command('evaluate')
    .description('Evaluate a policy against context')
    .option('--bundle <path>', 'Policy bundle file')
    .option('--context <json>', 'JSON context')
    .action((options) => {
      console.log('Evaluating policy...')
      console.log('Bundle:', options.bundle)
      console.log('Context:', options.context)
    })

  return cmd
}

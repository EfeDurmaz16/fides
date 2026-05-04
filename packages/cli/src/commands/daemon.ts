import { Command } from 'commander'

export function createDaemonCommand(): Command {
  const cmd = new Command('daemon')
    .description('Local daemon control')

  cmd.command('start')
    .description('Start agentd')
    .option('--port <port>', 'Port to listen on', '7345')
    .action((options) => {
      console.log(`Starting agentd on port ${options.port}...`)
    })

  cmd.command('status')
    .description('Check agentd status')
    .action(() => {
      console.log('agentd status: not running (stub)')
    })

  cmd.command('stop')
    .description('Stop agentd')
    .action(() => {
      console.log('Stopping agentd...')
    })

  return cmd
}

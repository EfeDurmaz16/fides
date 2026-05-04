import { Command } from 'commander'

export function createKillswitchCommand(): Command {
  const cmd = new Command('killswitch')
    .description('Kill switch control')

  cmd.command('engage')
    .description('Engage kill switch')
    .option('--global', 'Engage globally')
    .option('--agent <did>', 'Engage for agent')
    .action((options) => {
      if (options.global) {
        console.log('Global kill switch ENGAGED')
      } else if (options.agent) {
        console.log(`Kill switch ENGAGED for agent ${options.agent}`)
      } else {
        console.log('Kill switch ENGAGED')
      }
    })

  cmd.command('disengage')
    .description('Disengage kill switch')
    .action(() => {
      console.log('Kill switch DISENGAGED')
    })

  return cmd
}

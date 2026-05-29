import { basename } from 'node:path'

export function inferCliName(argv: readonly string[] = process.argv, lifecycleEvent = process.env.npm_lifecycle_event): 'fides' | 'agentd' {
  if (lifecycleEvent === 'agentd') return 'agentd'
  const invoked = basename(argv[1] ?? '')
  return invoked === 'agentd' ? 'agentd' : 'fides'
}

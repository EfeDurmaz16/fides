import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'

function readPackageJson(path: URL): Record<string, any> {
  return JSON.parse(readFileSync(path, 'utf-8'))
}

describe('workspace agentd script contract', () => {
  it('keeps the root pnpm agentd script wired to the cli agentd entrypoint', () => {
    const rootPackage = readPackageJson(new URL('../../../package.json', import.meta.url))
    const cliPackage = readPackageJson(new URL('../package.json', import.meta.url))

    expect(rootPackage.scripts.agentd).toBe('pnpm --filter @fides/cli agentd')
    expect(rootPackage.scripts['agentd:dev']).toBe('pnpm --filter @fides/agentd dev')
    expect(cliPackage.scripts.agentd).toBe('node dist/index.js')
    expect(cliPackage.bin.agentd).toBe('./dist/index.js')
  })
})

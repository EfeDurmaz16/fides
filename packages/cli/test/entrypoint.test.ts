import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { describe, expect, it } from 'vitest'

describe('CLI entrypoint', () => {
  it('formats uncaught async command failures instead of leaking rejections', () => {
    const cliRoot = path.resolve(fileURLToPath(import.meta.url), '..', '..')
    const result = spawnSync(process.execPath, [
      '--import',
      'tsx',
      'src/index.ts',
      'agents',
      'inspect',
      'did:fides:missing',
      '--agentd-url',
      'http://127.0.0.1:9',
      '--json',
    ], {
      cwd: cliRoot,
      encoding: 'utf8',
      stdio: 'pipe',
      timeout: 5000,
    })

    expect(result.status).toBe(1)
    expect(result.stderr).toContain('Error: fetch failed')
    expect(result.stderr).not.toContain('UnhandledPromiseRejection')
  })
})

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createIdentityCommand } from '../src/commands/identity.js'

const ORIGINAL_FIDES_HOME = process.env.FIDES_HOME

let fidesHome: string

beforeEach(async () => {
  fidesHome = await mkdtemp(join(tmpdir(), 'fides-cli-identity-'))
  process.env.FIDES_HOME = fidesHome
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

afterEach(async () => {
  if (ORIGINAL_FIDES_HOME) {
    process.env.FIDES_HOME = ORIGINAL_FIDES_HOME
  } else {
    delete process.env.FIDES_HOME
  }
  vi.restoreAllMocks()
  await rm(fidesHome, { recursive: true, force: true })
})

describe('identity local commands', () => {
  it('creates, lists, and shows a local agent identity without printing the private key', async () => {
    const create = createIdentityCommand()
    await create.parseAsync(['create', '--type', 'agent', '--name', 'Calendar Agent', '--json'], { from: 'user' })

    const createOutput = JSON.parse(String(vi.mocked(console.log).mock.calls.at(-1)?.[0]))
    expect(createOutput.did).toMatch(/^did:fides:/)
    expect(createOutput.privateKeyHex).toBeUndefined()
    expect(createOutput.path).toContain('identities')

    const stored = JSON.parse(await readFile(createOutput.path, 'utf-8'))
    expect(stored.identity.metadata.name).toBe('Calendar Agent')
    expect(stored.privateKeyHex).toMatch(/^[a-f0-9]+$/)

    const list = createIdentityCommand()
    await list.parseAsync(['list', '--json'], { from: 'user' })
    const listOutput = JSON.parse(String(vi.mocked(console.log).mock.calls.at(-1)?.[0]))
    expect(listOutput.identities).toHaveLength(1)
    expect(listOutput.identities[0].did).toBe(createOutput.did)

    const show = createIdentityCommand()
    await show.parseAsync(['show', createOutput.did, '--json'], { from: 'user' })
    const showOutput = JSON.parse(String(vi.mocked(console.log).mock.calls.at(-1)?.[0]))
    expect(showOutput.identity.did).toBe(createOutput.did)
    expect(showOutput.privateKeyHex).toBeUndefined()
  })
})

import { join } from 'node:path'
import { homedir } from 'node:os'
import { FidesClient, type FidesClientOptions } from '@fides/sdk'

export interface DaemonConfig {
  daemonUrl: string
  configDir: string
  databasePath: string
  evidenceDir: string
  logsDir: string
}

export const DEFAULT_DAEMON_PORT = 7345

export function defaultDaemonConfig(homeDirectory = homedir()): DaemonConfig {
  const configDir = join(homeDirectory, '.fides')
  return {
    daemonUrl: `http://localhost:${DEFAULT_DAEMON_PORT}`,
    configDir,
    databasePath: join(configDir, 'fides.sqlite'),
    evidenceDir: join(configDir, 'evidence'),
    logsDir: join(configDir, 'logs'),
  }
}

export function createDaemonClient(options: Partial<FidesClientOptions> = {}): FidesClient {
  const defaults = defaultDaemonConfig()
  return new FidesClient({
    daemonUrl: options.daemonUrl ?? defaults.daemonUrl,
    apiKey: options.apiKey,
  })
}

export function wellKnownDaemonEndpoints(baseUrl = defaultDaemonConfig().daemonUrl): string[] {
  const normalized = baseUrl.replace(/\/$/, '')
  return [
    `${normalized}/.well-known/fides.json`,
    `${normalized}/.well-known/agents.json`,
  ]
}

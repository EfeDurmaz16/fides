import { readFileSync } from 'node:fs'
import { isErrorEnvelope, type ErrorEnvelope } from '@fides/core'
import * as ed from '@noble/ed25519'
import { bytesToHex } from '@noble/hashes/utils'

export interface JsonOptions {
  json?: boolean
}

export function printResult(label: string, value: unknown, options: JsonOptions = {}): void {
  if (options.json) {
    console.log(JSON.stringify(value, null, 2))
    return
  }
  console.log(label)
  console.log(JSON.stringify(value, null, 2))
}

export function parseList(value?: string): string[] {
  if (!value) return []
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

export function parseJsonObject(value?: string): Record<string, unknown> {
  if (!value) return {}
  const parsed = JSON.parse(value)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('JSON value must be an object')
  }
  return parsed as Record<string, unknown>
}

export function parseTokenInput(options: { tokenFile?: string; tokenJson?: string }): unknown {
  if (options.tokenFile) {
    return JSON.parse(readFileSync(options.tokenFile, 'utf-8'))
  }
  if (options.tokenJson) {
    return JSON.parse(options.tokenJson)
  }
  throw new Error('Either --token-file or --token-json is required')
}

export async function derivePublicKeyHex(privateKeyHex: string): Promise<string> {
  const privateKey = Uint8Array.from(Buffer.from(privateKeyHex, 'hex'))
  const publicKey = await ed.getPublicKeyAsync(privateKey)
  return bytesToHex(publicKey)
}

export class AgentdHttpError extends Error {
  constructor(
    readonly status: number,
    readonly payload: unknown,
    readonly error?: ErrorEnvelope
  ) {
    super(error ? `[${error.code}] ${error.message}` : `HTTP ${status}: ${JSON.stringify(payload)}`)
    this.name = 'AgentdHttpError'
  }
}

function extractErrorEnvelope(payload: unknown): ErrorEnvelope | undefined {
  if (isErrorEnvelope(payload)) return payload
  if (!payload || typeof payload !== 'object') return undefined
  const error = (payload as { error?: unknown }).error
  return isErrorEnvelope(error) ? error : undefined
}

async function parseJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text()
  return text ? JSON.parse(text) : {}
}

async function requestJson(url: string, init: RequestInit): Promise<unknown> {
  const response = await fetch(url, init)
  const payload = await parseJsonResponse(response)
  if (!response.ok) {
    throw new AgentdHttpError(response.status, payload, extractErrorEnvelope(payload))
  }
  return payload
}

export async function postJson(url: string, body: unknown): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const apiKey = process.env.FIDES_API_KEY || process.env.SERVICE_API_KEY
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  return requestJson(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
}

export async function getJson(url: string): Promise<unknown> {
  const headers: Record<string, string> = {}
  const apiKey = process.env.FIDES_API_KEY || process.env.SERVICE_API_KEY
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  return requestJson(url, { method: 'GET', headers })
}

export async function deleteJson(url: string): Promise<unknown> {
  const headers: Record<string, string> = {}
  const apiKey = process.env.FIDES_API_KEY || process.env.SERVICE_API_KEY
  if (apiKey) {
    headers['X-API-Key'] = apiKey
  }

  return requestJson(url, { method: 'DELETE', headers })
}

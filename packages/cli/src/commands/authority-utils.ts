import { readFileSync } from 'node:fs'

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

export async function postJson(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${JSON.stringify(payload)}`)
  }
  return payload
}


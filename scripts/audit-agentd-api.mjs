import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const agentdSourcePath = join(root, 'services/agentd/src/index.ts')
const agentdOpenApiPath = join(root, 'docs/api/agentd.yaml')

const source = readFileSync(agentdSourcePath, 'utf8')
const openApi = readFileSync(agentdOpenApiPath, 'utf8')

const routeAliases = new Map([
  ['GET /.well-known/agents/*', ['GET /.well-known/agents/{param}.json']],
])

const documentedRoutes = parseOpenApiRoutes(openApi)
const implementedRoutes = parseImplementedRoutes(source)

const documented = new Set(documentedRoutes.map(normalizeRoute))
const implemented = new Set(expandAliases(implementedRoutes).map(normalizeRoute))

const missingFromDocs = [...implemented].filter(route => !documented.has(route)).sort()
const missingFromImplementation = [...documented].filter(route => !implemented.has(route)).sort()

const routeOrderErrors = checkRouteOrdering(source)
const errors = [
  ...missingFromDocs.map(route => `implemented route is missing from docs/api/agentd.yaml: ${route}`),
  ...missingFromImplementation.map(route => `documented route is missing from services/agentd/src/index.ts: ${route}`),
  ...routeOrderErrors,
]

if (errors.length > 0) {
  console.error('agentd API audit failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`agentd API audit passed for ${implemented.size} documented routes.`)

function parseOpenApiRoutes(contents) {
  const routes = []
  let currentPath = null
  for (const line of contents.split('\n')) {
    const pathMatch = line.match(/^  (\/[^:]+):$/)
    if (pathMatch) {
      currentPath = pathMatch[1]
      continue
    }

    const methodMatch = line.match(/^    (get|post|put|delete|patch):$/)
    if (methodMatch && currentPath) {
      routes.push(`${methodMatch[1].toUpperCase()} ${currentPath}`)
    }
  }
  return routes
}

function parseImplementedRoutes(contents) {
  const routes = []
  const routePattern = /^app\.(get|post|put|delete|patch)\('([^']+)'/gm
  for (const match of contents.matchAll(routePattern)) {
    const method = match[1].toUpperCase()
    const path = match[2]
    if (path === '*') continue
    routes.push(`${method} ${path}`)
  }
  return routes
}

function expandAliases(routes) {
  const expanded = []
  for (const route of routes) {
    const aliases = routeAliases.get(route)
    if (aliases) {
      expanded.push(...aliases)
    } else {
      expanded.push(route)
    }
  }
  return expanded
}

function normalizeRoute(route) {
  const [method, rawPath] = route.split(' ')
  const path = rawPath
    .replace(/:[^/]+/g, '{param}')
    .replace(/\{[^/}]+\}/g, '{param}')
  return `${method} ${path}`
}

function checkRouteOrdering(contents) {
  const errors = []
  const domainVerifyIndex = contents.indexOf("app.get('/v1/identities/domain/verify'")
  const didIdentityIndex = contents.indexOf("app.get('/v1/identities/:did'")

  if (domainVerifyIndex === -1) {
    errors.push('implemented route missing static domain verification route: GET /v1/identities/domain/verify')
  }
  if (didIdentityIndex === -1) {
    errors.push('implemented route missing parameterized identity route: GET /v1/identities/{param}')
  }
  if (domainVerifyIndex !== -1 && didIdentityIndex !== -1 && domainVerifyIndex > didIdentityIndex) {
    errors.push('GET /v1/identities/domain/verify must be registered before GET /v1/identities/{param}')
  }

  return errors
}

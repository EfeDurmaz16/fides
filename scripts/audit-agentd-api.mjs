import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const agentdSourcePath = join(root, 'services/agentd/src/index.ts')
const agentdOpenApiPath = join(root, 'docs/api/agentd.yaml')
const statusDocPath = join(root, 'docs/status/fides-v2-implementation-status.md')
const apiReferencePath = join(root, 'docs/api-reference.md')

const source = readFileSync(agentdSourcePath, 'utf8')
const openApi = readFileSync(agentdOpenApiPath, 'utf8')
const statusDoc = readFileSync(statusDocPath, 'utf8')
const apiReference = readFileSync(apiReferencePath, 'utf8')

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
const markdownErrors = [
  ...checkStatusRootApiOverview(documented, statusDoc),
  ...checkMarkdownRoutesExist(documented, apiReference, 'docs/api-reference.md'),
]
const errors = [
  ...missingFromDocs.map(route => `implemented route is missing from docs/api/agentd.yaml: ${route}`),
  ...missingFromImplementation.map(route => `documented route is missing from services/agentd/src/index.ts: ${route}`),
  ...routeOrderErrors,
  ...markdownErrors,
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
    .replace(/:([A-Za-z0-9_]+)/g, '{param}')
    .replace(/\{[^/}]+\}/g, '{param}')
  return `${method} ${path}`
}

function checkStatusRootApiOverview(openApiRoutes, contents) {
  const section = extractSection(contents, 'Primary root v2 API:', 'See `docs/api/agentd.yaml`')
  const markdownRoutes = new Set(parseMarkdownRoutes(section).map(normalizeRoute))
  const expectedRoutes = [...openApiRoutes]
    .filter(route => {
      const path = route.split(' ')[1]
      return !path.startsWith('/v1/') && path !== '/metrics'
    })
    .sort()

  const missing = expectedRoutes.filter(route => !markdownRoutes.has(route))
  const extra = [...markdownRoutes].filter(route => !expectedRoutes.includes(route)).sort()

  return [
    ...missing.map(route => `docs/status/fides-v2-implementation-status.md Primary root v2 API is missing ${route}`),
    ...extra.map(route => `docs/status/fides-v2-implementation-status.md Primary root v2 API lists non-root or undocumented route ${route}`),
  ]
}

function checkMarkdownRoutesExist(openApiRoutes, contents, label) {
  const markdownRoutes = parseMarkdownRoutes(contents).map(normalizeRoute)
  return markdownRoutes
    .filter(route => !openApiRoutes.has(route))
    .sort()
    .map(route => `${label} lists route missing from docs/api/agentd.yaml: ${route}`)
}

function parseMarkdownRoutes(contents) {
  const routes = []
  const routePattern = /^- `((GET|POST|PUT|DELETE|PATCH) [^`]+)`$/gm
  for (const match of contents.matchAll(routePattern)) {
    routes.push(match[1])
  }
  return routes
}

function extractSection(contents, startMarker, endMarker) {
  const start = contents.indexOf(startMarker)
  if (start === -1) return ''
  const end = contents.indexOf(endMarker, start)
  if (end === -1) return contents.slice(start)
  return contents.slice(start, end)
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

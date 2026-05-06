import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const packagePaths = [
  'packages/cli/package.json',
  'packages/core/package.json',
  'packages/discovery/package.json',
  'packages/evidence/package.json',
  'packages/policy/package.json',
  'packages/runtime/package.json',
  'packages/sdk/package.json',
  'packages/shared/package.json',
]

const requiredFileEntries = new Set(['README.md', 'LICENSE'])
const errors = []

for (const packagePath of packagePaths) {
  const absolutePath = join(root, packagePath)
  const pkg = JSON.parse(readFileSync(absolutePath, 'utf8'))
  const packageDir = dirname(absolutePath)
  const label = `${pkg.name} (${packagePath})`

  if (pkg.private) {
    continue
  }

  if (pkg.license !== 'MIT') {
    errors.push(`${label} must declare MIT license`)
  }

  if (!pkg.repository?.url || !pkg.repository?.directory) {
    errors.push(`${label} must declare repository.url and repository.directory`)
  }

  if (!pkg.homepage) {
    errors.push(`${label} must declare homepage`)
  }

  if (!pkg.engines?.node?.startsWith('>=22')) {
    errors.push(`${label} must require Node.js >=22`)
  }

  for (const entry of requiredFileEntries) {
    if (!pkg.files?.includes(entry)) {
      errors.push(`${label} files must include ${entry}`)
      continue
    }

    if (!existsSync(join(packageDir, entry))) {
      errors.push(`${label} references missing ${relative(root, join(packageDir, entry))}`)
    }
  }
}

if (errors.length > 0) {
  console.error('Package hygiene check failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`Package hygiene check passed for ${packagePaths.length} publishable package manifests.`)

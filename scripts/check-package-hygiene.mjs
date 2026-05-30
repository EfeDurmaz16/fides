import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { publicPackageDirs, publicPackageJsonPaths } from './public-packages.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))

const requiredFileEntries = new Set(['README.md', 'LICENSE'])
const errors = []
const configuredPublicPackageDirs = new Set(publicPackageDirs)
const discoveredPublicPackageDirs = readdirSync(join(root, 'packages'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => `packages/${entry.name}`)
  .filter((packageDir) => existsSync(join(root, packageDir, 'package.json')))
  .filter((packageDir) => {
    const pkg = JSON.parse(readFileSync(join(root, packageDir, 'package.json'), 'utf8'))
    return pkg.private !== true
  })

for (const packageDir of discoveredPublicPackageDirs) {
  if (!configuredPublicPackageDirs.has(packageDir)) {
    errors.push(`${packageDir}/package.json is publishable but missing from scripts/public-packages.mjs`)
  }
}

for (const packagePath of publicPackageJsonPaths) {
  const absolutePath = join(root, packagePath)
  const pkg = JSON.parse(readFileSync(absolutePath, 'utf8'))
  const packageDir = dirname(absolutePath)
  const label = `${pkg.name} (${packagePath})`

  if (pkg.private) {
    errors.push(`${label} is listed as publishable but marked private`)
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

console.log(`Package hygiene check passed for ${publicPackageJsonPaths.length} publishable package manifests.`)

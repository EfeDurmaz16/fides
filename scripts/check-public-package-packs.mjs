import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { publicPackageDirs } from './public-packages.mjs'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const requiredPackFiles = new Set(['README.md', 'LICENSE'])
const errors = []

for (const packageDir of publicPackageDirs) {
  const packageRoot = join(root, packageDir)
  const pkg = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'))
  const label = `${pkg.name} (${packageDir})`

  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: packageRoot,
    encoding: 'utf8',
  })

  if (result.status !== 0) {
    errors.push(`${label} failed npm pack --dry-run: ${result.stderr || result.stdout}`)
    continue
  }

  let pack
  try {
    pack = JSON.parse(result.stdout)[0]
  } catch (error) {
    errors.push(`${label} returned invalid npm pack JSON: ${error}`)
    continue
  }

  const packedFiles = new Set(pack.files.map((file) => file.path))
  for (const requiredFile of requiredPackFiles) {
    if (!packedFiles.has(requiredFile)) {
      errors.push(`${label} pack output is missing ${requiredFile}`)
    }
  }
}

if (errors.length > 0) {
  console.error('Public package pack check failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`Public package pack check passed for ${publicPackageDirs.length} packages.`)

export const publicPackageDirs = [
  'packages/shared',
  'packages/core',
  'packages/policy',
  'packages/runtime',
  'packages/discovery',
  'packages/evidence',
  'packages/sdk',
  'packages/cli',
]

export const publicPackageJsonPaths = publicPackageDirs.map((packageDir) => `${packageDir}/package.json`)

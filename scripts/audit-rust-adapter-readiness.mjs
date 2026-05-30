import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const rustAdapterDir = resolve(root, 'packages/rust-sdk')
const rustReadmePath = resolve(rustAdapterDir, 'README.md')
const adapterSourcePath = resolve(root, 'packages/adapters/src/index.ts')
const errors = []

const forbiddenRuntimeManifests = [
  'Cargo.toml',
  'Cargo.lock',
  'package.json',
]

for (const manifest of forbiddenRuntimeManifests) {
  if (existsSync(resolve(rustAdapterDir, manifest))) {
    errors.push(`packages/rust-sdk/${manifest} must not exist until Rust becomes an explicit optional adapter package`)
  }
}

if (!existsSync(rustReadmePath)) {
  errors.push('packages/rust-sdk/README.md is required to document the Rust adapter boundary')
}

const readme = existsSync(rustReadmePath) ? readFileSync(rustReadmePath, 'utf8') : ''
const adapterSource = readFileSync(adapterSourcePath, 'utf8')
const requiredReadmePhrases = [
  'FIDES v2 is TS-first',
  'Rust is adapter-ready, not required',
  'No Rust crate is required or published yet',
  'Rust must not become a runtime dependency for the TypeScript SDK, CLI, daemon,',
  '@fides/adapters',
  'RustPrimitiveAdapter',
]

for (const phrase of requiredReadmePhrases) {
  if (!readme.includes(phrase)) {
    errors.push(`packages/rust-sdk/README.md must include "${phrase}"`)
  }
}

const adapterSurfaces = extractStringArray(adapterSource, 'RUST_PRIMITIVE_SURFACES')
const readmeSurfaces = [
  'canonical JSON serialization',
  'hashing',
  'canonical object signing',
  'canonical object signature verification',
  'evidence hash-chain append and verification helpers',
  'Merkle proof creation and verification',
  'DAG primitives for evidence lineage',
]

for (const surface of [
  'canonical_json',
  'hashing',
  'object_signing',
  'signature_verification',
  'evidence_hash_chain',
  'merkle_proofs',
  'dag_primitives',
]) {
  if (!adapterSurfaces.includes(surface)) {
    errors.push(`RUST_PRIMITIVE_SURFACES is missing ${surface}`)
  }
}

for (const readmeSurface of readmeSurfaces) {
  if (!readme.includes(readmeSurface)) {
    errors.push(`packages/rust-sdk/README.md is missing documented surface "${readmeSurface}"`)
  }
}

if (!adapterSource.includes('runtime_dependency_required: false')) {
  errors.push('RustPrimitiveAdapterManifest must require runtime_dependency_required: false')
}

if (!adapterSource.includes("schema_version: 'fides.rust_primitive_adapter.manifest.v1'")) {
  errors.push('RustPrimitiveAdapterManifest must declare the stable fides.rust_primitive_adapter.manifest.v1 schema')
}

if (errors.length > 0) {
  console.error('Rust adapter readiness audit failed:')
  for (const error of errors) {
    console.error(`- ${error}`)
  }
  process.exit(1)
}

console.log(`Rust adapter readiness audit passed for ${adapterSurfaces.length} primitive surfaces.`)

function extractStringArray(source, exportName) {
  const match = source.match(new RegExp(String.raw`export const ${exportName} = \[([\s\S]*?)\] as const`))
  if (!match) {
    errors.push(`Could not find ${exportName} in packages/adapters/src/index.ts`)
    return []
  }

  return [...match[1].matchAll(/'([^']+)'/g)].map((entry) => entry[1])
}

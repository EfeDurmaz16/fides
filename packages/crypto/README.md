# @fides/crypto

Canonical JSON, hashing, and signing entrypoints for FIDES v2.

This package is a domain facade over the TS-first core implementation. It keeps
crypto-related imports stable while Rust adapters for canonicalization, hashing,
Merkle, DAG, or performance-critical primitives remain optional.

All signed protocol objects should use the same canonical object signing model.
Higher level packages should not invent object-specific signature formats.

## Installation

```bash
npm install @fides/crypto
```

## Usage

```typescript
import {
  canonicalDigest,
  canonicalJson,
  signObject,
  verifyObject,
} from '@fides/crypto'
```

## Status

`@fides/crypto` is TS-first and Rust adapter-ready. Future AGIT/Rust adapters
can provide faster primitives without changing public protocol objects.

## License

MIT

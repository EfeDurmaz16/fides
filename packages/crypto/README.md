# @fides/crypto

Canonical JSON, hashing, and signing entrypoints for FIDES v2.

This package is a domain facade over the TS-first core implementation. It keeps
crypto-related imports stable while Rust adapters for canonicalization, hashing,
Merkle, DAG, or performance-critical primitives remain optional.

```typescript
import { canonicalDigest, signObject } from '@fides/crypto'
```

## License

MIT

# @fides/shared

Shared protocol types, constants, security helpers, service-auth utilities,
metrics helpers, and stable error classes for the FIDES trust protocol.

This package is intentionally small. It contains cross-package infrastructure
that is not specific to canonical protocol objects, signing, discovery,
policy, or the daemon API.

## Installation

```bash
npm install @fides/shared
```

## Usage

```typescript
import {
  FIDES_PROTOCOL_VERSION,
  FidesError,
  createErrorEnvelope,
} from '@fides/shared'
```

## Status

`@fides/shared` is a low-level support package for FIDES services and SDKs. New
protocol primitives should normally live in `@fides/core` or a focused facade
package instead of being added here.

## License

MIT

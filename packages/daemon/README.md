# @fides/daemon

Local daemon configuration and client boundary for FIDES v2.

The production daemon implementation currently lives in `services/agentd`.
This package provides the publishable package boundary for tools and adapters
that need stable daemon defaults, local config paths, well-known endpoint
helpers, and a Promise-based client factory.

## Installation

```bash
npm install @fides/daemon
```

## Usage

```typescript
import {
  DEFAULT_DAEMON_PORT,
  createDaemonClient,
  defaultDaemonConfig,
  wellKnownDaemonEndpoints,
} from '@fides/daemon'
```

## Status

`@fides/daemon` is a lightweight boundary package. It does not embed storage,
migrations, or server routes; those remain in the `agentd` service and
`@fides/sdk`.

## License

MIT

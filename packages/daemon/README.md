# @fides/daemon

Local daemon configuration and client boundary for FIDES v2.

The production daemon implementation currently lives in `services/agentd`.
This package provides the publishable package boundary for tools and adapters
that need stable daemon defaults, local config paths, and a Promise-based client
factory.

```typescript
import { createDaemonClient, defaultDaemonConfig } from '@fides/daemon'
```

## License

MIT

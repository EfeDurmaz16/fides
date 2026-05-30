# @fides/runtime-effect

Effect-ready internal runtime workflow boundary for FIDES v2.

This package does not make protocol objects Effect-specific. It exposes plain
workflow descriptors and Promise-based runners so Effect services, layers, and
typed-error workflows can be added around the same framework-agnostic protocol
objects.

```typescript
import { createRuntimeWorkflow, runRuntimeWorkflow } from '@fides/runtime-effect'
```

## License

MIT

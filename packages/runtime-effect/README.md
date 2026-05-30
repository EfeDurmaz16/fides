# @fides/runtime-effect

Effect-ready internal runtime workflow boundary for FIDES v2.

This package does not make protocol objects Effect-specific. It exposes plain
workflow descriptors and Promise-based runners so Effect services, layers, and
typed-error workflows can be added around the same framework-agnostic protocol
objects.

## Installation

```bash
npm install @fides/runtime-effect
```

## Usage

```typescript
import { createRuntimeWorkflow, runRuntimeWorkflow } from '@fides/runtime-effect'
```

## Status

The current package provides typed workflow boundaries and a Promise-based
runner interface. It does not make AgentCards, EvidenceEvents, SessionGrants,
or public schemas Effect-specific; optional Effect-native APIs can be layered
on later without changing protocol objects.

## License

MIT

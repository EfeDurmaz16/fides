# @fides/runtime

Runtime attestation and kill switch primitives for FIDES.

This package provides adapter interfaces for runtime attestation, local mock attestation for tests and demos, container image claim validation, and in-memory kill switch controls at global, agent, capability, and principal scope.

## Installation

```bash
npm install @fides/runtime
```

## Usage

```typescript
import { InMemoryKillSwitch, MockTEEProvider } from '@fides/runtime'

const attestation = await new MockTEEProvider().attest('did:fides:agent')

const killSwitch = new InMemoryKillSwitch()
killSwitch.engageAgent('did:fides:agent', 'incident response')

const blocked = killSwitch.isEngaged({ agentDid: 'did:fides:agent' })
```

## License

MIT

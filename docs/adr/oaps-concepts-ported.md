# ADR: OAPS Concepts Ported Into FIDES

## Status

Accepted.

## Decision

FIDES v2 ports relevant OAPS concepts into FIDES-owned runtime types. FIDES does not depend on `@oaps/core` at runtime.

## Consequences

- FIDES owns its namespace, schemas, SDK, CLI, and services.
- OAPS remains a semantic compatibility source.
- Mapping docs and adapters preserve interoperability.

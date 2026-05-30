# ADR: Use Effect Internally Only

## Status

Accepted.

## Decision

Effect may be used internally for service layers, typed errors, workflows, dependency injection, provider orchestration, daemon workflows, and CLI workflows.

Protocol objects and public SDK APIs remain framework-agnostic.

## Consequences

- Public SDK remains Promise-based.
- Protocol objects do not expose Effect types.
- Optional Effect-native APIs may be added later.

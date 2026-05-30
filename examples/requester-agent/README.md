# Requester Agent

Runnable FIDES v2 requester example.

This example discovers candidate agents, checks trust and policy, requests
scoped authority, and records evidence for multi-agent interaction. It is the
ARP-like resolution step upgraded with identity, trust, policy, and evidence,
not a naive directory lookup.

```bash
pnpm exec tsx examples/requester-agent/index.ts
```

The legacy wrapper remains available:

```bash
pnpm exec tsx examples/requester-agent.ts
```

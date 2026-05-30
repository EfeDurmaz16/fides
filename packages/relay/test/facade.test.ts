import { describe, expect, it } from 'vitest'
import { RelayDiscoveryProvider } from '../src/index.js'

describe('@fides/relay facade', () => {
  it('exports relay discovery provider', () => {
    const provider = new RelayDiscoveryProvider({ relayUrl: 'https://relay.example.test' })

    expect(provider.name).toBe('relay')
  })
})

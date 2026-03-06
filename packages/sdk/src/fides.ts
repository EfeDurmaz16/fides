import type {
  AgentIdentity,
  AgentCard,
  AgentCardQuery,
  TrustAttestation,
  TrustScore,
} from '@fides/shared'
import type { RequestLike } from './signing/canonicalize.js'
import { MemoryKeyStore, type KeyStore } from './identity/keystore.js'
import { generateKeyPair } from './identity/keypair.js'
import { generateDID } from './identity/did.js'
import { signRequest } from './signing/http-signature.js'
import { verifyRequest, type VerifyResult } from './signing/verify.js'
import { DiscoveryClient } from './discovery/client.js'
import { IdentityResolver } from './discovery/resolver.js'
import { TrustClient } from './trust/client.js'
import { createAttestation } from './trust/attestation.js'
import { AgentDiscoveryClient, type RegisterAgentParams } from './discovery/agent-client.js'

export interface FidesOptions {
  discoveryUrl: string
  trustUrl: string
  keyStore?: KeyStore
}

export class Fides {
  private discoveryClient: DiscoveryClient
  private agentClient: AgentDiscoveryClient
  private resolver: IdentityResolver
  private trustClient: TrustClient
  private keyStore: KeyStore
  private currentDid?: string
  private heartbeatTimer?: ReturnType<typeof setInterval>

  constructor(options: FidesOptions) {
    this.discoveryClient = new DiscoveryClient({ baseUrl: options.discoveryUrl })
    this.agentClient = new AgentDiscoveryClient({ baseUrl: options.discoveryUrl })
    this.resolver = new IdentityResolver({ discoveryUrl: options.discoveryUrl })
    this.trustClient = new TrustClient({ baseUrl: options.trustUrl })
    this.keyStore = options.keyStore ?? new MemoryKeyStore()
  }

  /**
   * Create a new identity (keypair + DID) and register with discovery
   */
  async createIdentity(
    metadata?: Record<string, unknown>
  ): Promise<{ did: string; publicKey: string }> {
    // Generate keypair
    const keyPair = await generateKeyPair()

    // Generate DID from public key
    const did = generateDID(keyPair.publicKey)

    // Store in keystore
    await this.keyStore.save(did, keyPair)

    // Convert public key to hex for registration
    const publicKey = Buffer.from(keyPair.publicKey).toString('hex')

    // Register with discovery service
    await this.discoveryClient.register({
      did,
      publicKey,
      metadata,
    })

    // Set as current DID
    this.currentDid = did

    return { did, publicKey }
  }

  /**
   * Sign an HTTP request using the current identity
   */
  async signRequest(request: RequestLike): Promise<RequestLike> {
    if (!this.currentDid) {
      throw new Error('No identity available. Call createIdentity() first.')
    }

    const keyPair = await this.keyStore.load(this.currentDid)

    return signRequest(request, keyPair.privateKey, {
      keyid: this.currentDid,
    })
  }

  /**
   * Verify an HTTP request signature
   */
  async verifyRequest(request: RequestLike): Promise<VerifyResult> {
    // First extract the keyId from the signature input
    const signatureInput = request.headers['Signature-Input'] || request.headers['signature-input']
    if (!signatureInput) {
      return {
        valid: false,
        error: 'Missing Signature-Input header',
      }
    }

    // Parse to get keyId
    const keyIdMatch = signatureInput.match(/keyid="([^"]+)"/)
    if (!keyIdMatch) {
      return {
        valid: false,
        error: 'No keyId found in Signature-Input',
      }
    }

    const keyId = keyIdMatch[1]

    // Resolve identity to get public key
    const identity = await this.resolver.resolve(keyId)
    if (!identity) {
      return {
        valid: false,
        error: `Could not resolve identity for keyId: ${keyId}`,
      }
    }

    const publicKey = Buffer.from(identity.publicKey, 'hex')
    return verifyRequest(request, publicKey)
  }

  /**
   * Create and submit a trust attestation
   */
  async trust(subjectDid: string, level: number): Promise<TrustAttestation> {
    if (!this.currentDid) {
      throw new Error('No identity available. Call createIdentity() first.')
    }

    const keyPair = await this.keyStore.load(this.currentDid)

    // Create attestation
    const attestation = await createAttestation(
      this.currentDid,
      subjectDid,
      level,
      keyPair.privateKey
    )

    // Submit to trust service
    await this.trustClient.attest(
      this.currentDid,
      subjectDid,
      level,
      attestation.signature,
      attestation.payload
    )

    return attestation
  }

  /**
   * Get the reputation score for a DID
   */
  async getReputation(did: string): Promise<TrustScore> {
    return this.trustClient.getScore(did)
  }

  /**
   * Resolve a DID or domain to an identity
   */
  async resolve(didOrDomain: string): Promise<AgentIdentity | null> {
    return this.resolver.resolve(didOrDomain)
  }

  /**
   * Register this agent with capabilities for discovery by other agents.
   * Starts automatic heartbeat to maintain online status.
   */
  async registerAgent(
    params: Omit<RegisterAgentParams, 'did'>
  ): Promise<AgentCard> {
    if (!this.currentDid) {
      throw new Error('No identity available. Call createIdentity() first.')
    }

    const card = await this.agentClient.registerAgent({
      ...params,
      did: this.currentDid,
    })

    // Start automatic heartbeat every 60 seconds
    this.startHeartbeat()

    return card
  }

  /**
   * Discover other agents by capability, status, tag, or provider
   */
  async discoverAgents(query?: AgentCardQuery): Promise<AgentCard[]> {
    return this.agentClient.discoverAgents(query)
  }

  /**
   * Get a specific agent's card by DID
   */
  async getAgent(did: string): Promise<AgentCard | null> {
    return this.agentClient.getAgent(did)
  }

  /**
   * Stop heartbeat and deregister this agent
   */
  async deregisterAgent(): Promise<void> {
    if (!this.currentDid) return
    this.stopHeartbeat()
    await this.agentClient.deregisterAgent(this.currentDid)
  }

  private startHeartbeat(): void {
    this.stopHeartbeat()
    this.heartbeatTimer = setInterval(async () => {
      if (this.currentDid) {
        try {
          await this.agentClient.heartbeat(this.currentDid)
        } catch {
          // Silently ignore heartbeat failures
        }
      }
    }, 60_000)
    // Allow process to exit even if heartbeat is running
    if (this.heartbeatTimer.unref) this.heartbeatTimer.unref()
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = undefined
    }
  }

  /**
   * Rotate the current identity's keypair
   */
  async rotateKey(reason?: string): Promise<{ oldDid: string; newDid: string; newPublicKey: string }> {
    if (!this.currentDid) {
      throw new Error('No identity available. Call createIdentity() first.')
    }

    const { rotateKey: rotate } = await import('./identity/rotation.js')
    const result = await rotate(this.currentDid, this.keyStore, { reason })

    // Register new identity with discovery
    await this.discoveryClient.register({
      did: result.newDid,
      publicKey: result.newPublicKey,
    })

    const oldDid = this.currentDid
    this.currentDid = result.newDid

    return {
      oldDid,
      newDid: result.newDid,
      newPublicKey: result.newPublicKey,
    }
  }
}

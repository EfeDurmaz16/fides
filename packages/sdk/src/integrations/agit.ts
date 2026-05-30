/**
 * agit (AgentGit) integration for FIDES.
 *
 * Provides commit signing, verification, and trust-gated access
 * for agit repositories using FIDES decentralized identity.
 *
 * @example
 * ```ts
 * import { Fides } from "@fides/sdk";
 * import { AgitCommitSigner, TrustGatedAccess } from "@fides/sdk/integrations/agit";
 *
 * const fides = new Fides({ discoveryUrl: "...", trustUrl: "..." });
 * const signer = new AgitCommitSigner(fides);
 * await signer.init();
 *
 * // Sign a commit
 * const signed = await signer.signCommitData(stateJson);
 *
 * // Verify a commit
 * const result = await signer.verifyCommitData(stateJson, signature, signerDid);
 * ```
 */

import type { TrustAttestation, TrustScore } from '@fides/shared'
import { canonicalJson, hashProtocolPayload } from '@fides/core'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { generateKeyPair, sign, verify } from '../identity/keypair.js'
import { generateDID, parseDID, isValidDID } from '../identity/did.js'
import type { KeyStore } from '../identity/keystore.js'
import { MemoryKeyStore } from '../identity/keystore.js'
import { createAttestation, verifyAttestation } from '../trust/attestation.js'

export interface CommitSignature {
  did: string
  publicKey: string // hex-encoded
  signature: string // hex-encoded
  stateHash: string // SHA-256 hex
  algorithm: 'ed25519'
  signedAt: string // ISO timestamp
}

export interface CommitVerification {
  valid: boolean
  did?: string
  error?: string
}

export interface TrustGateResult {
  allowed: boolean
  requesterDid: string
  trustLevel: number
  requiredLevel: number
  reason?: string
}

export interface AgitEvidenceHashChainInput {
  previousEventHash?: string
  eventPayload: Record<string, unknown>
}

export interface AgitEvidenceHashChainResult {
  eventHash: string
  previousEventHash?: string
}

export interface AgitMerkleProofInput {
  leaves: string[]
  leaf: string
}

export interface AgitMerkleProofResult {
  root: string
  leaf: string
  proof: string[]
}

export interface AgitRustPrimitiveAdapter {
  canonicalizeJson?(value: unknown): Promise<string> | string
  hashBytes?(bytes: Uint8Array, algorithm?: 'sha256'): Promise<string> | string
  appendEvidenceHash?(input: AgitEvidenceHashChainInput): Promise<AgitEvidenceHashChainResult> | AgitEvidenceHashChainResult
  createMerkleProof?(input: AgitMerkleProofInput): Promise<AgitMerkleProofResult> | AgitMerkleProofResult
}

export interface AgitPrimitiveBridgeOptions {
  rustAdapter?: AgitRustPrimitiveAdapter
}

/**
 * AgitPrimitiveBridge provides the adapter-ready boundary between FIDES and
 * future AGIT/Rust primitives. Rust is optional: when no adapter is supplied,
 * the SDK uses the same TypeScript canonical JSON and hashing model as FIDES.
 */
export class AgitPrimitiveBridge {
  constructor(private readonly options: AgitPrimitiveBridgeOptions = {}) {}

  get rustAdapter(): AgitRustPrimitiveAdapter | undefined {
    return this.options.rustAdapter
  }

  async canonicalizeJson(value: unknown): Promise<string> {
    return this.options.rustAdapter?.canonicalizeJson
      ? this.options.rustAdapter.canonicalizeJson(value)
      : canonicalJson(value)
  }

  async hashBytes(bytes: Uint8Array): Promise<string> {
    return this.options.rustAdapter?.hashBytes
      ? this.options.rustAdapter.hashBytes(bytes, 'sha256')
      : `sha256:${bytesToHex(sha256(bytes))}`
  }

  async hashObject(value: unknown): Promise<string> {
    const canonical = await this.canonicalizeJson(value)
    return this.hashBytes(new TextEncoder().encode(canonical))
  }

  async appendEvidenceHash(input: AgitEvidenceHashChainInput): Promise<AgitEvidenceHashChainResult> {
    if (this.options.rustAdapter?.appendEvidenceHash) {
      return this.options.rustAdapter.appendEvidenceHash(input)
    }

    return {
      previousEventHash: input.previousEventHash,
      eventHash: hashProtocolPayload({
        prev_event_hash: input.previousEventHash ?? '0',
        event_payload: input.eventPayload,
      }),
    }
  }

  async createMerkleProof(input: AgitMerkleProofInput): Promise<AgitMerkleProofResult> {
    if (this.options.rustAdapter?.createMerkleProof) {
      return this.options.rustAdapter.createMerkleProof(input)
    }
    return createLocalMerkleProof(input)
  }
}

function createLocalMerkleProof(input: AgitMerkleProofInput): AgitMerkleProofResult {
  const leafIndex = input.leaves.indexOf(input.leaf)
  if (leafIndex === -1) {
    throw new Error('Merkle proof leaf is not present in leaves')
  }

  let index = leafIndex
  let level = input.leaves
  const proof: string[] = []

  while (level.length > 1) {
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1
    proof.push(level[siblingIndex] ?? level[index])
    index = Math.floor(index / 2)
    level = nextMerkleLevel(level)
  }

  return {
    root: level[0] ?? input.leaf,
    leaf: input.leaf,
    proof,
  }
}

function nextMerkleLevel(level: string[]): string[] {
  const next: string[] = []
  for (let i = 0; i < level.length; i += 2) {
    const left = level[i]
    const right = level[i + 1] ?? left
    next.push(hashPair(left, right))
  }
  return next
}

function hashPair(left: string, right: string): string {
  return `sha256:${bytesToHex(sha256(new TextEncoder().encode(`${left}:${right}`)))}`
}

/**
 * AgitCommitSigner — Signs and verifies agit commits with FIDES identity.
 *
 * Each commit's state hash is signed with the agent's Ed25519 keypair,
 * creating a cryptographic proof that links the state change to a
 * verified agent identity.
 */
export class AgitCommitSigner {
  private keyStore: KeyStore
  private currentDid: string | null = null
  private publicKeyHex: string | null = null

  constructor(keyStore?: KeyStore) {
    this.keyStore = keyStore ?? new MemoryKeyStore()
  }

  /**
   * Initialize a new identity for commit signing.
   */
  async init(metadata?: Record<string, unknown>): Promise<string> {
    const keyPair = await generateKeyPair()
    const did = generateDID(keyPair.publicKey)

    await this.keyStore.save(did, keyPair)
    this.currentDid = did
    this.publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex')

    return did
  }

  /**
   * Load an existing identity for commit signing.
   */
  async loadIdentity(did: string): Promise<void> {
    const keyPair = await this.keyStore.load(did)
    this.currentDid = did
    this.publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex')
  }

  /**
   * Sign a commit's state data. Returns a CommitSignature to embed
   * in the agit state's `_fides` field.
   */
  async signCommitData(stateJson: string): Promise<CommitSignature> {
    if (!this.currentDid) {
      throw new Error('No identity initialized. Call init() first.')
    }

    const keyPair = await this.keyStore.load(this.currentDid)

    // SHA-256 hash of the state
    const encoder = new TextEncoder()
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(stateJson))
    const stateHash = Buffer.from(hashBuffer).toString('hex')

    // Sign the hash with Ed25519
    const hashBytes = encoder.encode(stateHash)
    const signatureBytes = await sign(hashBytes, keyPair.privateKey)

    return {
      did: this.currentDid,
      publicKey: this.publicKeyHex!,
      signature: Buffer.from(signatureBytes).toString('hex'),
      stateHash,
      algorithm: 'ed25519',
      signedAt: new Date().toISOString(),
    }
  }

  /**
   * Verify a commit signature. Used to check that a commit was
   * actually created by the claimed agent DID.
   */
  async verifyCommitData(
    stateJson: string,
    commitSignature: CommitSignature
  ): Promise<CommitVerification> {
    try {
      // Validate DID format
      if (!isValidDID(commitSignature.did)) {
        return { valid: false, error: 'Invalid DID format' }
      }

      // Recompute state hash
      const encoder = new TextEncoder()
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(stateJson))
      const computedHash = Buffer.from(hashBuffer).toString('hex')

      // Verify hash matches
      if (computedHash !== commitSignature.stateHash) {
        return {
          valid: false,
          did: commitSignature.did,
          error: 'State hash mismatch (possible tampering)',
        }
      }

      // Extract public key from DID
      const publicKey = parseDID(commitSignature.did)

      // Verify Ed25519 signature over the hash
      const hashBytes = encoder.encode(commitSignature.stateHash)
      const signatureBytes = Buffer.from(commitSignature.signature, 'hex')
      const valid = await verify(hashBytes, signatureBytes, publicKey)

      if (!valid) {
        return {
          valid: false,
          did: commitSignature.did,
          error: 'Ed25519 signature verification failed',
        }
      }

      return { valid: true, did: commitSignature.did }
    } catch (e) {
      return { valid: false, error: String(e) }
    }
  }

  /** Get the current signer's DID. */
  getDid(): string | null {
    return this.currentDid
  }

  /** Get the current signer's public key (hex). */
  getPublicKey(): string | null {
    return this.publicKeyHex
  }
}

/**
 * TrustGatedAccess — Enforces minimum trust levels for agit operations.
 *
 * Use this to gate merge, write, or read operations based on the
 * requester's reputation score in the FIDES trust graph.
 */
export class TrustGatedAccess {
  private trustScoreResolver: (did: string) => Promise<TrustScore | null>

  constructor(
    trustScoreResolver: (did: string) => Promise<TrustScore | null>
  ) {
    this.trustScoreResolver = trustScoreResolver
  }

  /**
   * Check if an agent has sufficient trust for an operation.
   */
  async checkAccess(
    requesterDid: string,
    requiredLevel: number
  ): Promise<TrustGateResult> {
    if (!isValidDID(requesterDid)) {
      return {
        allowed: false,
        requesterDid,
        trustLevel: 0,
        requiredLevel,
        reason: 'Invalid DID format',
      }
    }

    const score = await this.trustScoreResolver(requesterDid)

    if (!score) {
      return {
        allowed: false,
        requesterDid,
        trustLevel: 0,
        requiredLevel,
        reason: 'Agent not found in trust graph',
      }
    }

    const trustLevel = Math.round(score.score * 100)

    return {
      allowed: trustLevel >= requiredLevel,
      requesterDid,
      trustLevel,
      requiredLevel,
      reason: trustLevel >= requiredLevel
        ? undefined
        : `Insufficient trust: ${trustLevel} < ${requiredLevel}`,
    }
  }

  /**
   * Create a trust gate for merge operations.
   * Typical threshold: 50 (medium trust).
   */
  mergeGate(minLevel: number = 50) {
    return async (requesterDid: string) =>
      this.checkAccess(requesterDid, minLevel)
  }

  /**
   * Create a trust gate for write operations.
   * Typical threshold: 25 (low trust).
   */
  writeGate(minLevel: number = 25) {
    return async (requesterDid: string) =>
      this.checkAccess(requesterDid, minLevel)
  }

  /**
   * Create a trust gate for admin operations.
   * Typical threshold: 75 (high trust).
   */
  adminGate(minLevel: number = 75) {
    return async (requesterDid: string) =>
      this.checkAccess(requesterDid, minLevel)
  }
}

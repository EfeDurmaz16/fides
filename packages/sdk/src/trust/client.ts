import type { TrustScore, TrustPath } from '@fides/shared'
import { TrustError } from '@fides/shared'

export class TrustClient {
  constructor(private options: { baseUrl: string }) {}

  /**
   * Submit a trust attestation
   */
  async attest(
    issuerDid: string,
    subjectDid: string,
    level: number,
    signature: string,
    payload: string
  ): Promise<void> {
    try {
      const response = await fetch(`${this.options.baseUrl}/v1/trust`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          issuerDid,
          subjectDid,
          trustLevel: level,
          signature,
          payload,
        }),
      })

      if (!response.ok) {
        const text = await response.text()
        throw new TrustError(
          `Failed to submit attestation: ${response.status} ${text}`
        )
      }
    } catch (error) {
      if (error instanceof TrustError) {
        throw error
      }
      throw new TrustError(
        `Failed to submit attestation: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Get the trust score for a DID
   */
  async getScore(did: string): Promise<TrustScore> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/v1/trust/${encodeURIComponent(did)}/score`
      )

      if (!response.ok) {
        const text = await response.text()
        throw new TrustError(
          `Failed to get trust score: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof TrustError) {
        throw error
      }
      throw new TrustError(
        `Failed to get trust score: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }

  /**
   * Get the trust path between two DIDs
   */
  async getPath(from: string, to: string): Promise<TrustPath> {
    try {
      const response = await fetch(
        `${this.options.baseUrl}/v1/trust/${encodeURIComponent(from)}/${encodeURIComponent(to)}`
      )

      if (!response.ok) {
        const text = await response.text()
        throw new TrustError(
          `Failed to get trust path: ${response.status} ${text}`
        )
      }

      return await response.json()
    } catch (error) {
      if (error instanceof TrustError) {
        throw error
      }
      throw new TrustError(
        `Failed to get trust path: ${error instanceof Error ? error.message : String(error)}`
      )
    }
  }
}

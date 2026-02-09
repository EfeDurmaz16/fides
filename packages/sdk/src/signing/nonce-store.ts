/**
 * In-memory nonce store for replay attack detection
 * Tracks seen nonces with automatic TTL-based cleanup
 */
export class NonceStore {
  private seen = new Map<string, number>() // nonce -> timestamp
  private readonly ttlMs: number
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(ttlSeconds = 300) {
    this.ttlMs = ttlSeconds * 1000
    // Cleanup expired nonces every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000)
    // Allow process to exit even if interval is running
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref()
    }
  }

  /**
   * Check if nonce has been seen before. If not, mark it as seen.
   * @returns true if nonce is fresh (not a replay), false if already seen
   */
  check(nonce: string): boolean {
    const now = Date.now()
    if (this.seen.has(nonce)) {
      return false // replay detected
    }
    this.seen.set(nonce, now)
    return true
  }

  private cleanup(): void {
    const cutoff = Date.now() - this.ttlMs
    for (const [nonce, timestamp] of this.seen) {
      if (timestamp < cutoff) {
        this.seen.delete(nonce)
      }
    }
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.seen.clear()
  }
}

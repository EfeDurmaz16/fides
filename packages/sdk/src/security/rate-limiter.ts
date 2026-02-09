/**
 * In-memory sliding window rate limiter
 * For use as middleware in Hono services
 */

export interface RateLimiterOptions {
  /** Max requests per window */
  maxRequests: number
  /** Window size in milliseconds */
  windowMs: number
}

export class RateLimiter {
  private windows = new Map<string, number[]>()
  private readonly maxRequests: number
  private readonly windowMs: number
  private cleanupInterval: ReturnType<typeof setInterval> | null = null

  constructor(options: RateLimiterOptions) {
    this.maxRequests = options.maxRequests
    this.windowMs = options.windowMs

    // Cleanup every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000)
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref()
    }
  }

  /**
   * Check if request should be allowed
   * @param key - Identifier (IP, DID, etc.)
   * @returns true if allowed, false if rate limited
   */
  check(key: string): boolean {
    const now = Date.now()
    const cutoff = now - this.windowMs

    let timestamps = this.windows.get(key) || []
    // Remove expired entries
    timestamps = timestamps.filter(t => t > cutoff)

    if (timestamps.length >= this.maxRequests) {
      this.windows.set(key, timestamps)
      return false
    }

    timestamps.push(now)
    this.windows.set(key, timestamps)
    return true
  }

  /** Get remaining requests for a key */
  remaining(key: string): number {
    const now = Date.now()
    const cutoff = now - this.windowMs
    const timestamps = (this.windows.get(key) || []).filter(t => t > cutoff)
    return Math.max(0, this.maxRequests - timestamps.length)
  }

  private cleanup(): void {
    const cutoff = Date.now() - this.windowMs
    for (const [key, timestamps] of this.windows) {
      const valid = timestamps.filter(t => t > cutoff)
      if (valid.length === 0) {
        this.windows.delete(key)
      } else {
        this.windows.set(key, valid)
      }
    }
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval)
      this.cleanupInterval = null
    }
    this.windows.clear()
  }
}

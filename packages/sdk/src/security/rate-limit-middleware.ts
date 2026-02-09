/**
 * Hono middleware wrapper for RateLimiter
 *
 * Usage: import and use with Hono apps that have @fides/sdk as a dependency
 */
import { RateLimiter, type RateLimiterOptions } from './rate-limiter.js'

export interface RateLimitMiddlewareOptions extends RateLimiterOptions {
  /** Function to extract the rate limit key from the request context */
  keyExtractor?: (c: any) => string
}

export function rateLimitMiddleware(options: RateLimitMiddlewareOptions) {
  const limiter = new RateLimiter({
    maxRequests: options.maxRequests,
    windowMs: options.windowMs,
  })

  return async (c: any, next: () => Promise<void>) => {
    const key = options.keyExtractor
      ? options.keyExtractor(c)
      : c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown'

    const remaining = limiter.remaining(key)

    c.header('X-RateLimit-Limit', String(options.maxRequests))
    c.header('X-RateLimit-Remaining', String(remaining))
    c.header('X-RateLimit-Reset', String(Math.ceil(Date.now() / 1000) + Math.ceil(options.windowMs / 1000)))

    if (!limiter.check(key)) {
      return c.json(
        { error: 'Too many requests. Please try again later.' },
        429
      )
    }

    await next()
  }
}

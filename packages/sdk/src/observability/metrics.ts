/**
 * Zero-dependency Prometheus metrics collector.
 * Tracks request counts, response times (p50/p90/p99), and active connections.
 */

const MAX_RESPONSE_TIMES = 10_000

/** Normalize paths to reduce cardinality (replace DIDs/UUIDs with :id) */
function normalizePath(path: string): string {
  return path
    .replace(/did:[^/]+/g, ':id')
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
    .replace(/\/[A-Za-z0-9]{20,}/g, '/:id')
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0
  const idx = Math.ceil((p / 100) * sorted.length) - 1
  return sorted[Math.max(0, idx)]
}

interface RequestCount {
  count: number
}

export class MetricsCollector {
  private requests = new Map<string, RequestCount>()
  private responseTimes: number[] = []
  private activeConnections = 0

  /** Record a completed request */
  recordRequest(method: string, path: string, status: number, durationMs: number): void {
    const normalizedPath = normalizePath(path)
    const key = `${method}|${normalizedPath}|${status}`

    const existing = this.requests.get(key)
    if (existing) {
      existing.count++
    } else {
      this.requests.set(key, { count: 1 })
    }

    // Bounded response times buffer
    if (this.responseTimes.length >= MAX_RESPONSE_TIMES) {
      this.responseTimes.shift()
    }
    this.responseTimes.push(durationMs)
  }

  /** Increment active connections gauge */
  incrementConnections(): void {
    this.activeConnections++
  }

  /** Decrement active connections gauge */
  decrementConnections(): void {
    this.activeConnections = Math.max(0, this.activeConnections - 1)
  }

  /** Render metrics in Prometheus text exposition format */
  toPrometheus(): string {
    const lines: string[] = []

    // Request counters
    lines.push('# HELP http_requests_total Total number of HTTP requests')
    lines.push('# TYPE http_requests_total counter')
    for (const [key, { count }] of this.requests) {
      const [method, path, status] = key.split('|')
      lines.push(`http_requests_total{method="${method}",path="${path}",status="${status}"} ${count}`)
    }

    // Response time percentiles
    const sorted = [...this.responseTimes].sort((a, b) => a - b)
    lines.push('# HELP http_response_duration_ms HTTP response duration in milliseconds')
    lines.push('# TYPE http_response_duration_ms summary')
    lines.push(`http_response_duration_ms{quantile="0.5"} ${percentile(sorted, 50)}`)
    lines.push(`http_response_duration_ms{quantile="0.9"} ${percentile(sorted, 90)}`)
    lines.push(`http_response_duration_ms{quantile="0.99"} ${percentile(sorted, 99)}`)
    lines.push(`http_response_duration_ms_count ${sorted.length}`)

    // Active connections gauge
    lines.push('# HELP http_active_connections Current number of active connections')
    lines.push('# TYPE http_active_connections gauge')
    lines.push(`http_active_connections ${this.activeConnections}`)

    return lines.join('\n') + '\n'
  }
}

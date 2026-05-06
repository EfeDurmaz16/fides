import { describe, expect, it } from 'vitest'
import { MetricsCollector } from '../src/metrics.js'

describe('MetricsCollector', () => {
  it('records requests and renders Prometheus counters', () => {
    const collector = new MetricsCollector()

    collector.recordRequest('GET', '/v1/cards/did:fides:agent', 200, 12)

    const metrics = collector.toPrometheus()
    expect(metrics).toContain('# TYPE http_requests_total counter')
    expect(metrics).toContain('http_requests_total{method="GET",path="/v1/cards/:id",status="200"} 1')
    expect(metrics).toContain('http_response_duration_ms_count 1')
  })

  it('tracks active connections without going negative', () => {
    const collector = new MetricsCollector()

    collector.incrementConnections()
    collector.decrementConnections()
    collector.decrementConnections()

    expect(collector.toPrometheus()).toContain('http_active_connections 0')
  })
})

import { Hono } from 'hono'

const health = new Hono()

health.get('/', (c) => {
  return c.json({
    status: 'healthy',
    service: 'discovery',
    timestamp: new Date().toISOString(),
  })
})

export default health

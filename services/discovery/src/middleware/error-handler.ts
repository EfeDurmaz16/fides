import type { ErrorHandler } from 'hono'

export const errorHandler: ErrorHandler = (err, c) => {
  const requestId = c.req.header('x-request-id') || 'unknown'

  const logEntry = JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'error',
    requestId,
    error: err.message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  })

  console.error(logEntry)

  return c.json(
    {
      error: process.env.NODE_ENV === 'production'
        ? 'Internal server error'
        : err.message,
      requestId,
    },
    500
  )
}

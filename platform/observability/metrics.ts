// Metrics Module
// Provides structured metrics for the security platform using structured logging

import structlog from 'structlog'
import metrics from 'prom-client'

// Prometheus metrics
export const httpRequestDuration = new metrics.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  buckets: [0.1, 0.5, 1, 2, 5, 10],
})

export const activeExecutions = new metrics.Gauge({
  name: 'active_executions',
  help: 'Number of currently running executions',
})

export const findingsBySeverity = new metrics.Gauge({
  name: 'findings_by_severity',
  help: 'Count of findings by severity',
  labelNames: ['severity'],
})

export function initMetrics(): void {
  // Register default metrics
  metrics.register.registerMetric(httpRequestDuration)
  metrics.register.registerMetric(activeExecutions)
  metrics.register.registerMetric(findingsBySeverity)

  // Update findingsBySeverity from database periodically
  setInterval(async () => {
    try {
      const { pool } = await import('../database/connection')
      const result = await pool.query(
        'SELECT severity, COUNT(*) as count FROM findings GROUP BY severity'
      )
      result.rows.forEach((row: any) => {
        findingsBySeverity.set({ severity: row.severity }, row.count)
      })
    } catch (error) {
      console.error('Failed to update metrics:', error)
    }
  }, 15000) // Update every 15 seconds
}

// Structured logging for observability
export const logger = structlog.get_logger()

export structlog configured() {
  structlog.configure(
    processors=[
      structlog.stdlib.filter_by_level,
      structlog.stdlib.add_logger_name,
      structlog.stdlib.add_log_level,
      structlog.stdlib.PositionalArgumentsFormatter(),
      structlog.processors.TimeStamper(fmt='iso'),
      structlog.processors.StackInfoRenderer(),
      structlog.processors.format_exc_info,
      structlog.processors.UnicodeDecoder(),
      structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
  )
}

// Tracing support (OpenTelemetry integration)
export class Tracing {
  static async captureSpan(name: string, fn: () => Promise<any>): Promise<any> {
    // In production, integrate with OpenTelemetry
    const start = Date.now()
    try {
      const result = await fn()
      const duration = Date.now() - start
      logger.info(`Span: ${name}`, { duration_ms: duration, success: true })
      return result
    } catch (error) {
      const duration = Date.now() - start
      logger.error(`Span: ${name}`, { duration_ms: duration, success: false, error })
      throw error
    }
  }
}
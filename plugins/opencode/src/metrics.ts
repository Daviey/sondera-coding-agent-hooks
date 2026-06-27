export interface Metrics {
  total: number
  allowed: number
  denied: number
  escalated: number
  dryRunDenies: number
  bypassed: number
  errors: number
  totalDurationMs: number
}

let metrics: Metrics = createEmpty()

function createEmpty(): Metrics {
  return {
    total: 0,
    allowed: 0,
    denied: 0,
    escalated: 0,
    dryRunDenies: 0,
    bypassed: 0,
    errors: 0,
    totalDurationMs: 0,
  }
}

export function recordAllow(durationMs: number) {
  metrics.total++
  metrics.allowed++
  metrics.totalDurationMs += durationMs
}

export function recordDeny(durationMs: number) {
  metrics.total++
  metrics.denied++
  metrics.totalDurationMs += durationMs
}

export function recordEscalate(durationMs: number) {
  metrics.total++
  metrics.escalated++
  metrics.totalDurationMs += durationMs
}

export function recordDryRunDeny(durationMs: number) {
  metrics.total++
  metrics.dryRunDenies++
  metrics.totalDurationMs += durationMs
}

export function recordBypass() {
  metrics.total++
  metrics.bypassed++
}

export function recordError() {
  metrics.total++
  metrics.errors++
}

export function getMetrics(): Metrics {
  return { ...metrics }
}

export function resetMetrics() {
  metrics = createEmpty()
}

export function logSummary() {
  if (metrics.total === 0) return

  const avgMs = metrics.total > 0
    ? Math.round((metrics.totalDurationMs / metrics.total) * 100) / 100
    : 0

  console.error(
    `[sondera] session stats: ${metrics.total} calls, ` +
    `${metrics.allowed} allowed, ${metrics.denied} denied, ` +
    `${metrics.escalated} escalated, ${metrics.dryRunDenies} dry-run denies, ` +
    `${metrics.bypassed} bypassed, ${metrics.errors} errors, ` +
    `avg ${avgMs}ms`,
  )
}

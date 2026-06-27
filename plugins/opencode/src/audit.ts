import type { AdapterRequest, AdjudicationResponse } from "./types"
import type { SonderaConfig } from "./config"

export interface AuditEntry {
  ts: string
  trajectory_id: string
  tool: string
  action: string
  decision: string
  reason?: string
  dry_run: boolean
  duration_ms: number
}

let logStream: ReturnType<typeof Bun.file> | null = null
let logWriter: any = null

export function initAuditLog(config: SonderaConfig) {
  if (!config.auditLogPath) return
  try {
    logStream = Bun.file(config.auditLogPath)
    logWriter = logStream.writer()
  } catch (err) {
    console.error(`[sondera] failed to open audit log: ${config.auditLogPath}`, err)
  }
}

export function writeAudit(
  event: AdapterRequest,
  result: AdjudicationResponse,
  dryRun: boolean,
  durationMs: number,
) {
  if (!logWriter) return

  const entry: AuditEntry = {
    ts: new Date().toISOString(),
    trajectory_id: event.trajectory_id,
    tool: event.tool,
    action: event.action,
    decision: result.decision,
    reason: result.reason,
    dry_run: dryRun,
    duration_ms: Math.round(durationMs * 100) / 100,
  }

  try {
    logWriter.write(JSON.stringify(entry) + "\n")
    logWriter.flush()
  } catch {}
}

export function closeAuditLog() {
  if (logWriter) {
    try { logWriter.end() } catch {}
    logWriter = null
    logStream = null
  }
}

import type { PluginContext } from "./types"
import { HarnessClient } from "./client"
import { normalizeEvent, toolArgs } from "./normalize"
import { PolicyDenyError, AdjudicationError } from "./types"
import { loadConfig, matchesAllowPattern } from "./config"
import { initAuditLog, writeAudit, closeAuditLog } from "./audit"
import { initToast, sendToast, resetToast } from "./toast"
import {
  recordAllow, recordDeny, recordEscalate,
  recordDryRunDeny, recordBypass, recordError, logSummary,
  resetMetrics,
} from "./metrics"

let client: HarnessClient | null = null
let initialized = false
let config: ReturnType<typeof loadConfig> | null = null
let harnessProc: ReturnType<typeof Bun.spawn> | null = null

export function _reset() {
  client = null
  initialized = false
  config = null
  if (harnessProc) {
    try { if (!harnessProc.killed) harnessProc.kill() } catch {}
    harnessProc = null
  }
  resetMetrics()
  closeAuditLog()
  resetToast()
}

async function getClient(): Promise<HarnessClient | null> {
  if (initialized) return client
  initialized = true

  if (!config!.enabled) {
    return null
  }

  const c = new HarnessClient(undefined, false, config!.adjudicateTimeoutMs)
  let healthy = await c.health()
  if (!healthy && config!.harnessPath) {
    const spawned = spawnHarnessServer()
    if (spawned) {
      healthy = await waitForHarness(10, 500)
    }
  }
  if (!healthy) {
    if (config!.strictMode) {
      sendToast({
        variant: "error",
        title: "Sondera",
        message: "Strict mode: harness server not available, blocking all tool calls",
        duration: 10_000,
      })
    } else {
      sendToast({
        variant: "warning",
        title: "Sondera",
        message: "Harness server not available, policy enforcement disabled",
        duration: 6_000,
      })
    }
    return null
  }

  initAuditLog(config!)
  client = c
  return client
}

const SONDERA_AGENT_ID = `opencode-${process.env.USER || "unknown"}`

function spawnHarnessServer(): boolean {
  if (!config!.harnessPath) return false

  const args: string[] = []
  if (config!.policiesPath) {
    args.push("--policy-path", config!.policiesPath)
  }
  // The harness runs deterministically (Cedar + YARA, no LLM classifiers) by default when no
  // provider is configured via ~/.sondera/env. To enable the LLM classifiers, set SONDERA_PROVIDER
  // and credentials in the env file instead of passing a flag.

  try {
    harnessProc = Bun.spawn({
      cmd: [config!.harnessPath, ...args],
      stderr: "pipe",
      stdout: "pipe",
    })
    console.error(`[sondera] spawned harness server (pid ${harnessProc.pid})`)
    return true
  } catch (err) {
    console.error(`[sondera] failed to spawn harness server:`, err)
    return false
  }
}

async function waitForHarness(retries: number, delayMs: number): Promise<boolean> {
  for (let i = 0; i < retries; i++) {
    await new Promise((r) => setTimeout(r, delayMs))
    const c = new HarnessClient(undefined, false, 2000)
    const healthy = await c.health()
    if (healthy) return true
  }
  return false
}

export const SonderaPlugin = async ({
  directory,
  serverUrl,
}: PluginContext) => {
  config = loadConfig(directory)
  initToast(serverUrl)

  return {
    "tool.execute.before": async (input: any, output: any) => {
      if (!output || typeof output.args !== "object" || output.args === null) return

      let c: HarnessClient | null
      try {
        c = await getClient()
      } catch (err) {
        console.error("[sondera] init error, allowing:", err)
        return
      }
      if (!c) return

      const args = toolArgs(input.tool, output.args ?? {})

      if (matchesAllowPattern(input.tool, args, config!.allowPatterns)) {
        recordBypass()
        return
      }

      const event = normalizeEvent(
        input.tool,
        args,
        directory,
        input.sessionID ?? input.sessionId,
        SONDERA_AGENT_ID,
        "before",
      )

      const start = performance.now()
      let result
      try {
        result = await c.adjudicate(event)
      } catch (err) {
        console.error(new AdjudicationError(err))
        recordError()
        if (config!.strictMode) {
          sendToast({
            variant: "error",
            title: "Sondera",
            message: "Strict mode: adjudication failed, blocking by default",
          })
          throw new Error("[sondera] strict mode: adjudication failed, blocking by default")
        }
        return
      }
      const durationMs = performance.now() - start

      writeAudit(event, result, config!.dryRun, durationMs)

      if (result.decision === "deny") {
        const reason = result.reason || "action denied by policy"
        if (config!.dryRun) {
          sendToast({
            variant: "warning",
            title: "Sondera (dry-run)",
            message: `Would deny: ${reason}`,
            duration: 8_000,
          })
          recordDryRunDeny(durationMs)
          return
        }
        recordDeny(durationMs)
        sendToast({
          variant: "error",
          title: "Sondera",
          message: reason,
          duration: 10_000,
        })
        throw new PolicyDenyError(result)
      }

      if (result.decision === "allow") {
        recordAllow(durationMs)
      }

      if (result.decision === "escalate") {
        recordEscalate(durationMs)
        const reason = result.reason || "action requires approval"
        const policyCtx = formatPolicyContext(result)
        const msg = policyCtx ? `${reason}\n${policyCtx}` : reason
        sendToast({
          variant: "warning",
          title: "Sondera",
          message: msg,
          duration: 10_000,
        })
      }
    },

    "tool.execute.after": async (input: any, output: any) => {
      let c: HarnessClient | null
      try {
        c = await getClient()
      } catch {
        return
      }
      if (!c) return

      const args = toolArgs(input.tool, (input.args ?? output?.args) ?? {})
      const event = normalizeEvent(
        input.tool,
        args,
        directory,
        input.sessionID ?? input.sessionId,
        SONDERA_AGENT_ID,
        "after",
      )

      try {
        await c.adjudicate(event)
      } catch (err) {
        console.error(new AdjudicationError(err))
      }
    },
  }
}

function formatPolicyContext(result: {
  annotations?: Array<{
    policy_id?: string
    description?: string
    annotations?: Record<string, string>
  }>
}): string | null {
  if (!result.annotations || result.annotations.length === 0) return null

  const parts = result.annotations
    .map((a) => {
      const lines: string[] = []
      if (a.policy_id && a.description) {
        lines.push(`[Policy: ${a.policy_id}] ${a.description}`)
      } else if (a.policy_id) {
        lines.push(`[Policy: ${a.policy_id}]`)
      } else if (a.description) {
        lines.push(a.description)
      }
      if (a.annotations) {
        for (const [key, value] of Object.entries(a.annotations)) {
          lines.push(`  ${key}: ${value}`)
        }
      }
      return lines.join("\n")
    })
    .filter((s) => s.length > 0)

  return parts.length > 0 ? parts.join("\n") : null
}

export { HarnessClient } from "./client"
export { normalizeEvent, toolArgs } from "./normalize"
export { PolicyDenyError, HarnessUnavailableError, AdjudicationError } from "./types"
export { loadConfig, matchesAllowPattern } from "./config"
export { getMetrics, resetMetrics, logSummary } from "./metrics"
export { writeAudit, closeAuditLog } from "./audit"
export { sendToast, initToast, resetToast } from "./toast"

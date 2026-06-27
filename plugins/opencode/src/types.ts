export interface ToolInput {
  tool: string
  sessionId?: string
}

export interface ToolOutput {
  args: Record<string, unknown>
  result?: unknown
}

export interface AdapterRequest {
  trajectory_id: string
  agent_id: string
  tool: string
  action: string
  args: Record<string, unknown>
  cwd?: string
  event_type: "before" | "after"
}

export interface AdjudicationResponse {
  decision: "allow" | "deny" | "escalate"
  reason?: string
  annotations?: Array<{
    policy_id?: string
    description?: string
    annotations?: Record<string, string>
  }>
}

export interface PluginContext {
  project: { path: string }
  client: unknown
  $: unknown
  directory: string
  worktree: string
  serverUrl?: URL
}

export class PolicyDenyError extends Error {
  readonly decision: "deny"
  readonly reason: string
  readonly annotations?: AdjudicationResponse["annotations"]

  constructor(response: AdjudicationResponse) {
    const reason = response.reason || "action denied by policy"
    super(`[sondera] ${reason}`)
    this.name = "PolicyDenyError"
    this.decision = "deny"
    this.reason = reason
    this.annotations = response.annotations
  }
}

export class HarnessUnavailableError extends Error {
  constructor(message: string) {
    super(`[sondera] ${message}`)
    this.name = "HarnessUnavailableError"
  }
}

export class AdjudicationError extends Error {
  readonly cause: unknown

  constructor(cause: unknown) {
    super(`[sondera] adjudication failed, allowing by default`)
    this.name = "AdjudicationError"
    this.cause = cause
  }
}

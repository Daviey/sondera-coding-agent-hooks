import { readFileSync } from "fs"

export interface SonderaConfig {
  enabled: boolean
  dryRun: boolean
  allowPatterns: RegExp[]
  auditLogPath: string | null
  strictMode: boolean
  harnessPath: string | null
  policiesPath: string | null
  adjudicateTimeoutMs: number
}

interface ProjectConfig {
  enabled?: boolean
  dryRun?: boolean
  allowPatterns?: string[]
  auditLogPath?: string
  strictMode?: boolean
  harnessPath?: string
  policiesPath?: string
  adjudicateTimeoutMs?: number
}

export function loadConfig(directory: string): SonderaConfig {
  const project = loadProjectConfig(directory)

  const enabled = process.env.SONDERA_ENABLED !== undefined
    ? process.env.SONDERA_ENABLED !== "false"
    : (project.enabled ?? true)
  const dryRun = process.env.SONDERA_DRY_RUN !== undefined
    ? (process.env.SONDERA_DRY_RUN === "1" || process.env.SONDERA_DRY_RUN === "true")
    : (project.dryRun ?? false)
  const auditLogPath = process.env.SONDERA_AUDIT_LOG ?? project.auditLogPath ?? null
  const strictMode = process.env.SONDERA_STRICT !== undefined
    ? (process.env.SONDERA_STRICT === "1" || process.env.SONDERA_STRICT === "true")
    : (project.strictMode ?? false)
  const harnessPath = process.env.SONDERA_HARNESS_PATH ?? project.harnessPath ?? null
  const policiesPath = process.env.SONDERA_POLICIES_PATH ?? project.policiesPath ?? null
  const allowPatterns = loadAllowPatterns(project.allowPatterns)
  const adjudicateTimeoutMs = process.env.SONDERA_ADJUDICATE_TIMEOUT_MS !== undefined
    ? parseInt(process.env.SONDERA_ADJUDICATE_TIMEOUT_MS, 10)
    : (project.adjudicateTimeoutMs ?? 5000)

  return { enabled, dryRun, allowPatterns, auditLogPath, strictMode, harnessPath, policiesPath, adjudicateTimeoutMs }
}

function loadProjectConfig(directory: string): ProjectConfig {
  const candidates = [
    `${directory}/.opencode/sondera.json`,
    `${directory}/sondera.json`,
  ]

  for (const path of candidates) {
    try {
      const text = readFileSync(path, "utf-8")
      if (text.trim().length > 0) {
        return JSON.parse(text) as ProjectConfig
      }
    } catch {}
  }

  return {}
}

function loadAllowPatterns(projectPatterns?: string[]): RegExp[] {
  const patterns: RegExp[] = []

  if (projectPatterns) {
    for (const p of projectPatterns) {
      try { patterns.push(new RegExp(p)) }
      catch { console.error(`[sondera] invalid allow pattern in config: ${p}`) }
    }
  }

  const raw = process.env.SONDERA_ALLOW_PATTERNS
  if (raw) {
    for (const part of raw.split(",")) {
      const trimmed = part.trim()
      if (trimmed.length === 0) continue
      try { patterns.push(new RegExp(trimmed)) }
      catch { console.error(`[sondera] invalid allow pattern: ${trimmed}`) }
    }
  }

  return patterns
}

export function matchesAllowPattern(
  tool: string,
  args: Record<string, unknown>,
  patterns: RegExp[],
): boolean {
  if (patterns.length === 0) return false

  const targets = [tool]
  if (typeof args.command === "string") targets.push(args.command)
  if (typeof args.path === "string" || typeof args.filePath === "string") {
    targets.push((args.path as string) || (args.filePath as string) || "")
  }
  if (typeof args.url === "string") targets.push(args.url)
  if (typeof args.pattern === "string") targets.push(args.pattern)
  if (typeof args.query === "string") targets.push(args.query)

  const haystack = targets.join(" ")
  return patterns.some((p) => p.test(haystack))
}

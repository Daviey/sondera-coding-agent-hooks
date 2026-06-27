import { describe, expect, it, beforeEach, afterEach } from "bun:test"
import { loadConfig, matchesAllowPattern } from "./config"
import { mkdirSync, rmSync, writeFileSync } from "fs"

const TMP_DIR = "/tmp/sondera-test-config"

describe("loadConfig", () => {
  beforeEach(() => {
    delete process.env.SONDERA_ENABLED
    delete process.env.SONDERA_DRY_RUN
    delete process.env.SONDERA_ALLOW_PATTERNS
    delete process.env.SONDERA_AUDIT_LOG
    delete process.env.SONDERA_STRICT
    try { mkdirSync(TMP_DIR, { recursive: true }) } catch {}
  })

  afterEach(() => {
    try { rmSync(TMP_DIR, { recursive: true, force: true }) } catch {}
    delete process.env.SONDERA_ALLOW_PATTERNS
    delete process.env.SONDERA_AUDIT_LOG
  })

  it("returns defaults", () => {
    const config = loadConfig("/tmp")
    expect(config.enabled).toBe(true)
    expect(config.dryRun).toBe(false)
    expect(config.allowPatterns).toEqual([])
    expect(config.auditLogPath).toBeNull()
  })

  it("respects SONDERA_ENABLED=false", () => {
    process.env.SONDERA_ENABLED = "false"
    const config = loadConfig("/tmp")
    expect(config.enabled).toBe(false)
  })

  it("enables dry run with SONDERA_DRY_RUN=1", () => {
    process.env.SONDERA_DRY_RUN = "1"
    const config = loadConfig("/tmp")
    expect(config.dryRun).toBe(true)
  })

  it("enables dry run with SONDERA_DRY_RUN=true", () => {
    process.env.SONDERA_DRY_RUN = "true"
    const config = loadConfig("/tmp")
    expect(config.dryRun).toBe(true)
  })

  it("parses allow patterns", () => {
    process.env.SONDERA_ALLOW_PATTERNS = "git status,ls .*,echo"
    const config = loadConfig("/tmp")
    expect(config.allowPatterns).toHaveLength(3)
    expect(config.allowPatterns[0].source).toBe("git status")
    expect(config.allowPatterns[1].source).toBe("ls .*")
  })

  it("skips invalid allow patterns", () => {
    process.env.SONDERA_ALLOW_PATTERNS = "valid,([invalid,also-valid"
    const config = loadConfig("/tmp")
    expect(config.allowPatterns).toHaveLength(2)
  })

  it("sets audit log path", () => {
    process.env.SONDERA_AUDIT_LOG = "/tmp/sondera-audit.jsonl"
    const config = loadConfig("/tmp")
    expect(config.auditLogPath).toBe("/tmp/sondera-audit.jsonl")
  })

  it("handles empty allow patterns", () => {
    process.env.SONDERA_ALLOW_PATTERNS = ""
    const config = loadConfig("/tmp")
    expect(config.allowPatterns).toEqual([])
  })

  it("handles comma-only allow patterns", () => {
    process.env.SONDERA_ALLOW_PATTERNS = ",,,"
    const config = loadConfig("/tmp")
    expect(config.allowPatterns).toEqual([])
  })

  it("loads strictMode to false", () => {
    const config = loadConfig("/tmp")
    expect(config.strictMode).toBe(false)
  })

  it("enables strict mode via SONDERA_STRICT=1", () => {
    process.env.SONDERA_STRICT = "1"
    const config = loadConfig("/tmp")
    expect(config.strictMode).toBe(true)
  })

  it("loads project config from .opencode/sondera.json", () => {
    mkdirSync(`${TMP_DIR}/.opencode`, { recursive: true })
    writeFileSync(
      `${TMP_DIR}/.opencode/sondera.json`,
      JSON.stringify({ enabled: false, dryRun: true, allowPatterns: ["git .*"] }),
    )
    const config = loadConfig(TMP_DIR)
    expect(config.enabled).toBe(false)
    expect(config.dryRun).toBe(true)
    expect(config.allowPatterns).toHaveLength(1)
    expect(config.allowPatterns[0].source).toBe("git .*")
  })

  it("loads project config from sondera.json", () => {
    writeFileSync(
      `${TMP_DIR}/sondera.json`,
      JSON.stringify({ strictMode: true, auditLogPath: "/tmp/audit.jsonl" }),
    )
    const config = loadConfig(TMP_DIR)
    expect(config.strictMode).toBe(true)
    expect(config.auditLogPath).toBe("/tmp/audit.jsonl")
  })

  it("prefers .opencode/sondera.json over sondera.json", () => {
    mkdirSync(`${TMP_DIR}/.opencode`, { recursive: true })
    writeFileSync(`${TMP_DIR}/.opencode/sondera.json`, JSON.stringify({ enabled: false }))
    writeFileSync(`${TMP_DIR}/sondera.json`, JSON.stringify({ enabled: true }))
    const config = loadConfig(TMP_DIR)
    expect(config.enabled).toBe(false)
  })

  it("env vars override project config", () => {
    writeFileSync(
      `${TMP_DIR}/sondera.json`,
      JSON.stringify({ enabled: true }),
    )
    process.env.SONDERA_ENABLED = "false"
    const config = loadConfig(TMP_DIR)
    expect(config.enabled).toBe(false)
  })

  it("ignores invalid project config files", () => {
    mkdirSync(`${TMP_DIR}/.opencode`, { recursive: true })
    writeFileSync(`${TMP_DIR}/.opencode/sondera.json`, "not json")
    const config = loadConfig(TMP_DIR)
    expect(config.enabled).toBe(true)
  })

  it("merges project allow patterns with env allow patterns", () => {
    writeFileSync(
      `${TMP_DIR}/sondera.json`,
      JSON.stringify({ allowPatterns: ["git .*"] }),
    )
    process.env.SONDERA_ALLOW_PATTERNS = "echo,ls"
    const config = loadConfig(TMP_DIR)
    expect(config.allowPatterns).toHaveLength(3)
  })
})

describe("matchesAllowPattern", () => {
  it("returns false with no patterns", () => {
    expect(matchesAllowPattern("bash", { command: "ls" }, [])).toBe(false)
  })

  it("matches bash command", () => {
    const patterns = [/\bgit status\b/]
    expect(matchesAllowPattern("bash", { command: "git status" }, patterns)).toBe(true)
    expect(matchesAllowPattern("bash", { command: "git push" }, patterns)).toBe(false)
  })

  it("matches tool name", () => {
    const patterns = [/\bglob\b/]
    expect(matchesAllowPattern("glob", { pattern: "**/*.ts" }, patterns)).toBe(true)
    expect(matchesAllowPattern("grep", { pattern: "TODO" }, patterns)).toBe(false)
  })

  it("matches url", () => {
    const patterns = [/https:\/\/docs\.example\.com/]
    expect(matchesAllowPattern("webfetch", { url: "https://docs.example.com/api" }, patterns)).toBe(true)
    expect(matchesAllowPattern("webfetch", { url: "https://evil.com" }, patterns)).toBe(false)
  })

  it("matches path", () => {
    const patterns = [/\/home\/user\/safe/]
    expect(matchesAllowPattern("read", { path: "/home/user/safe/file.ts" }, patterns)).toBe(true)
    expect(matchesAllowPattern("read", { path: "/etc/passwd" }, patterns)).toBe(false)
  })

  it("matches any field in the combined haystack", () => {
    const patterns = [/TODO/]
    expect(matchesAllowPattern("grep", { pattern: "TODO" }, patterns)).toBe(true)
    expect(matchesAllowPattern("grep", { pattern: "FIXME" }, patterns)).toBe(false)
  })
})

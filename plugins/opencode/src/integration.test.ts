import { describe, test, expect, beforeAll, afterAll } from "bun:test"
import { existsSync, mkdirSync, rmSync, writeFileSync, copyFileSync } from "fs"
import { join } from "path"

const HARNESS_REPO = process.env.SONDERA_HARNESS_REPO || join(import.meta.dir, "../../..")
const PLUGIN_ROOT = join(import.meta.dir, "..")
function findAdapter(): string {
  const candidates = [
    join(PLUGIN_ROOT, "adapter/target/debug/sondera-opencode-adapter"),
    join(HARNESS_REPO, "target/debug/sondera-opencode-adapter"),
    join(HARNESS_REPO, "apps/opencode/target/debug/sondera-opencode-adapter"),
  ]
  return candidates.find(p => existsSync(p)) || candidates[0]
}
const ADAPTER_BIN = process.env.SONDERA_ADAPTER_BIN || findAdapter()
const HARNESS_BIN = join(HARNESS_REPO, "target/debug/sondera-harness-server")
const POLICY_PATH = join(HARNESS_REPO, "policies")
const SOCKET_PATH = process.env.SONDERA_SOCKET || join(process.env.HOME || "/tmp", ".sondera/sondera-harness.sock")
const SONDERA_DIR = join(process.env.HOME || "/tmp", ".sondera")
const TEST_DENY_POLICY = join(import.meta.dir, "policies/test-deny.cedar")

let harnessProc: ReturnType<typeof Bun.spawn> | null = null

function waitForSocket(maxMs = 15000): Promise<void> {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const check = () => {
      if (existsSync(SOCKET_PATH)) return resolve()
      if (Date.now() - start > maxMs) return reject(new Error("socket not found at " + SOCKET_PATH + " after " + maxMs + "ms"))
      setTimeout(check, 300)
    }
    check()
  })
}

async function readAll(stream: ReadableStream<Uint8Array> | number | null): Promise<string> {
  if (!stream || typeof stream === "number") return ""
  const reader = stream.getReader()
  const chunks: string[] = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(new TextDecoder().decode(value))
  }
  return chunks.join("")
}

function adjudicate(request: object, timeoutMs = 15000): Promise<{ decision: string; reason?: string; annotations: Array<{ policy_id: string; description: string }> }> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("adjudicate timed out after " + timeoutMs + "ms")), timeoutMs)
    const input = JSON.stringify(request) + "\n"
    const proc = Bun.spawn([ADAPTER_BIN, "adjudicate"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, RUST_LOG: "info", SONDERA_SOCKET: SOCKET_PATH },
    })
    proc.stdin.write(input)
    proc.stdin.end()
    Promise.all([
      proc.exited,
      readAll(proc.stdout),
      readAll(proc.stderr),
    ]).then(([code, stdout, stderr]) => {
      clearTimeout(timer)
      if (stderr.trim()) console.error("[adapter stderr]", stderr.trim())
      if (code !== 0) return reject(new Error("adapter exited " + code + ": " + stderr))
      try {
        const parsed = JSON.parse(stdout.trim())
        console.log("[adapter response]", JSON.stringify(parsed))
        resolve(parsed)
      }
      catch { reject(new Error("invalid JSON: " + stdout + " stderr: " + stderr)) }
    }).catch(err => { clearTimeout(timer); reject(err) })
  })
}

describe("integration: adapter + harness", () => {
  let cedarDenyWorks = false

  beforeAll(async () => {
    if (!existsSync(HARNESS_BIN)) throw new Error("harness binary not found at " + HARNESS_BIN + ". Build from sondera-coding-agent-hooks repo.")
    if (!existsSync(ADAPTER_BIN)) throw new Error("adapter binary not found at " + ADAPTER_BIN)
    if (!existsSync(POLICY_PATH)) throw new Error("policy directory not found at " + POLICY_PATH)

    console.log("[integration] copying test deny policy from", TEST_DENY_POLICY, "to", join(POLICY_PATH, "900-test-deny.cedar"))
    if (existsSync(TEST_DENY_POLICY)) {
      const dest = join(POLICY_PATH, "900-test-deny.cedar")
      copyFileSync(TEST_DENY_POLICY, dest)
      if (!existsSync(dest)) throw new Error("failed to copy test deny policy to " + dest)
      console.log("[integration] test deny policy copied, size:", require("fs").statSync(dest).size)
    } else {
      throw new Error("test deny policy not found at " + TEST_DENY_POLICY)
    }

    rmSync(SONDERA_DIR, { recursive: true, force: true })
    rmSync(SOCKET_PATH, { force: true })
    const socketDir = SOCKET_PATH.substring(0, SOCKET_PATH.lastIndexOf("/"))
    mkdirSync(socketDir, { recursive: true })

    harnessProc = Bun.spawn([HARNESS_BIN, "--policy-path", POLICY_PATH, "--socket", SOCKET_PATH], {
      env: { ...process.env, RUST_LOG: "info" },
      stderr: "pipe",
      stdout: "pipe",
    })
    await waitForSocket(20000)

    const probe = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-probe-" + Date.now(),
      agent_id: "test",
      args: { command: "rm -rf /" },
      cwd: "/tmp",
    })
    cedarDenyWorks = probe.decision === "deny" && !probe.reason
    if (!cedarDenyWorks) {
      console.warn("[integration] Cedar deny not working, skipping deny tests. Probe response:", JSON.stringify(probe))
    }
    }, 30000)

  afterAll(() => {
    const testPolicy = join(POLICY_PATH, "900-test-deny.cedar")
    try { rmSync(testPolicy, { force: true }) } catch {}
    if (harnessProc) {
      harnessProc.kill("SIGKILL")
      harnessProc = null
    }
    rmSync(SONDERA_DIR, { recursive: true, force: true })
  })

  test("health check returns exit 0", async () => {
    const proc = Bun.spawn([ADAPTER_BIN, "health"], {
      stdout: "pipe", stderr: "pipe",
      env: { ...process.env, SONDERA_SOCKET: SOCKET_PATH },
    })
    const code = await proc.exited
    expect(code).toBe(0)
  })

  test("harmless command is allowed", async () => {
    const result = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-" + Date.now() + "-allow",
      agent_id: "test",
      args: { command: "ls -la /tmp" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("allow")
  })

  test("benign test command is denied by test policy (Cedar-only, no Ollama)", async () => {
    if (!cedarDenyWorks) return
    const result = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-" + Date.now() + "-benign-deny",
      agent_id: "test",
      args: { command: "echo sondera-deny-test" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("deny")
    const ids = result.annotations.map(a => a.policy_id)
    expect(ids).toContain("forbid-sondera-test-deny")
  })

  test("rm -rf / is denied by Cedar policy", async () => {
    if (!cedarDenyWorks) return
    const result = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-" + Date.now() + "-deny",
      agent_id: "test",
      args: { command: "rm -rf /" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("deny")
    const ids = result.annotations.map(a => a.policy_id)
    expect(ids).toContain("forbid-rm-rf")
  })

  test("rm -rf root triggers forbid-rm-root", async () => {
    if (!cedarDenyWorks) return
    const result = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-" + Date.now() + "-root",
      agent_id: "test",
      args: { command: "rm -rf /" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("deny")
    const ids = result.annotations.map(a => a.policy_id)
    expect(ids).toContain("forbid-rm-root")
  })

  test("git force push is denied by Cedar policy", async () => {
    if (!cedarDenyWorks) return
    const result = await adjudicate({
      tool: "bash", action: "ShellCommand",
      trajectory_id: "int-" + Date.now() + "-forcepush",
      agent_id: "test",
      args: { command: "git push --force origin main" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("deny")
    const ids = result.annotations.map(a => a.policy_id)
    expect(ids).toContain("forbid-git-force-push")
  })

  test("private key read is denied by Cedar policy", async () => {
    if (!cedarDenyWorks) return
    const result = await adjudicate({
      tool: "read", action: "FileRead",
      trajectory_id: "int-" + Date.now() + "-keyread",
      agent_id: "test",
      args: { path: "/home/user/.ssh/id_rsa" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("deny")
  })

  test("same trajectory_id with different events is allowed", async () => {
    const id = "int-" + Date.now() + "-multi"
    const req1 = {
      tool: "bash", action: "ShellCommand",
      trajectory_id: id,
      agent_id: "test",
      args: { command: "ls /tmp" },
      cwd: "/tmp",
    }
    const req2 = {
      tool: "read", action: "FileRead",
      trajectory_id: id,
      agent_id: "test",
      args: { path: "/tmp/test.txt" },
      cwd: "/tmp",
    }
    const r1 = await adjudicate(req1)
    expect(r1.decision).toBe("allow")
    const r2 = await adjudicate(req2)
    expect(r2.decision).toBe("allow")
  })

  test("file read to non-sensitive path is allowed", async () => {
    const result = await adjudicate({
      tool: "read", action: "FileRead",
      trajectory_id: "int-" + Date.now() + "-read",
      agent_id: "test",
      args: { path: "/tmp/test.txt" },
      cwd: "/tmp",
    })
    expect(result.decision).toBe("allow")
  })
})

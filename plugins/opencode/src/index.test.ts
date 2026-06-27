import { describe, expect, it, mock, beforeEach, afterEach } from "bun:test"
import { PolicyDenyError } from "./types"

const origSpawn = Bun.spawn

beforeEach(() => {
  delete process.env.SONDERA_ENABLED
  delete process.env.SONDERA_ADAPTER_PATH
  delete process.env.SONDERA_DRY_RUN
  delete process.env.SONDERA_ALLOW_PATTERNS
  delete process.env.SONDERA_AUDIT_LOG
  delete process.env.SONDERA_STRICT
})

afterEach(() => {
  Bun.spawn = origSpawn as any
})

function makeStdout(text: string) {
  const encoder = new TextEncoder()
  const data = encoder.encode(text)
  return new ReadableStream({
    start(controller) {
      controller.enqueue(data)
      controller.close()
    },
  })
}

function mockSpawnOnce(exitCode: number, stdout: string) {
  Bun.spawn = mock(() => ({
    stdin: { write: mock(() => {}), end: mock(() => {}) },
    stdout: makeStdout(stdout),
    stderr: makeStdout(""),
    exited: Promise.resolve(exitCode),
  })) as any
}

function mockSpawnHealthyThenRespond(healthExit: number, adjExit: number, adjStdout: string) {
  let callCount = 0
  Bun.spawn = mock(() => {
    callCount++
    if (callCount === 1) {
      return {
        stdin: { write: mock(() => {}), end: mock(() => {}) },
        stdout: makeStdout(""),
        stderr: makeStdout(""),
        exited: Promise.resolve(healthExit),
      }
    }
    if (callCount === 2) {
      return {
        stdin: { write: mock(() => {}), end: mock(() => {}) },
        stdout: makeStdout(""),
        stderr: makeStdout(""),
        exited: Promise.resolve(1),
        exitCode: 1,
      }
    }
    return {
      stdin: { write: mock(() => {}), end: mock(() => {}) },
      stdout: makeStdout(adjStdout),
      stderr: makeStdout(""),
      exited: Promise.resolve(adjExit),
    }
  }) as any
}

async function makePlugin() {
  const mod = await import("./index")
  mod._reset()
  return mod.SonderaPlugin({
    directory: "/tmp",
    project: { path: "/tmp" },
    client: {} as any,
    $: {} as any,
    worktree: "/tmp",
  })
}

describe("SonderaPlugin", () => {
  it("blocks execution on deny", async () => {
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "deny", reason: "forbidden" }))

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "rm -rf /" } }

    try {
      await plugin["tool.execute.before"](input, output)
      expect.unreachable("should have thrown")
    } catch (err: any) {
      expect(err).toBeInstanceOf(PolicyDenyError)
      expect(err.reason).toBe("forbidden")
      expect(err.decision).toBe("deny")
    }
  })

  it("blocks execution with policy annotations on deny", async () => {
    const response = {
      decision: "deny",
      reason: "policy violation",
      annotations: [
        { policy_id: "P001", description: "No destructive commands" },
      ],
    }
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify(response))

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "rm -rf /" } }

    try {
      await plugin["tool.execute.before"](input, output)
      expect.unreachable("should have thrown")
    } catch (err: any) {
      expect(err).toBeInstanceOf(PolicyDenyError)
      expect(err.reason).toBe("policy violation")
      expect(err.annotations).toHaveLength(1)
      expect(err.annotations![0].policy_id).toBe("P001")
    }
  })

  it("allows execution on allow", async () => {
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "allow" }))

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.before"](input, output)
  })

  it("allows execution on escalate (logs warning)", async () => {
    const healthOutput = createMockOutputStream()
    healthOutput.close()
    const streamOutput = createMockOutputStream()

    let callIdx = 0
    Bun.spawn = mock(() => {
      callIdx++
      if (callIdx === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: healthOutput.stream,
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      return {
        stdin: {
          write: mock(() => {
            streamOutput.push(JSON.stringify({ decision: "escalate", reason: "suspicious" }) + "\n")
          }),
          end: mock(() => {}),
        },
        stdout: streamOutput.stream,
        stderr: makeStdout(""),
        exitCode: null,
        exited: new Promise(() => {}),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    const plugin = await makePlugin()

    await plugin["tool.execute.before"](
      { tool: "bash", sessionId: "s1" },
      { args: { command: "ls" } },
    )

    const mod = await import("./index")
    const m = mod.getMetrics()
    expect(m.escalated).toBe(1)
  })

  it("allows execution when adapter exits non-zero (fail open)", async () => {
    mockSpawnHealthyThenRespond(0, 1, "")

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.before"](input, output)
  })

  it("allows execution when spawn throws (fail open)", async () => {
    let callCount = 0
    Bun.spawn = mock(() => {
      callCount++
      if (callCount === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      throw new Error("ENOENT: adapter not found")
    }) as any

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.before"](input, output)
  })

  it("after hook does not throw on deny", async () => {
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "deny" }))

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.after"](input, output)
  })

  it("after hook does not throw on spawn failure", async () => {
    let callCount = 0
    Bun.spawn = mock(() => {
      callCount++
      if (callCount === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      throw new Error("spawn failed")
    }) as any

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.after"](input, output)
  })

  it("disables when SONDERA_ENABLED=false", async () => {
    process.env.SONDERA_ENABLED = "false"

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.before"](input, output)
    await plugin["tool.execute.after"](input, output)
  })

  it("disables when health check fails", async () => {
    Bun.spawn = mock(() => ({
      stdin: { write: mock(() => {}), end: mock(() => {}) },
      stdout: makeStdout(""),
      stderr: makeStdout(""),
      exited: Promise.resolve(1),
    })) as any

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "ls" } }

    await plugin["tool.execute.before"](input, output)
    await plugin["tool.execute.after"](input, output)
  })

  it("auto-spawns harness with --policy-path when configured", async () => {
    const spawnCalls: string[][] = []
    let callIdx = 0
    Bun.spawn = mock((opts: any) => {
      const cmd = opts?.cmd || []
      spawnCalls.push(cmd)
      callIdx++
      if (callIdx === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: Promise.resolve(1),
        }
      }
      if (callIdx === 2) {
        return {
          pid: 12345,
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: new Promise(() => {}),
        }
      }
      if (callIdx === 3) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      const output = createMockOutputStream()
      return {
        stdin: {
          write: mock((data: string) => {
            output.push(JSON.stringify({ decision: "allow" }) + "\n")
          }),
          end: mock(() => {}),
        },
        stdout: output.stream,
        stderr: makeStdout(""),
        exitCode: null,
        exited: new Promise(() => {}),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    process.env.SONDERA_HARNESS_PATH = "/usr/local/bin/harness"
    process.env.SONDERA_POLICIES_PATH = "/tmp/policies"

    const mod = await import("./index")
    mod._reset()
    const plugin = await mod.SonderaPlugin({
      directory: "/tmp",
      project: { path: "/tmp" },
      client: {} as any,
      $: {} as any,
      worktree: "/tmp",
    })

    await plugin["tool.execute.before"](
      { tool: "bash", sessionId: "s1" },
      { args: { command: "ls" } },
    )

    const harnessSpawn = spawnCalls[1]
    expect(harnessSpawn).not.toContain("--deterministic-only")
    expect(harnessSpawn).toContain("--policy-path")
    expect(harnessSpawn).toContain("/tmp/policies")

    delete process.env.SONDERA_HARNESS_PATH
    delete process.env.SONDERA_POLICIES_PATH
  })

})

function createMockOutputStream() {
  let controller: ReadableStreamDefaultController<Uint8Array>
  const stream = new ReadableStream<Uint8Array>({
    start(c) { controller = c },
  })
  return {
    stream,
    push(text: string) { controller.enqueue(new TextEncoder().encode(text)) },
    close() { controller.close() },
  }
}

describe("SonderaPlugin (stream mode)", () => {
  it("uses persistent stream for multiple tool calls", async () => {
    const healthOutput = createMockOutputStream()
    healthOutput.close()
    const streamOutput = createMockOutputStream()

    let callIdx = 0
    Bun.spawn = mock(() => {
      callIdx++
      if (callIdx === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: healthOutput.stream,
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      return {
        stdin: {
          write: mock((data: string) => {
            streamOutput.push(JSON.stringify({ decision: "allow" }) + "\n")
          }),
          end: mock(() => {}),
        },
        stdout: streamOutput.stream,
        stderr: makeStdout(""),
        exitCode: null,
        exited: new Promise(() => {}),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    const plugin = await makePlugin()

    await plugin["tool.execute.before"](
      { tool: "bash", sessionId: "s1" },
      { args: { command: "ls" } },
    )
    await plugin["tool.execute.before"](
      { tool: "read", sessionId: "s1" },
      { args: { filePath: "/foo.ts" } },
    )

    expect(callIdx).toBe(2)
  })

  it("blocks on deny via stream mode", async () => {
    const healthOutput = createMockOutputStream()
    healthOutput.close()
    const streamOutput = createMockOutputStream()

    let callIdx = 0
    Bun.spawn = mock(() => {
      callIdx++
      if (callIdx === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: healthOutput.stream,
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      return {
        stdin: {
          write: mock((data: string) => {
            streamOutput.push(JSON.stringify({ decision: "deny", reason: "blocked" }) + "\n")
          }),
          end: mock(() => {}),
        },
        stdout: streamOutput.stream,
        stderr: makeStdout(""),
        exitCode: null,
        exited: new Promise(() => {}),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    const plugin = await makePlugin()

    try {
      await plugin["tool.execute.before"](
        { tool: "bash", sessionId: "s1" },
        { args: { command: "rm -rf /" } },
      )
      expect.unreachable("should have thrown")
    } catch (err: any) {
      expect(err).toBeInstanceOf(PolicyDenyError)
      expect(err.reason).toBe("blocked")
    }
  })
})

describe("SonderaPlugin (dry-run mode)", () => {
  beforeEach(() => {
    delete process.env.SONDERA_DRY_RUN
    delete process.env.SONDERA_ALLOW_PATTERNS
    delete process.env.SONDERA_STRICT
  })

  it("logs deny but does not block in dry-run mode", async () => {
    process.env.SONDERA_DRY_RUN = "1"
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "deny", reason: "would block" }))

    const fetchCalls: any[] = []
    const origFetch = globalThis.fetch
    globalThis.fetch = mock((url: string, opts: any) => {
      fetchCalls.push({ url, opts })
      return Promise.resolve(new Response())
    }) as any

    const mod = await import("./index")
    mod._reset()
    const plugin = await mod.SonderaPlugin({
      directory: "/tmp",
      project: { path: "/tmp" },
      client: {} as any,
      $: {} as any,
      worktree: "/tmp",
      serverUrl: new URL("http://localhost:12345"),
    })

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "rm -rf /" } }

    await plugin["tool.execute.before"](input, output)

    expect(fetchCalls.length).toBeGreaterThanOrEqual(1)
    const toastCall = fetchCalls.find((c) => c.url.includes("show-toast"))
    expect(toastCall).toBeDefined()
    const body = JSON.parse(toastCall.opts.body)
    expect(body.message).toContain("Would deny")

    globalThis.fetch = origFetch
  })
})

describe("SonderaPlugin (strict mode)", () => {
  beforeEach(() => {
    delete process.env.SONDERA_DRY_RUN
    delete process.env.SONDERA_ALLOW_PATTERNS
    delete process.env.SONDERA_STRICT
  })

  it("blocks on adjudication failure in strict mode", async () => {
    process.env.SONDERA_STRICT = "1"
    let callCount = 0
    Bun.spawn = mock(() => {
      callCount++
      if (callCount === 1) {
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: makeStdout(""),
          stderr: makeStdout(""),
          exited: Promise.resolve(0),
        }
      }
      throw new Error("ENOENT")
    }) as any

    const plugin = await makePlugin()

    try {
      await plugin["tool.execute.before"](
        { tool: "bash", sessionId: "s1" },
        { args: { command: "ls" } },
      )
      expect.unreachable("should have thrown")
    } catch (err: any) {
      expect(err.message).toContain("strict mode")
    }
  })
})

describe("SonderaPlugin (allow pattern bypass)", () => {
  beforeEach(() => {
    delete process.env.SONDERA_DRY_RUN
    delete process.env.SONDERA_ALLOW_PATTERNS
    delete process.env.SONDERA_STRICT
  })

  it("skips adjudication when tool matches allow pattern", async () => {
    process.env.SONDERA_ALLOW_PATTERNS = "\\bgit status\\b"
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "deny", reason: "blocked" }))

    const plugin = await makePlugin()

    const input = { tool: "bash", sessionId: "s1" }
    const output = { args: { command: "git status" } }

    await plugin["tool.execute.before"](input, output)
  })

  it("still blocks non-matching commands", async () => {
    process.env.SONDERA_ALLOW_PATTERNS = "\\bgit status\\b"
    mockSpawnHealthyThenRespond(0, 0, JSON.stringify({ decision: "deny", reason: "blocked" }))

    const plugin = await makePlugin()

    try {
      await plugin["tool.execute.before"](
        { tool: "bash", sessionId: "s1" },
        { args: { command: "rm -rf /" } },
      )
      expect.unreachable("should have thrown")
    } catch (err: any) {
      expect(err).toBeInstanceOf(PolicyDenyError)
    }
  })
})

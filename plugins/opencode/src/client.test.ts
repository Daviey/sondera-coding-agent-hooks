import { describe, expect, it, mock, beforeEach, afterEach } from "bun:test"
import { HarnessClient } from "./client"

const origSpawn = Bun.spawn

beforeEach(() => {
  Bun.spawn = origSpawn as any
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

function makeMockSpawn(exitCode: number, stdout: string, stderr: string = "") {
  return mock(() => ({
    stdin: {
      write: mock(() => {}),
      end: mock(() => {}),
    },
    stdout: makeStdout(stdout),
    stderr: makeStdout(stderr),
    exited: Promise.resolve(exitCode),
  }))
}

describe("HarnessClient (oneshot mode)", () => {
  describe("constructor", () => {
    it("uses provided binaryPath", () => {
      const c = new HarnessClient("/usr/local/bin/adapter")
      expect((c as any).binaryPath).toBe("/usr/local/bin/adapter")
    })

    it("falls back to SONDERA_ADAPTER_PATH env", () => {
      process.env.SONDERA_ADAPTER_PATH = "/custom/adapter"
      const c = new HarnessClient()
      expect((c as any).binaryPath).toBe("/custom/adapter")
      delete process.env.SONDERA_ADAPTER_PATH
    })

    it("falls back to default path under HOME", () => {
      delete process.env.SONDERA_ADAPTER_PATH
      const c = new HarnessClient()
      const home = process.env.HOME || "/root"
      expect((c as any).binaryPath).toBe(`${home}/.local/bin/sondera-opencode-adapter`)
    })
  })

  describe("adjudicate", () => {
    it("returns allow on successful allow response", async () => {
      const mockSpawn = makeMockSpawn(0, JSON.stringify({ decision: "allow" }))
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: { command: "ls" },
        event_type: "before",
      })

      expect(result.decision).toBe("allow")
      expect(mockSpawn).toHaveBeenCalledTimes(1)
    })

    it("returns deny when harness denies", async () => {
      const response = { decision: "deny", reason: "blocked" }
      const mockSpawn = makeMockSpawn(0, JSON.stringify(response))
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: { command: "rm -rf /" },
        event_type: "before",
      })

      expect(result.decision).toBe("deny")
      expect(result.reason).toBe("blocked")
    })

    it("returns allow when adapter exits non-zero (fail open)", async () => {
      const mockSpawn = makeMockSpawn(1, "", "Error: connection refused")
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: {},
        event_type: "before",
      })

      expect(result.decision).toBe("allow")
    })

    it("returns allow when adapter returns invalid JSON (fail open)", async () => {
      const mockSpawn = makeMockSpawn(0, "not json at all")
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: {},
        event_type: "before",
      })

      expect(result.decision).toBe("allow")
    })

    it("returns escalate with reason", async () => {
      const response = { decision: "escalate", reason: "sensitive operation" }
      const mockSpawn = makeMockSpawn(0, JSON.stringify(response))
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "write",
        action: "FileWrite",
        args: { path: "/etc/passwd" },
        event_type: "before",
      })

      expect(result.decision).toBe("escalate")
      expect(result.reason).toBe("sensitive operation")
    })

    it("returns response with annotations", async () => {
      const response = {
        decision: "deny",
        reason: "policy violation",
        annotations: [
          { policy_id: "P001", description: "No shell access" },
        ],
      }
      const mockSpawn = makeMockSpawn(0, JSON.stringify(response))
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/bin/adapter", true)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: {},
        event_type: "before",
      })

      expect(result.decision).toBe("deny")
      expect(result.annotations).toHaveLength(1)
      expect(result.annotations![0].policy_id).toBe("P001")
    })

    it("writes JSON to stdin and ends it", async () => {
      const stdinWrite = mock(() => {})
      const stdinEnd = mock(() => {})
      Bun.spawn = mock(() => ({
        stdin: { write: stdinWrite, end: stdinEnd },
        stdout: makeStdout('{"decision":"allow"}'),
        stderr: makeStdout(""),
        exited: Promise.resolve(0),
      })) as any

      const c = new HarnessClient("/bin/adapter", true)
      await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: { command: "ls" },
        event_type: "before",
      })

      expect(stdinWrite).toHaveBeenCalledTimes(1)
      const calls = stdinWrite.mock.calls as unknown as string[][]
      const written = calls[0]?.[0] ?? ""
      const parsed = JSON.parse(written)
      expect(parsed.trajectory_id).toBe("t1")
      expect(parsed.args.command).toBe("ls")
      expect(stdinEnd).toHaveBeenCalledTimes(1)
    })

    it("spawns with correct binary and command", async () => {
      const mockSpawn = makeMockSpawn(0, '{"decision":"allow"}')
      Bun.spawn = mockSpawn as any

      const c = new HarnessClient("/custom/adapter-bin", true)
      await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: {},
        event_type: "before",
      })

      const calls = mockSpawn.mock.calls as unknown as Record<string, unknown>[][]
      const call = calls[0]?.[0] ?? {}
      expect(call.cmd).toEqual(["/custom/adapter-bin", "adjudicate"])
    })

    it("returns allow on oneshot timeout", async () => {
      let resolveExited: (code: number) => void
      const exitedPromise = new Promise<number>((r) => { resolveExited = r })
      const mockSpawn = mock(() => {
        setTimeout(() => resolveExited(0), 500)
        return {
          stdin: { write: mock(() => {}), end: mock(() => {}) },
          stdout: new ReadableStream({ start(c) {} }),
          stderr: new ReadableStream({ start(c) {} }),
          exited: exitedPromise,
          killed: false,
          kill: mock(() => {}),
        }
      }) as any
      Bun.spawn = mockSpawn

      const c = new HarnessClient("/bin/adapter", true, 50)
      const result = await c.adjudicate({
        trajectory_id: "t1",
        agent_id: "a1",
        tool: "bash",
        action: "ShellCommand",
        args: {},
        event_type: "before",
      })

      expect(result.decision).toBe("allow")
    })

    it("passes timeoutMs to constructor", () => {
      const c = new HarnessClient("/bin/adapter", true, 3000)
      expect((c as any).timeoutMs).toBe(3000)
    })
  })

  describe("health", () => {
    it("returns true when adapter exits 0", async () => {
      Bun.spawn = mock(() => ({
        stdout: makeStdout(""),
        stderr: makeStdout(""),
        exited: Promise.resolve(0),
      })) as any

      const c = new HarnessClient("/bin/adapter", true)
      expect(await c.health()).toBe(true)
    })

    it("returns false when adapter exits non-zero", async () => {
      Bun.spawn = mock(() => ({
        stdout: makeStdout(""),
        stderr: makeStdout(""),
        exited: Promise.resolve(1),
      })) as any

      const c = new HarnessClient("/bin/adapter", true)
      expect(await c.health()).toBe(false)
    })

    it("returns false when spawn throws", async () => {
      Bun.spawn = mock(() => {
        throw new Error("ENOENT")
      }) as any

      const c = new HarnessClient("/nonexistent", true)
      expect(await c.health()).toBe(false)
    })
  })
})

function createMockOutputStream() {
  let controller: ReadableStreamDefaultController<Uint8Array>
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c
    },
  })
  return {
    stream,
    push(text: string) {
      controller.enqueue(new TextEncoder().encode(text))
    },
    close() {
      controller.close()
    },
  }
}

describe("HarnessClient (stream mode)", () => {
  it("uses persistent stream process for multiple calls", async () => {
    const output = createMockOutputStream()
    let resolveExited: (code: number) => void
    const exitedPromise = new Promise<number>((r) => {
      resolveExited = r
    })

    const writtenData: string[] = []
    const mockProc = {
      stdin: {
        write: mock((data: string) => {
          writtenData.push(data.trim())
          output.push(JSON.stringify({ decision: "allow" }) + "\n")
        }),
        end: mock(() => {}),
      },
      stdout: output.stream,
      stderr: new ReadableStream({ start(c) { c.close() } }),
      exitCode: null as number | null,
      exited: exitedPromise,
      killed: false,
      kill: mock(() => {
        mockProc.exitCode = 1
        output.close()
        resolveExited(1)
      }),
    }

    let spawnCount = 0
    Bun.spawn = mock(() => {
      spawnCount++
      return mockProc
    }) as any

    const c = new HarnessClient("/bin/adapter")
    const r1 = await c.adjudicate({
      trajectory_id: "t1", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: { command: "ls" }, event_type: "before",
    })
    const r2 = await c.adjudicate({
      trajectory_id: "t2", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: { command: "pwd" }, event_type: "before",
    })

    expect(r1.decision).toBe("allow")
    expect(r2.decision).toBe("allow")
    expect(spawnCount).toBe(1)
    expect(writtenData).toHaveLength(2)
    expect(JSON.parse(writtenData[0]).trajectory_id).toBe("t1")
    expect(JSON.parse(writtenData[1]).trajectory_id).toBe("t2")
  })

  it("falls back to oneshot when stream command is unsupported", async () => {
    let callIdx = 0
    Bun.spawn = mock(() => {
      callIdx++
      if (callIdx === 1) {
        return {
          stdin: {
            write: mock(() => {}),
            end: mock(() => {}),
          },
          stdout: new ReadableStream({ start(c) { c.close() } }),
          stderr: makeStdout("unknown command: stream"),
          exitCode: 1,
          exited: Promise.resolve(1),
          killed: false,
          kill: mock(() => {}),
        }
      }
      return {
        stdin: {
          write: mock((data: string) => {}),
          end: mock(() => {}),
        },
        stdout: makeStdout(JSON.stringify({ decision: "allow" })),
        stderr: makeStdout(""),
        exitCode: 0,
        exited: Promise.resolve(0),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    const c = new HarnessClient("/bin/adapter")
    const result = await c.adjudicate({
      trajectory_id: "t1", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: { command: "ls" }, event_type: "before",
    })

    expect(result.decision).toBe("allow")
    expect((c as any).useStream).toBe(false)
    expect(callIdx).toBe(2)
  })

  it("reconnects stream process after crash", async () => {
    let spawnCount = 0

    Bun.spawn = mock(() => {
      spawnCount++
      const output = createMockOutputStream()
      const isFirst = spawnCount === 1
      let wrote = false

      return {
        stdin: {
          write: mock((data: string) => {
            if (!wrote) {
              wrote = true
              output.push(JSON.stringify({ decision: "allow" }) + "\n")
              if (isFirst) {
                setTimeout(() => {
                  output.close()
                }, 0)
              }
            }
          }),
          end: mock(() => {}),
        },
        stdout: output.stream,
        stderr: new ReadableStream({ start(c) { c.close() } }),
        exitCode: null as number | null,
        exited: new Promise<number>((resolve) => {
          if (isFirst) {
            setTimeout(() => resolve(1), 5)
          }
        }),
        killed: false,
        kill: mock(() => {}),
      }
    }) as any

    const c = new HarnessClient("/bin/adapter")
    const r1 = await c.adjudicate({
      trajectory_id: "t1", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: {}, event_type: "before",
    })
    expect(r1.decision).toBe("allow")
    expect(spawnCount).toBe(1)

    await new Promise((r) => setTimeout(r, 20))

    const r2 = await c.adjudicate({
      trajectory_id: "t2", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: {}, event_type: "before",
    })
    expect(r2.decision).toBe("allow")
    expect(spawnCount).toBe(2)
  })

  it("returns deny from stream mode", async () => {
    const output = createMockOutputStream()
    const mockProc = {
      stdin: {
        write: mock((data: string) => {
          output.push(JSON.stringify({ decision: "deny", reason: "blocked" }) + "\n")
        }),
        end: mock(() => {}),
      },
      stdout: output.stream,
      stderr: new ReadableStream({ start(c) { c.close() } }),
      exitCode: null as number | null,
      exited: new Promise(() => {}),
      killed: false,
      kill: mock(() => {}),
    }

    Bun.spawn = mock(() => mockProc) as any

    const c = new HarnessClient("/bin/adapter")
    const result = await c.adjudicate({
      trajectory_id: "t1", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: { command: "rm -rf /" }, event_type: "before",
    })

    expect(result.decision).toBe("deny")
    expect(result.reason).toBe("blocked")
  })

  it("serializes concurrent calls", async () => {
    const output = createMockOutputStream()
    const order: string[] = []

    const mockProc = {
      stdin: {
        write: mock((data: string) => {
          const id = JSON.parse(data).trajectory_id
          order.push(id)
          output.push(JSON.stringify({ decision: "allow" }) + "\n")
        }),
        end: mock(() => {}),
      },
      stdout: output.stream,
      stderr: new ReadableStream({ start(c) { c.close() } }),
      exitCode: null as number | null,
      exited: new Promise(() => {}),
      killed: false,
      kill: mock(() => {}),
    }

    Bun.spawn = mock(() => mockProc) as any

    const c = new HarnessClient("/bin/adapter")

    const [r1, r2, r3] = await Promise.all([
      c.adjudicate({
        trajectory_id: "1" as any, agent_id: "a", tool: "bash",
        action: "ShellCommand", args: {}, event_type: "before",
      }),
      c.adjudicate({
        trajectory_id: "2" as any, agent_id: "a", tool: "bash",
        action: "ShellCommand", args: {}, event_type: "before",
      }),
      c.adjudicate({
        trajectory_id: "3" as any, agent_id: "a", tool: "bash",
        action: "ShellCommand", args: {}, event_type: "before",
      }),
    ])

    expect(r1.decision).toBe("allow")
    expect(r2.decision).toBe("allow")
    expect(r3.decision).toBe("allow")
    expect(order).toEqual(["1", "2", "3"])
  })

  it("returns allow on stream timeout", async () => {
    const output = createMockOutputStream()
    const mockProc = {
      stdin: {
        write: mock((data: string) => {}),
        end: mock(() => {}),
      },
      stdout: output.stream,
      stderr: new ReadableStream({ start(c) { c.close() } }),
      exitCode: null as number | null,
      exited: new Promise(() => {}),
      killed: false,
      kill: mock(() => {}),
    }

    Bun.spawn = mock(() => mockProc) as any

    const c = new HarnessClient("/bin/adapter", false, 50)
    const result = await c.adjudicate({
      trajectory_id: "t1", agent_id: "a1", tool: "bash",
      action: "ShellCommand", args: { command: "ls" }, event_type: "before",
    })

    expect(result.decision).toBe("allow")
  })
})

import type { AdapterRequest, AdjudicationResponse } from "./types"

class LineReader {
  private reader: ReadableStreamDefaultReader<Uint8Array>
  private decoder = new TextDecoder()
  private buffer = ""

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader()
  }

  async readLine(): Promise<string | null> {
    while (!this.buffer.includes("\n")) {
      const { done, value } = await this.reader.read()
      if (done) {
        const remaining = this.buffer.trim()
        this.buffer = ""
        return remaining.length > 0 ? remaining : null
      }
      this.buffer += this.decoder.decode(value, { stream: true })
    }
    const idx = this.buffer.indexOf("\n")
    const line = this.buffer.slice(0, idx)
    this.buffer = this.buffer.slice(idx + 1)
    return line
  }

  cancel() {
    this.reader.cancel().catch(() => {})
  }
}

export class HarnessClient {
  private binaryPath: string
  private proc: ReturnType<typeof Bun.spawn> | null = null
  private lineReader: LineReader | null = null
  private useStream: boolean | null = null
  private chain: Promise<void> = Promise.resolve()
  private forceOneshot: boolean
  private timeoutMs: number

  constructor(binaryPath?: string, forceOneshot = false, timeoutMs = 5000) {
    this.forceOneshot = forceOneshot
    this.timeoutMs = timeoutMs
    const envPath = process.env.SONDERA_ADAPTER_PATH
    if (envPath) {
      this.binaryPath = envPath
    } else if (binaryPath) {
      this.binaryPath = binaryPath
    } else {
      const home = process.env.HOME || "/root"
      this.binaryPath = `${home}/.local/bin/sondera-opencode-adapter`
    }
  }

  async adjudicate(event: AdapterRequest): Promise<AdjudicationResponse> {
    const token = this.chain
    let release: () => void
    const gate = new Promise<void>((r) => {
      release = r
    })
    this.chain = gate

    await token
    try {
      return await this._adjudicate(event)
    } finally {
      release!()
    }
  }

  private async _adjudicate(event: AdapterRequest): Promise<AdjudicationResponse> {
    if (this.useStream === false || this.forceOneshot) {
      return this.oneshotAdjudicate(event)
    }

    try {
      await this.ensureStreamProcess()
      const stdin = this.proc!.stdin as unknown as { write: (d: string) => void }
      stdin.write(JSON.stringify(event) + "\n")

      const lineResult = await Promise.race([
        this.lineReader!.readLine(),
        new Promise<string | null>((resolve) =>
          setTimeout(() => {
            console.error(`[sondera] stream adjudicate timed out after ${this.timeoutMs}ms`)
            resolve(null)
          }, this.timeoutMs)
        ),
      ])

      if (lineResult === null) throw new Error("stream closed or timed out")
      const result = JSON.parse(lineResult) as AdjudicationResponse
      this.useStream = true
      return result
    } catch (err) {
      this.killStream()
      if (this.useStream === null) {
        this.useStream = false
        return this.oneshotAdjudicate(event)
      }
      console.error(`[sondera] stream error, allowing:`, err)
      return { decision: "allow" }
    }
  }

  private async ensureStreamProcess() {
    if (this.proc && this.proc.exitCode === null) return

    this.proc = Bun.spawn({
      cmd: [this.binaryPath, "stream"],
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
    this.lineReader = new LineReader(this.proc.stdout as ReadableStream<Uint8Array>)

    const capturedProc = this.proc
    capturedProc.exited.then((code) => {
      if (this.proc === capturedProc) {
        if (code !== 0 && this.useStream !== false) {
          console.error(`[sondera] stream process exited with code ${code}`)
        }
        this.proc = null
        this.lineReader = null
      }
    })
  }

  private killStream() {
    if (this.proc) {
      try {
        if (!this.proc.killed) this.proc.kill()
      } catch {}
    }
    if (this.lineReader) {
      this.lineReader.cancel()
    }
    this.proc = null
    this.lineReader = null
  }

  private async oneshotAdjudicate(event: AdapterRequest): Promise<AdjudicationResponse> {
    const proc = Bun.spawn({
      cmd: [this.binaryPath, "adjudicate"],
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })

    proc.stdin.write(JSON.stringify(event))
    proc.stdin.end()

    const result = await Promise.race([
      proc.exited.then(async (exitCode) => {
        if (exitCode !== 0) {
          const stderr = await new Response(proc.stderr).text()
          console.error(`[sondera] adapter error (exit ${exitCode}): ${stderr.trim()}`)
          return { decision: "allow" } as AdjudicationResponse
        }
        const stdout = await new Response(proc.stdout).text()
        try {
          return JSON.parse(stdout.trim()) as AdjudicationResponse
        } catch {
          console.error(`[sondera] invalid adapter response: ${stdout.trim()}`)
          return { decision: "allow" } as AdjudicationResponse
        }
      }),
      new Promise<{ decision: "allow" }>((resolve) =>
        setTimeout(() => {
          try { if (!proc.killed) proc.kill() } catch {}
          console.error(`[sondera] adjudicate timed out after ${this.timeoutMs}ms`)
          resolve({ decision: "allow" })
        }, this.timeoutMs)
      ),
    ])

    return result as AdjudicationResponse
  }

  async health(): Promise<boolean> {
    try {
      const proc = Bun.spawn({
        cmd: [this.binaryPath, "health"],
        stdout: "pipe",
        stderr: "pipe",
      })
      const exitCode = await proc.exited
      return exitCode === 0
    } catch {
      return false
    }
  }
}

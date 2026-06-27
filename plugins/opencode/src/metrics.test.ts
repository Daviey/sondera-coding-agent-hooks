import { describe, expect, it, beforeEach, mock } from "bun:test"
import { recordAllow, recordDeny, recordEscalate, recordDryRunDeny, recordBypass, recordError, getMetrics, resetMetrics, logSummary } from "./metrics"

beforeEach(() => {
  resetMetrics()
})

describe("metrics", () => {
  it("starts at zero", () => {
    const m = getMetrics()
    expect(m.total).toBe(0)
    expect(m.allowed).toBe(0)
    expect(m.denied).toBe(0)
  })

  it("tracks allows", () => {
    recordAllow(10)
    recordAllow(20)
    const m = getMetrics()
    expect(m.total).toBe(2)
    expect(m.allowed).toBe(2)
    expect(m.totalDurationMs).toBe(30)
  })

  it("tracks denies", () => {
    recordDeny(5)
    const m = getMetrics()
    expect(m.denied).toBe(1)
    expect(m.total).toBe(1)
  })

  it("tracks escalations", () => {
    recordEscalate(7)
    const m = getMetrics()
    expect(m.escalated).toBe(1)
  })

  it("tracks dry-run denies", () => {
    recordDryRunDeny(3)
    const m = getMetrics()
    expect(m.dryRunDenies).toBe(1)
    expect(m.denied).toBe(0)
  })

  it("tracks bypasses", () => {
    recordBypass()
    const m = getMetrics()
    expect(m.bypassed).toBe(1)
    expect(m.total).toBe(1)
  })

  it("tracks errors", () => {
    recordError()
    const m = getMetrics()
    expect(m.errors).toBe(1)
  })

  it("resets to zero", () => {
    recordAllow(1)
    recordDeny(1)
    resetMetrics()
    const m = getMetrics()
    expect(m.total).toBe(0)
    expect(m.allowed).toBe(0)
  })

  it("logSummary does not throw with zero calls", () => {
    logSummary()
  })

  it("logSummary logs with recorded data", () => {
    const spy = mock(() => {})
    const orig = console.error
    console.error = spy as any
    recordAllow(10)
    recordDeny(5)
    logSummary()
    expect(spy).toHaveBeenCalledTimes(1)
    const call = (spy.mock.calls as unknown as string[][])[0] as string[]
    expect(call[0]).toContain("2 calls")
    expect(call[0]).toContain("1 allowed")
    expect(call[0]).toContain("1 denied")
    console.error = orig
  })
})

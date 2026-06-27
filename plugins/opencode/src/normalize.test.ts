import { describe, expect, it } from "bun:test"
import { normalizeEvent, toolArgs } from "./normalize"

describe("normalizeEvent", () => {
  it("maps bash to ShellCommand", () => {
    const event = normalizeEvent("bash", { command: "ls" }, "/tmp", "sess1", "agent1", "before")
    expect(event.action).toBe("ShellCommand")
    expect(event.tool).toBe("bash")
    expect(event.args).toEqual({ command: "ls" })
    expect(event.cwd).toBe("/tmp")
    expect(event.trajectory_id).toBe("sess1")
    expect(event.agent_id).toBe("agent1")
    expect(event.event_type).toBe("before")
  })

  it("maps read to FileRead", () => {
    const event = normalizeEvent("read", { filePath: "/foo/bar" }, undefined, undefined, "agent1", "before")
    expect(event.action).toBe("FileRead")
    expect(event.cwd).toBeUndefined()
    expect(event.trajectory_id).toBe("unknown")
  })

  it("maps edit to FileEdit", () => {
    const event = normalizeEvent("edit", {}, "/home", "s1", "a1", "after")
    expect(event.action).toBe("FileEdit")
    expect(event.event_type).toBe("after")
  })

  it("maps write to FileWrite", () => {
    expect(normalizeEvent("write", {}, "/", "s", "a", "before").action).toBe("FileWrite")
  })

  it("maps apply_patch to FileEdit", () => {
    expect(normalizeEvent("apply_patch", {}, "/", "s", "a", "before").action).toBe("FileEdit")
  })

  it("maps glob to FileSearch", () => {
    expect(normalizeEvent("glob", {}, "/", "s", "a", "before").action).toBe("FileSearch")
  })

  it("maps grep to ContentSearch", () => {
    expect(normalizeEvent("grep", {}, "/", "s", "a", "before").action).toBe("ContentSearch")
  })

  it("maps webfetch to WebFetch", () => {
    expect(normalizeEvent("webfetch", {}, "/", "s", "a", "before").action).toBe("WebFetch")
  })

  it("maps websearch to WebSearch", () => {
    expect(normalizeEvent("websearch", {}, "/", "s", "a", "before").action).toBe("WebSearch")
  })

  it("maps skill to SkillLoad", () => {
    expect(normalizeEvent("skill", {}, "/", "s", "a", "before").action).toBe("SkillLoad")
  })

  it("maps todowrite to TodoUpdate", () => {
    expect(normalizeEvent("todowrite", {}, "/", "s", "a", "before").action).toBe("TodoUpdate")
  })

  it("maps lsp to LspQuery", () => {
    expect(normalizeEvent("lsp", {}, "/", "s", "a", "before").action).toBe("LspQuery")
  })

  it("maps question to Question", () => {
    expect(normalizeEvent("question", {}, "/", "s", "a", "before").action).toBe("Question")
  })

  it("maps task to SubAgent", () => {
    expect(normalizeEvent("task", {}, "/", "s", "a", "before").action).toBe("SubAgent")
  })

  it("maps unknown tools to ToolCall", () => {
    expect(normalizeEvent("foobar", {}, "/", "s", "a", "before").action).toBe("ToolCall")
  })

  it("defaults trajectory_id to unknown when sessionId is undefined", () => {
    const event = normalizeEvent("bash", {}, "/", undefined, "a1", "before")
    expect(event.trajectory_id).toBe("unknown")
  })
})

describe("toolArgs", () => {
  it("extracts bash args", () => {
    const result = toolArgs("bash", { command: "ls -la", workdir: "/tmp" })
    expect(result).toEqual({ command: "ls -la", workdir: "/tmp" })
  })

  it("extracts bash args with missing command", () => {
    const result = toolArgs("bash", {})
    expect(result).toEqual({ command: "", workdir: undefined })
  })

  it("extracts read args from filePath", () => {
    const result = toolArgs("read", { filePath: "/foo.ts" })
    expect(result).toEqual({ path: "/foo.ts" })
  })

  it("extracts read args from path fallback", () => {
    const result = toolArgs("read", { path: "/bar.ts" })
    expect(result).toEqual({ path: "/bar.ts" })
  })

  it("extracts edit args", () => {
    const result = toolArgs("edit", { filePath: "/a.ts", oldString: "old", newString: "new" })
    expect(result).toEqual({ path: "/a.ts", old_content: "old", new_content: "new" })
  })

  it("extracts write args", () => {
    const result = toolArgs("write", { filePath: "/a.ts", content: "hello" })
    expect(result).toEqual({ path: "/a.ts", content: "hello" })
  })

  it("extracts apply_patch args", () => {
    const result = toolArgs("apply_patch", { patchText: "--- a\n+++ b" })
    expect(result).toEqual({ patch_text: "--- a\n+++ b" })
  })

  it("extracts webfetch args", () => {
    const result = toolArgs("webfetch", { url: "https://example.com", format: "text" })
    expect(result).toEqual({ url: "https://example.com", format: "text" })
  })

  it("extracts glob args", () => {
    const result = toolArgs("glob", { pattern: "**/*.ts" })
    expect(result).toEqual({ pattern: "**/*.ts" })
  })

  it("extracts grep args", () => {
    const result = toolArgs("grep", { pattern: "TODO", include: "*.ts" })
    expect(result).toEqual({ pattern: "TODO", include: "*.ts" })
  })

  it("returns raw args for unknown tools", () => {
    const args = { foo: "bar", baz: 42 }
    expect(toolArgs("unknown_tool", args)).toEqual(args)
  })

  it("extracts websearch query", () => {
    expect(toolArgs("websearch", { query: "rust async" })).toEqual({ query: "rust async" })
  })

  it("extracts websearch query from search_query fallback", () => {
    expect(toolArgs("websearch", { search_query: "cedar policy" })).toEqual({ query: "cedar policy" })
  })

  it("omits empty optional fields", () => {
    const result = toolArgs("bash", { command: "ls", workdir: "" })
    expect(result).toEqual({ command: "ls", workdir: undefined })
  })

  it("omits undefined optional fields in edit", () => {
    const result = toolArgs("edit", { filePath: "/a.ts" })
    expect(result).toEqual({ path: "/a.ts", old_content: undefined, new_content: undefined })
  })

  it("returns raw args for task (SubAgent)", () => {
    const args = { prompt: "do stuff", subagent_type: "general" }
    expect(toolArgs("task", args)).toEqual(args)
  })

  it("returns raw args for skill (SkillLoad)", () => {
    const args = { skill_name: "debugging" }
    expect(toolArgs("skill", args)).toEqual(args)
  })
})

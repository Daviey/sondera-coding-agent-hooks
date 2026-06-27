import type { AdapterRequest } from "./types"

const TOOL_ACTION_MAP: Record<string, string> = {
  bash: "ShellCommand",
  read: "FileRead",
  edit: "FileEdit",
  write: "FileWrite",
  apply_patch: "FileEdit",
  glob: "FileSearch",
  grep: "ContentSearch",
  webfetch: "WebFetch",
  websearch: "WebSearch",
  question: "Question",
  task: "SubAgent",
  skill: "SkillLoad",
  todowrite: "TodoUpdate",
  lsp: "LspQuery",
}

export function normalizeEvent(
  tool: string,
  args: Record<string, unknown>,
  cwd: string | undefined,
  sessionId: string | undefined,
  agentId: string,
  eventType: "before" | "after",
): AdapterRequest {
  return {
    trajectory_id: sessionId || "unknown",
    agent_id: agentId,
    tool,
    action: TOOL_ACTION_MAP[tool] || "ToolCall",
    args,
    cwd,
    event_type: eventType,
  }
}

function str(val: unknown): string | undefined {
  if (typeof val === "string" && val.length > 0) return val
  return undefined
}

export function toolArgs(
  tool: string,
  args: Record<string, unknown>,
): Record<string, unknown> {
  switch (tool) {
    case "bash":
      return {
        command: (args.command as string) || "",
        workdir: str(args.workdir),
      }
    case "read":
      return {
        path: str(args.filePath) || str(args.path) || "",
      }
    case "edit":
      return {
        path: str(args.filePath) || str(args.path) || "",
        old_content: str(args.oldString),
        new_content: str(args.newString),
      }
    case "write":
      return {
        path: str(args.filePath) || str(args.path) || "",
        content: str(args.content),
      }
    case "apply_patch":
      return {
        patch_text: (args.patchText as string) || "",
      }
    case "webfetch":
      return {
        url: (args.url as string) || "",
        format: str(args.format),
      }
    case "glob":
      return {
        pattern: (args.pattern as string) || "",
      }
    case "grep":
      return {
        pattern: (args.pattern as string) || "",
        include: str(args.include),
      }
    case "websearch":
      return {
        query: (args.query as string) || (args.search_query as string) || "",
      }
    default:
      return args
  }
}

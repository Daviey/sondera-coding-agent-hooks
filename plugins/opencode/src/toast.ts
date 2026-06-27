export interface ToastInput {
  variant: "info" | "success" | "warning" | "error"
  title?: string
  message: string
  duration?: number
}

let serverOrigin: string | null = null

export function initToast(url: URL | undefined) {
  serverOrigin = url?.origin ?? null
}

export async function sendToast(input: ToastInput): Promise<void> {
  if (!serverOrigin) return
  try {
    await fetch(`${serverOrigin}/tui/show-toast`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    })
  } catch {}
}

export function resetToast() {
  serverOrigin = null
}

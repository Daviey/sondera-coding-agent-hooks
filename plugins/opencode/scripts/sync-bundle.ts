const files = [
  "src/types.ts",
  "src/config.ts",
  "src/audit.ts",
  "src/metrics.ts",
  "src/toast.ts",
  "src/normalize.ts",
  "src/client.ts",
  "src/index.ts",
]

const header = `// Auto-generated from src/ — do not edit directly.\n// Run: bun scripts/sync-bundle.ts\n\n`

let bundled = header
for (const f of files) {
  let src = await Bun.file(f).text()

  src = src.replace(/import\s+(type\s+)?\{[^}]*\}\s*from\s*"[.][^"]*"\s*;?\n?/g, "")
  src = src.replace(/import\s+.*\s*from\s*"[.][^"]*"\s*;?\n?/g, "")
  src = src.replace(/export\s+\{[^}]*\}\s*from\s*"[.][^"]*"\s*;?\n?/g, "")
  src = src.replace(/^export\s+(?!const\s+SonderaPlugin\b)/gm, "")

  bundled += `// --- ${f} ---\n${src.trim()}\n\n`
}

await Bun.write("sondera-bundled.ts", bundled)

try {
  new Bun.Transpiler({ loader: "ts" }).transformSync(bundled)
  console.log("OK: sondera-bundled.ts synced and parses cleanly")
} catch (e) {
  console.error("PARSE ERROR in bundled output:", e)
  process.exit(1)
}

/**
 * Shared helpers for the Netsight ECC OpenCode plugin (V2 port).
 *
 * The original ECC 2.2.3 plugin used OpenCode V1's Bun `$` shell helper. V2
 * plugins do not receive `$`; native helpers here use `node:child_process` with
 * `execFile` (no shell), so arguments are never interpreted as shell syntax.
 * Command detection still scans the raw command string, which is data, not
 * executable input.
 */
import { execFile } from "node:child_process"
import * as fs from "node:fs"
import * as path from "node:path"
import { Plugin } from "@opencode/plugin"

export function createLogger(context: Plugin.Context) {
  return (level: "debug" | "info" | "warn" | "error", message: string): void => {
    // OpenCode V2's plugin `App` has no log method; write to stderr so plugin
    // diagnostics never pollute any stdout protocol stream.
    void context
    console.error(`[ecc:${level}] ${message}`)
  }
}

export type Logger = ReturnType<typeof createLogger>

/** Read the project's ECC/version marker without throwing if it is absent. */
export function detectProjectVersion(worktreePath: string): string {
  try {
    const packageJsonPath = path.join(worktreePath, "package.json")
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"))
    return typeof packageJson.version === "string" ? packageJson.version : "2.2.3"
  } catch {
    return "2.2.3"
  }
}

export interface ExecResult {
  code: number
  stdout: string
  stderr: string
  failed: boolean
}

/** Run an executable with an argument array. Never invokes a shell. */
export function execFileResult(
  file: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number } = {}
): Promise<ExecResult> {
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      {
        cwd: options.cwd,
        timeout: options.timeoutMs ?? 120_000,
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        const out = stdout?.toString() ?? ""
        const err = stderr?.toString() ?? ""
        if (error) {
          resolve({
            code: typeof error.code === "number" ? error.code : 1,
            stdout: out,
            stderr: err || error.message,
            failed: true,
          })
          return
        }
        resolve({ code: 0, stdout: out, stderr: err, failed: false })
      }
    )
  })
}

/** Count lines containing `needle` in a file without spawning a shell. */
export function countMatchesInFile(file: string, needle: RegExp): number {
  try {
    const content = fs.readFileSync(file, "utf-8")
    let count = 0
    for (const line of content.split(/\r?\n/)) {
      if (needle.test(line)) count += 1
    }
    return count
  } catch {
    return 0
  }
}

/**
 * Resolve a locally-installed formatter's JS entrypoint (e.g. Prettier) without
 * invoking a shell or a package manager. Returns `null` when the formatter is
 * not installed, so callers skip quietly instead of triggering a network fetch
 * (e.g. `npx`). Returning the JS script lets the caller run it with
 * `process.execPath`, which avoids Windows `.cmd` shim limitations.
 */
export function resolvePrettierScript(projectRoot: string): string | null {
  const candidates = [
    path.join(projectRoot, "node_modules", "prettier", "package.json"),
    path.join(projectRoot, "apps", "web", "node_modules", "prettier", "package.json"),
  ]
  for (const pkgPath of candidates) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"))
      const bin = pkg.bin
      const rel = typeof bin === "string" ? bin : bin?.prettier
      if (typeof rel === "string") {
        const script = path.resolve(path.dirname(pkgPath), rel)
        if (fs.statSync(script).isFile()) return script
      }
    } catch {
      // not present; try the next candidate
    }
  }
  return null
}


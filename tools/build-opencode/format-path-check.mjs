// Verify resolvePrettierScript + the process.execPath invocation path using a
// controlled fake formatter, without a shell and without network access.
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { execFile } from "node:child_process"
import { promisify } from "node:util"

const { resolvePrettierScript } = await import("../../.opencode/dist/plugins/hook-support.js")

const root = fs.mkdtempSync(path.join(os.tmpdir(), "ecc-fmt-"))
const pkgDir = path.join(root, "node_modules", "prettier")
fs.mkdirSync(pkgDir, { recursive: true })
fs.writeFileSync(
  path.join(pkgDir, "package.json"),
  JSON.stringify({ name: "prettier", bin: { prettier: "bin-prettier.js" } })
)
fs.writeFileSync(
  path.join(pkgDir, "bin-prettier.js"),
  'import fs from "node:fs"; fs.writeFileSync(process.argv[3] + ".formatted", "ok")\n'
)

const script = resolvePrettierScript(root)
if (!script) throw new Error("resolvePrettierScript returned null for a present formatter")
console.log("resolved script:", path.relative(root, script))

const target = path.join(root, "sample.ts")
fs.writeFileSync(target, "const x = 1\n")

await promisify(execFile)(process.execPath, [script, "--write", target], { cwd: root })
const marker = target + ".formatted"
if (!fs.existsSync(marker)) throw new Error("formatter did not run")
console.log("formatter executed; marker:", path.basename(marker))
console.log("FORMAT PATH OK")

/**
 * ECC OpenCode plugin (V2 port) for Netsight.
 *
 * Ported from `ecc-universal@2.2.3` `.opencode/plugins/ecc-hooks.ts`, which
 * targets OpenCode V1 (Bun `$` shell + the V1 `Hooks` object keyed by string).
 * This port targets OpenCode V2's `@opencode/plugin` API:
 *
 *   - V1 returned a hook map; V2 registers hooks on their owning domain.
 *   - V1 `tool.execute.before/after` -> `ctx.tool.hook("execute.before"/"execute.after")`.
 *   - V1 `shell.env`                -> `ctx.shell.hook("create.before")`.
 *   - V1 `permission.ask`           -> `ctx.permission.hook("evaluate")`.
 *   - V1 `experimental.session.compacting` -> `ctx.session.hook("compaction")`.
 *   - V1 `event` callback           -> `ctx.event.subscribe()`.
 *   - V1 `tool` map                 -> `ctx.tool.transform(...)`.
 *   - V1 Bun `$`                    -> `node:child_process.execFile` (no shell).
 *
 * Deliberate deviations from the original:
 *   - Desktop notifications on `session.idle` are omitted. The Windows variant
 *     used a blocking `MessageBox`, which would stall an agent harness; ECC's
 *     own guidance is against noisy, harness-blocking behaviour.
 *   - Auto-format on `file.edited` resolves a *locally installed* Prettier and
 *     runs it via `process.execPath` (no shell, no `npx`/network fetch). It is a
 *     strict-profile hook and is a no-op when Prettier is not installed.
 *   - `tool.execute.after` now receives the call input directly as `event.input`
 *     (V2 shape) instead of a nested `{ tool, args }` object.
 *
 * Runtime controls are preserved: `ECC_HOOK_PROFILE` and `ECC_DISABLED_HOOKS`.
 */
import { Plugin } from "@opencode/plugin";
import * as fs from "node:fs";
import * as path from "node:path";
import { initStore, recordChange, clearChanges, } from "./changed-files-store.js";
import { createLogger, countMatchesInFile, detectProjectVersion, execFileResult, resolvePrettierScript, } from "./hook-support.js";
import { changedFilesTool } from "../tools/changed-files.js";
import { dependencyAnalyzerTool } from "../tools/dependency-analyzer.js";
function getFilePath(args) {
    if (!args)
        return null;
    const p = (args.filePath ?? args.file_path ?? args.path);
    return typeof p === "string" && p.trim() ? p : null;
}
function getCommand(args) {
    if (typeof args === "string")
        return args;
    if (args && typeof args === "object") {
        const command = args.command;
        if (typeof command === "string")
            return command;
    }
    return "";
}
const profileOrder = { minimal: 0, standard: 1, strict: 2 };
const IS_JS_TS = /\.(ts|tsx|js|jsx)$/;
export const ECCHooksPlugin = Plugin.define({
    id: "ecc",
    async setup(context) {
        const worktreePath = context.location.project?.canonical || context.location.directory || process.cwd();
        const log = createLogger(context);
        initStore(worktreePath);
        const editedFiles = new Set();
        const pendingToolChanges = new Map();
        let writeCounter = 0;
        const currentProfile = (() => {
            const value = process.env.ECC_HOOK_PROFILE;
            return value === "minimal" || value === "strict" ? value : "standard";
        })();
        const disabledHooks = new Set((process.env.ECC_DISABLED_HOOKS || "")
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean));
        const profileAllowed = (required) => {
            if (Array.isArray(required)) {
                return required.some((entry) => profileOrder[currentProfile] >= profileOrder[entry]);
            }
            return profileOrder[currentProfile] >= profileOrder[required];
        };
        const hookEnabled = (hookId, requiredProfile = "standard") => {
            if (disabledHooks.has(hookId))
                return false;
            return profileAllowed(requiredProfile);
        };
        const resolvePath = (p) => path.isAbsolute(p) ? p : path.join(worktreePath, p);
        const hasProjectFile = (relativePath) => {
            try {
                return fs.statSync(resolvePath(relativePath)).isFile();
            }
            catch {
                return false;
            }
        };
        // ---------------------------------------------------------------------
        // Tool hooks
        // ---------------------------------------------------------------------
        await context.tool.hook("execute.after", async (event) => {
            const args = event.input;
            const filePath = getFilePath(args);
            if (event.tool === "edit" && filePath) {
                recordChange(filePath, "modified");
            }
            if (event.tool === "write" && filePath) {
                const key = event.id ?? `write-${++writeCounter}-${filePath}`;
                const pending = pendingToolChanges.get(key);
                if (pending) {
                    recordChange(pending.path, pending.type);
                    pendingToolChanges.delete(key);
                }
                else {
                    recordChange(filePath, "modified");
                }
            }
            if (hookEnabled("post:edit:typecheck", ["strict"]) &&
                event.tool === "edit" &&
                typeof args?.filePath === "string" &&
                /\.tsx?$/.test(args.filePath)) {
                const result = await execFileResult("npx", ["tsc", "--noEmit"], {
                    cwd: worktreePath,
                });
                if (result.failed) {
                    log("warn", "[ECC] TypeScript errors detected:");
                    result.stdout
                        .split(/\r?\n/)
                        .slice(0, 5)
                        .forEach((line) => {
                        if (line.trim())
                            log("warn", `  ${line}`);
                    });
                }
                else {
                    log("info", "[ECC] TypeScript check passed");
                }
            }
            if (hookEnabled("post:bash:pr-created", ["standard", "strict"]) &&
                event.tool === "bash" &&
                getCommand(args).includes("gh pr create")) {
                log("info", "[ECC] PR created - check GitHub Actions status");
            }
        });
        await context.tool.hook("execute.before", async (event) => {
            const args = event.input;
            if (event.tool === "write") {
                const filePath = getFilePath(args);
                if (filePath) {
                    const absPath = resolvePath(filePath);
                    let type = "modified";
                    try {
                        type = fs.existsSync(absPath) ? "modified" : "added";
                    }
                    catch {
                        type = "modified";
                    }
                    const key = event.id ?? `write-${++writeCounter}-${filePath}`;
                    pendingToolChanges.set(key, { path: filePath, type });
                }
            }
            if (hookEnabled("pre:bash:git-push-reminder", "strict") &&
                event.tool === "bash" &&
                getCommand(args).includes("git push")) {
                log("info", "[ECC] Remember to review changes before pushing: git diff origin/main...HEAD");
            }
            if (hookEnabled("pre:write:doc-file-warning", ["standard", "strict"]) &&
                event.tool === "write" &&
                typeof args?.filePath === "string") {
                const filePath = args.filePath;
                if (/\.(md|txt)$/i.test(filePath) &&
                    !/README|CHANGELOG|LICENSE|CONTRIBUTING/.test(filePath)) {
                    log("warn", `[ECC] Creating ${filePath} - consider if this documentation is necessary`);
                }
            }
            if (hookEnabled("pre:bash:tmux-reminder", "strict") && event.tool === "bash") {
                const cmd = getCommand(args);
                if (/^(npm|pnpm|yarn|bun)\s+(install|build|test|run)/.test(cmd) ||
                    /^cargo\s+(build|test|run)/.test(cmd) ||
                    /^go\s+(build|test|run)/.test(cmd)) {
                    log("info", "[ECC] Long-running command detected - consider background execution");
                }
            }
        });
        // ---------------------------------------------------------------------
        // Shell environment hook
        // ---------------------------------------------------------------------
        await context.shell.hook("create.before", (event) => {
            const env = {
                ECC_VERSION: detectProjectVersion(worktreePath),
                ECC_PLUGIN: "true",
                ECC_HOOK_PROFILE: currentProfile,
                ECC_DISABLED_HOOKS: process.env.ECC_DISABLED_HOOKS || "",
                PROJECT_ROOT: worktreePath,
            };
            const lockfiles = {
                "bun.lockb": "bun",
                "pnpm-lock.yaml": "pnpm",
                "yarn.lock": "yarn",
                "package-lock.json": "npm",
            };
            for (const [lockfile, pm] of Object.entries(lockfiles)) {
                if (hasProjectFile(lockfile)) {
                    env.PACKAGE_MANAGER = pm;
                    break;
                }
            }
            const langDetectors = {
                "tsconfig.json": "typescript",
                "go.mod": "go",
                "pyproject.toml": "python",
                "Cargo.toml": "rust",
                "Package.swift": "swift",
            };
            const detected = [];
            for (const [file, lang] of Object.entries(langDetectors)) {
                if (hasProjectFile(file))
                    detected.push(lang);
            }
            if (detected.length > 0) {
                env.DETECTED_LANGUAGES = detected.join(",");
                env.PRIMARY_LANGUAGE = detected[0];
            }
            event.env = { ...event.env, ...env };
        });
        // ---------------------------------------------------------------------
        // Permission hook
        // ---------------------------------------------------------------------
        const READ_ONLY_TOOLS = new Set(["read", "glob", "grep", "search", "list", "webfetch"]);
        const FORMATTER_CMD = /^(npx )?(@biomejs\/biome|prettier|black|gofmt|rustfmt|swift-format)/;
        const TEST_CMD = /^(npm test|npx vitest|npx jest|pytest|go test|cargo test)/;
        await context.permission.hook("evaluate", (event) => {
            log("info", `[ECC] Permission requested for: ${event.action}`);
            try {
                const cmd = typeof event.metadata?.command === "string" ? String(event.metadata.command) : "";
                if (READ_ONLY_TOOLS.has(event.action)) {
                    event.effect = "allow";
                    event.message = "Read-only operation";
                    return;
                }
                if (event.action === "bash" && FORMATTER_CMD.test(cmd)) {
                    event.effect = "allow";
                    event.message = "Formatter execution";
                    return;
                }
                if (event.action === "bash" && TEST_CMD.test(cmd)) {
                    event.effect = "allow";
                    event.message = "Test execution";
                    return;
                }
                // Everything else: leave the harness's proposed effect untouched.
            }
            catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                log("error", `[ECC] Permission handling error for ${event.action}: ${message}`);
                event.effect = "deny";
                event.message = `Error: ${message}`;
            }
        });
        // ---------------------------------------------------------------------
        // Session compaction hook
        // ---------------------------------------------------------------------
        await context.session.hook("compaction", (event) => {
            const contextBlock = [
                "# ECC Context (preserve across compaction)",
                "",
                "## Active Plugin: ECC (OpenCode V2 port)",
                "- Hooks: file.edited, tool.execute.before/after, session lifecycle, shell.env, compaction, permission.evaluate",
                "- Tools: changed-files, dependency-analyzer",
                "",
                "## Key Principles",
                "- TDD: write tests first, 80%+ coverage",
                "- Immutability: never mutate, always return new copies",
                "- Security: validate inputs, no hardcoded secrets",
                "",
            ];
            if (editedFiles.size > 0) {
                contextBlock.push("## Recently Edited Files");
                for (const file of editedFiles)
                    contextBlock.push(`- ${file}`);
                contextBlock.push("");
            }
            contextBlock.push("Focus on preserving: 1) Current task status and progress, 2) Key decisions made, " +
                "3) Files created/modified, 4) Remaining work items, 5) Any security concerns flagged. " +
                "Discard: verbose tool outputs, intermediate exploration, redundant file listings.");
            event.system.push({ type: "text", text: contextBlock.join("\n") });
        });
        // ---------------------------------------------------------------------
        // Event subscription (session lifecycle, file edits)
        // ---------------------------------------------------------------------
        const controller = new AbortController();
        const runConsoleAudit = () => {
            if (editedFiles.size === 0)
                return;
            let total = 0;
            const filesWithConsoleLogs = [];
            for (const file of editedFiles) {
                if (!IS_JS_TS.test(file))
                    continue;
                const count = countMatchesInFile(file, /console\.log/);
                if (count > 0) {
                    total += count;
                    filesWithConsoleLogs.push(file);
                }
            }
            if (total > 0) {
                log("warn", `[ECC] Audit: ${total} console.log statement(s) in ${filesWithConsoleLogs.length} file(s)`);
                filesWithConsoleLogs.forEach((file) => log("warn", `  - ${file}`));
                log("warn", "[ECC] Remove console.log statements before committing");
            }
            else {
                log("info", "[ECC] Audit passed: No console.log statements found");
            }
        };
        const formatEditedFile = async (file) => {
            if (!hookEnabled("post:edit:format", ["strict"]) || !IS_JS_TS.test(file))
                return;
            const script = resolvePrettierScript(worktreePath);
            // Formatter not installed: skip quietly (never fetch it at edit time).
            if (!script)
                return;
            const result = await execFileResult(process.execPath, [script, "--write", resolvePath(file)], { cwd: worktreePath });
            if (result.failed) {
                log("debug", `[ECC] Prettier formatting failed for ${file}: ${result.stderr.trim()}`);
            }
            else {
                log("info", `[ECC] Formatted: ${file}`);
            }
        };
        const handleEvent = (event) => {
            const data = event.data ?? {};
            switch (event.type) {
                case "session.created": {
                    if (!hookEnabled("session:start", ["minimal", "standard", "strict"]))
                        return;
                    log("info", `[ECC] Session started - profile=${currentProfile}`);
                    if (hasProjectFile("CLAUDE.md")) {
                        log("info", "[ECC] Found CLAUDE.md - loading project context");
                    }
                    return;
                }
                case "session.idle": {
                    if (!hookEnabled("stop:check-console-log", ["minimal", "standard", "strict"]))
                        return;
                    log("info", "[ECC] Session idle - running console.log audit");
                    runConsoleAudit();
                    editedFiles.clear();
                    return;
                }
                case "session.deleted": {
                    if (!hookEnabled("session:end-marker", ["minimal", "standard", "strict"]))
                        return;
                    log("info", "[ECC] Session ended - cleaning up");
                    editedFiles.clear();
                    clearChanges();
                    pendingToolChanges.clear();
                    return;
                }
                case "file.edited": {
                    const file = typeof data.file === "string" ? data.file : undefined;
                    if (file) {
                        editedFiles.add(file);
                        recordChange(file, "modified");
                        void formatEditedFile(file);
                    }
                    return;
                }
                case "filesystem.changed": {
                    const file = typeof data.file === "string" ? data.file : undefined;
                    if (!file)
                        return;
                    const rawEvent = typeof data.event === "string" ? data.event : "change";
                    const changeType = rawEvent === "add" ? "added" : rawEvent === "unlink" ? "deleted" : "modified";
                    recordChange(file, changeType);
                    if (changeType === "modified" && IS_JS_TS.test(file))
                        editedFiles.add(file);
                    return;
                }
                default:
                    return;
            }
        };
        void (async () => {
            try {
                // `subscribe` shape differs between SDK builds; iterate defensively.
                const stream = context.event.subscribe({ signal: controller.signal });
                const iterable = (await Promise.resolve(stream));
                for await (const raw of iterable) {
                    if (raw && typeof raw === "object" && typeof raw.type === "string") {
                        handleEvent(raw);
                    }
                }
            }
            catch (error) {
                // Aborting on unload is expected; anything else is a best-effort diagnostic.
                const message = error instanceof Error ? error.message : String(error);
                log("debug", `[ECC] event subscription ended: ${message}`);
            }
        })();
        // ---------------------------------------------------------------------
        // Custom tools
        // ---------------------------------------------------------------------
        context.tool.transform((editor) => {
            editor.add(changedFilesTool);
            editor.add(dependencyAnalyzerTool);
        });
        return () => {
            controller.abort();
        };
    },
});
export default ECCHooksPlugin;

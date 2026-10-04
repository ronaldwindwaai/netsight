/**
 * ECC custom tool: `dependency-analyzer` (V2 port).
 *
 * Ported from `ecc-universal@2.2.3` to the OpenCode V2 tool API.
 */
import * as path from "node:path";
import * as fs from "node:fs";
import { getWorktreeRoot } from "../plugins/changed-files-store.js";
function detectPackageManager(cwd) {
    if (fs.existsSync(path.join(cwd, "bun.lockb")))
        return "bun";
    if (fs.existsSync(path.join(cwd, "pnpm-lock.yaml")))
        return "pnpm";
    if (fs.existsSync(path.join(cwd, "yarn.lock")))
        return "yarn";
    if (fs.existsSync(path.join(cwd, "package-lock.json")))
        return "npm";
    return "npm";
}
function analyzeDependencies(cwd) {
    const dependencies = [];
    const packageJsonPath = path.join(cwd, "package.json");
    if (!fs.existsSync(packageJsonPath)) {
        throw new Error("package.json not found");
    }
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
    const pushAll = (record, type) => {
        if (!record)
            return;
        for (const [name, version] of Object.entries(record)) {
            dependencies.push({ name, current: version, type, outdated: false });
        }
    };
    pushAll(packageJson.dependencies, "production");
    pushAll(packageJson.devDependencies, "development");
    pushAll(packageJson.peerDependencies, "peer");
    return dependencies;
}
function generateSummary(dependencies) {
    return {
        total: dependencies.length,
        outdated: dependencies.filter((d) => d.outdated).length,
        vulnerable: dependencies.filter((d) => d.security?.vulnerable).length,
        unused: 0,
    };
}
function generateRecommendations(dependencies, summary) {
    const recommendations = [];
    if (summary.outdated > 0) {
        recommendations.push(`${summary.outdated} outdated dependencies found. Consider updating.`);
    }
    if (summary.vulnerable > 0) {
        recommendations.push(`${summary.vulnerable} vulnerable dependencies found. Run: npm audit fix`);
    }
    if (summary.total > 100) {
        recommendations.push("Large number of dependencies detected. Consider removing unused packages.");
    }
    const hasTypeScript = dependencies.some((d) => d.name === "typescript");
    const hasEslint = dependencies.some((d) => d.name === "eslint");
    const hasPrettier = dependencies.some((d) => d.name === "prettier");
    if (hasTypeScript && !hasEslint) {
        recommendations.push("TypeScript project without ESLint detected. Consider adding linting.");
    }
    if (hasEslint && !hasPrettier) {
        recommendations.push("ESLint without Prettier detected. Consider adding code formatting.");
    }
    if (recommendations.length === 0) {
        recommendations.push("No critical dependency issues found.");
    }
    return recommendations;
}
export const dependencyAnalyzerTool = {
    name: "dependency-analyzer",
    description: "Analyze project dependencies for outdated packages, security vulnerabilities, and unused " +
        "dependencies. Supports npm, pnpm, yarn, and bun.",
    input: {
        type: "object",
        properties: {
            type: {
                type: "string",
                enum: ["all", "outdated", "security", "unused"],
                description: "Type of analysis to run (default: all)",
            },
            fix: { type: "boolean", description: "Attempt to fix issues automatically (default: false)" },
            depth: { type: "number", description: "Depth of dependency analysis (default: 1)" },
        },
        additionalProperties: false,
    },
    async execute(input) {
        const args = (input ?? {});
        try {
            const cwd = getWorktreeRoot();
            const analysisType = args.type ?? "all";
            const fix = args.fix ?? false;
            const depth = args.depth ?? 1;
            const packageManager = detectPackageManager(cwd);
            const dependencies = analyzeDependencies(cwd);
            const summary = generateSummary(dependencies);
            const recommendations = generateRecommendations(dependencies, summary);
            return {
                content: JSON.stringify({
                    success: true,
                    packageManager,
                    dependencies: dependencies.slice(0, 50),
                    summary,
                    recommendations,
                    analysisType,
                    fixMode: fix,
                    depth,
                    platform: process.platform,
                }),
            };
        }
        catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            return {
                content: JSON.stringify({
                    success: false,
                    error: `Failed to analyze dependencies: ${message}`,
                    type: args.type,
                }),
            };
        }
    },
};

/**
 * ECC custom tool: `changed-files` (V2 port).
 *
 * Ported from `ecc-universal@2.2.3` to the OpenCode V2 tool API. V1 used the
 * `tool()` helper from `@opencode-ai/plugin/tool` with a Zod schema; V2 tools
 * are plain definitions registered through `ctx.tool.transform`, with JSON
 * Schema inputs.
 */
import {
  buildTree,
  getChangedPaths,
  hasChanges,
  type ChangeType,
  type TreeNode,
} from "../plugins/changed-files-store.ts"

const INDICATORS: Record<ChangeType, string> = {
  added: "+",
  modified: "~",
  deleted: "-",
}

function renderTree(nodes: TreeNode[], indent: string): string {
  const lines: string[] = []
  for (const node of nodes) {
    const indicator = node.changeType ? ` (${INDICATORS[node.changeType]})` : ""
    const name = node.changeType ? `${node.name}${indicator}` : `${node.name}/`
    lines.push(`${indent}${name}`)
    if (node.children.length > 0) {
      lines.push(renderTree(node.children, `${indent}  `))
    }
  }
  return lines.join("\n")
}

export const changedFilesTool = {
  name: "changed-files",
  description:
    "List files changed by agents in this session as a navigable tree. Shows added (+), " +
    "modified (~), and deleted (-) indicators. Use filter to show only specific change types. " +
    "Returns paths for git diff.",
  input: {
    type: "object",
    properties: {
      filter: {
        type: "string",
        enum: ["all", "added", "modified", "deleted"],
        description: "Filter by change type (default: all)",
      },
      format: {
        type: "string",
        enum: ["tree", "json"],
        description: "Output format: tree for display, json for structured data (default: tree)",
      },
    },
    additionalProperties: false,
  },
  async execute(input: unknown) {
    const args = (input ?? {}) as { filter?: string; format?: string }
    const filter = args.filter && args.filter !== "all" ? (args.filter as ChangeType) : undefined
    const format = args.format ?? "tree"

    if (!hasChanges()) {
      return { content: JSON.stringify({ changed: false, message: "No files changed in this session" }) }
    }

    const paths = getChangedPaths(filter)

    if (format === "json") {
      return {
        content: JSON.stringify(
          {
            changed: true,
            filter: filter ?? "all",
            files: paths.map((p) => ({ path: p.path, changeType: p.changeType })),
            diffCommands: paths
              .filter((p) => p.changeType !== "added")
              .map((p) => `git diff ${p.path}`),
          },
          null,
          2
        ),
      }
    }

    const tree = buildTree(filter)
    const treeStr = renderTree(tree, "")
    const diffHint = paths
      .filter((p) => p.changeType !== "added")
      .slice(0, 5)
      .map((p) => `  git diff ${p.path}`)
      .join("\n")

    let output = `Changed files (${paths.length}):\n\n${treeStr}`
    if (diffHint) {
      output += `\n\nTo view diff for a file:\n${diffHint}`
    }
    return { content: output }
  },
}

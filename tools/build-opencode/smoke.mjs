// Smoke test: call the plugin's setup() against a stub V2 context and assert
// that all hooks/transforms register without throwing.
import plugin from "../../.opencode/dist/index.js"

const registrations = []
const hooks = []
function makeHook(namespace) {
  return async (name, cb) => {
    hooks.push(`${namespace}:${name}`)
    registrations.push({ dispose: async () => {} })
    return registrations[registrations.length - 1]
  }
}
const transform = async (cb) => {
  hooks.push("tool:transform")
  return { dispose: async () => {} }
}

const noop = () => {}
const context = {
  app: { name: "test", version: "0", channel: "test" },
  location: { directory: process.cwd(), project: { id: "p", directory: process.cwd(), canonical: process.cwd() } },
  options: {},
  agent: { hook: makeHook("agent"), reload: async () => {}, transform },
  aisdk: {},
  catalog: {},
  command: { hook: makeHook("command") },
  event: {
    subscribe: () => ({
      async *[Symbol.asyncIterator]() {
        // immediately end the stream
      },
    }),
  },
  integration: {},
  mcp: {},
  model: {},
  generate: {},
  permission: { hook: makeHook("permission") },
  plugin: {},
  provider: {},
  reference: {},
  rpc: {},
  session: { hook: makeHook("session") },
  shell: { hook: makeHook("shell") },
  skill: {},
  storage: {},
  tool: { hook: makeHook("tool"), transform, reload: async () => {} },
  vcs: {},
  websearch: {},
  worktree: {},
}

const cleanup = await plugin.setup(context)
console.log("setup ok; registered:", hooks.sort().join(", "))
console.log("cleanup type:", typeof cleanup)
// give the async event subscription a tick
await new Promise((r) => setTimeout(r, 20))
console.log("SMOKE OK")

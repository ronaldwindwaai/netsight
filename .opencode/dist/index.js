/**
 * OpenCode V2 plugin entrypoint (Netsight).
 *
 * OpenCode's plugin loader iterates module exports; only the default export
 * must be a plugin definition. Re-export the ECC plugin as the default.
 */
export { ECCHooksPlugin as default } from "./plugins/ecc-hooks.js";

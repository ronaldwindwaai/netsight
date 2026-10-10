/**
 * Stands in for the diagnostics server action in component tests. A test installs a handler
 * (usually a `mock.fn`) and inspects what the component sent.
 */
export type DiagnosticActionResult = { ok: false; message: string };

type Handler = (input: unknown) => Promise<DiagnosticActionResult>;

const unconfigured: Handler = () => {
  throw new Error('No diagnostics action handler installed for this test');
};

export const diagnosticsHandler: { current: Handler } = { current: unconfigured };

export function createDiagnosticRun(input: unknown): Promise<DiagnosticActionResult> {
  return diagnosticsHandler.current(input);
}

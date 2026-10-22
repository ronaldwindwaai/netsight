import type { CopilotStatus } from '@/lib/api-contracts-copilot';
import { TOOL_TITLES } from '@/lib/copilot-view';

/**
 * What the copilot can do for this session: whether a model and a knowledge base are connected and
 * which read tools the viewer's role allows. Every state is words and an icon. Nothing here names the
 * model or its endpoint (the API never sends them).
 */
export function CopilotStatusCard({ status }: { status: CopilotStatus }) {
  const model = status.model.state === 'ok';
  const knowledge = status.knowledge;
  const knowledgeIcon =
    knowledge.state === 'ok' ? 'bi-check-circle' : knowledge.state === 'unknown' ? 'bi-question-circle' : 'bi-plug';
  return (
    <section className="mb-3" aria-label="Copilot status">
      <p className="text-body-secondary mb-2">
        <i className="bi bi-shield-check me-1" aria-hidden="true" />
        Read-only: the copilot reads evidence with your own permissions and cannot change anything,
        run a command or approve an action.
      </p>
      <ul className="list-unstyled small mb-2">
        <li>
          <i className={`bi ${model ? 'bi-check-circle' : 'bi-plug'} me-1`} aria-hidden="true" />
          {model ? 'AI model configured' : 'AI model not connected'}
        </li>
        <li>
          <i className={`bi ${knowledgeIcon} me-1`} aria-hidden="true" />
          {knowledge.state === 'ok'
            ? `Knowledge base: ${knowledge.documents} documents, ${knowledge.chunks} sections`
            : knowledge.state === 'unknown'
              ? 'Knowledge base unreadable'
              : 'Knowledge base not connected'}
        </li>
      </ul>
      <ul className="list-unstyled small mb-0">
        {status.tools.map((tool) => (
          <li key={tool.name}>
            <i
              className={`bi ${tool.allowed ? 'bi-check-circle' : 'bi-shield-lock'} me-1`}
              aria-hidden="true"
            />
            <span className="fw-semibold">{TOOL_TITLES[tool.name]}</span>:{' '}
            {tool.allowed ? 'Available' : `Not permitted (needs ${tool.permission})`}
          </li>
        ))}
      </ul>
    </section>
  );
}

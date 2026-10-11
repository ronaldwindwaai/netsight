import type { CohortStatus } from '@/lib/api-contracts-traffic-explorer';
import { cohortNotice } from '@/lib/traffic-view';

/**
 * The small-cohort rule, in words. `too-few-sources` is a status of its own (something was withheld
 * and the visitor should know why); `sufficient` is a quiet footnote; `not-applied` says nothing.
 */
export function CohortNotice({ cohort, noun }: { cohort: CohortStatus; noun: string }) {
  const text = cohortNotice(cohort, noun);
  if (text === '') return null;
  if (cohort.state === 'sufficient') {
    return <p className="small text-body-secondary">{text}</p>;
  }
  return (
    <div role="status" aria-label="Too few sources" className="alert alert-info small py-2">
      <i className="bi bi-people me-1" aria-hidden="true" />
      <span>{text}</span>
    </div>
  );
}

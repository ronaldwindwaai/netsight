import { redirect } from 'next/navigation';

import { apiGet } from '@/lib/api';
import { parseSessionInfo } from '@/lib/api-contracts';

export default async function Landing() {
  const sessionState = await apiGet('/api/v1/auth/session', parseSessionInfo);
  redirect(sessionState.kind === 'ok' ? '/overview' : '/login');
}

/** Published report capabilities only. No generated or archived report is implied. */
export interface ReportTemplate { id: 'wan-sla'; title: string; description: string; sourcePermission: string }
export const REPORT_TEMPLATES: readonly ReportTemplate[] = [{
  id: 'wan-sla', title: 'Monthly WAN availability',
  description: 'Availability and outage evidence for each WAN link, including sampling gaps and SLA targets.',
  sourcePermission: 'internet:read',
}];
export function visibleReports(permissions: readonly string[] | null): readonly ReportTemplate[] {
  if (!permissions?.includes('reports:read')) return [];
  return REPORT_TEMPLATES.filter(report => permissions.includes(report.sourcePermission));
}
export function reportTemplate(id: string): ReportTemplate | null {
  return REPORT_TEMPLATES.find(report => report.id === id) ?? null;
}

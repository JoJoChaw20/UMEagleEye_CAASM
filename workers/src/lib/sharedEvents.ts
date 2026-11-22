/**
 * Whether a published threat-intel event raises alerts in a tenant, as the events list shows it. The
 * SQL that decides it for matching is services/threatIntel.ts eventAlertsSql; this mirrors it for one
 * event. Its own and platform events always do; an event another tenant shares with all tenants does
 * by the viewer tenant's choice for it (ti_event_alert_choices), else the tenant's default
 * (tenants.shared_event_alerts, off).
 */
export interface AlertSetting { tenantDefault: boolean; choices: Map<string, boolean> }

export interface EventForAlerts { tiEventId: string; tenantId: string | null; status: string; distribution: string }

/** Nothing for a viewer without a tenant: the platform superadmin has no alerts of its own. */
export function alertsHere(ev: EventForAlerts, viewerTenant: string | null | undefined, s: AlertSetting) {
  if (!viewerTenant) return {}
  const sharedIn = !!ev.tenantId && ev.tenantId !== viewerTenant && ev.distribution === 'all_tenants'
  const choice = sharedIn ? s.choices.get(ev.tiEventId) ?? null : null
  const visible = !ev.tenantId || ev.tenantId === viewerTenant || ev.distribution !== 'organisation'
  const on = ev.status === 'published' && visible && (sharedIn ? (choice ?? s.tenantDefault) : true)
  return { alerts_here: on, alerts_choice: choice, shared_in: sharedIn }
}

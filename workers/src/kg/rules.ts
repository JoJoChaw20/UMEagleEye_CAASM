/**
 * kg/rules.ts — fixed rules that find a company's problems, each with its evidence and a
 * recommended solution. Pure: the facts are loaded by kg/problems.ts. Not AI.
 */
export interface AssetFact { key: string; title: string; criticality: number; internetFacing: boolean; inMyAssets: boolean; ports: number[]; hasSbom: boolean }
export interface AdvisoryFact { key: string; assetKey: string; severity: string }
export interface AlertFact { key: string; title: string; severity: string; timestamp: string }
export interface AgentFact { key: string; name: string; status: string; lastHeartbeat: string | null; retired: boolean }
export interface ScanFact { key: string; agentKey: string | null; status: string; startedAt: string }

export interface Facts {
  assets: AssetFact[]
  advisories: AdvisoryFact[]
  agingAlerts: AlertFact[]
  agingTotal: number
  agents: AgentFact[]
  scans: ScanFact[]
  postureMeasuredAt: string | null
}

export interface Problem {
  id: string
  rule: string
  rank: number
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  detail: string
  solution: string
  evidence: string[]
  count: number
}

const DAY = 86_400_000
const RISKY_PORTS: Record<number, string> = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 3389: 'RDP', 5900: 'VNC' }
export const ALERT_AGE_DAYS = 7
const AGENT_SILENT_HOURS = 24
const FAILED_SCANS = 3
const POSTURE_STALE_HOURS = 48
const EVIDENCE_LIMIT = 20

export function evaluateRules(f: Facts, now: Date): Problem[] {
  const problems: Problem[] = []
  const nowMs = now.getTime()

  for (const a of f.assets) {
    if (a.internetFacing && a.criticality >= 8) {
      const open = f.advisories.filter(x => x.assetKey === a.key)
      if (open.length) {
        problems.push({
          id: `exposed:${a.key}`, rule: 'exposed_critical_with_advisory', rank: 100, severity: 'critical',
          title: `Internet-facing critical device ${a.title} has ${open.length} open advisory(ies)`,
          detail: `${a.title} is reachable from the internet, has criticality ${a.criticality}, and has ${open.length} open advisory(ies).`,
          solution: 'Fix this device first. Work through its open advisories, and restrict inbound access at the firewall until they are closed.',
          evidence: [a.key, ...open.slice(0, EVIDENCE_LIMIT).map(x => x.key)], count: open.length,
        })
      }
    }
    if (a.internetFacing) {
      const risky = a.ports.filter(p => RISKY_PORTS[p])
      if (risky.length) {
        problems.push({
          id: `port:${a.key}`, rule: 'exposed_risky_port', rank: 80, severity: 'high',
          title: `${a.title} exposes ${risky.map(p => `${RISKY_PORTS[p]} (${p})`).join(', ')} to the internet`,
          detail: `${a.title} is internet-facing with remote-access or file-sharing ports open.`,
          solution: 'Close these ports at the firewall, or allow them only through a VPN. Then run New scan on the Discovery page to confirm.',
          evidence: [a.key], count: risky.length,
        })
      }
    }
  }

  const uncovered = f.assets.filter(a => a.inMyAssets && !a.hasSbom)
  if (uncovered.length) {
    problems.push({
      id: 'no_sbom', rule: 'asset_without_sbom', rank: 50, severity: 'medium',
      title: `${uncovered.length} device(s) in My Assets have no SBOM and are not checked for CVEs`,
      detail: `These devices have no software bill of materials, so a lack of CVE alerts on them says nothing: ${uncovered.slice(0, EVIDENCE_LIMIT).map(a => a.title).join(', ')}.`,
      solution: 'Open each device and press Run SBOM scan. Start with the most critical devices.',
      evidence: uncovered.slice(0, EVIDENCE_LIMIT).map(a => a.key), count: uncovered.length,
    })
  }

  if (f.agingTotal > 0) {
    const anyCritical = f.agingAlerts.some(a => a.severity === 'critical')
    problems.push({
      id: 'aging_alerts', rule: 'open_alert_ageing', rank: anyCritical ? 70 : 60, severity: anyCritical ? 'critical' : 'high',
      title: `${f.agingTotal} high or critical alert(s) have been open for more than ${ALERT_AGE_DAYS} days`,
      detail: `Oldest examples: ${f.agingAlerts.slice(0, 5).map(a => a.title).join('; ')}.`,
      solution: 'Triage these on the Alerts page: fix the cause, Accept change if it was intended, Accept risk if it is tolerated, or Resolve.',
      evidence: f.agingAlerts.slice(0, EVIDENCE_LIMIT).map(a => a.key), count: f.agingTotal,
    })
  }

  for (const a of f.agents) {
    if (a.retired) continue
    const silent = a.lastHeartbeat == null || nowMs - new Date(a.lastHeartbeat).getTime() > AGENT_SILENT_HOURS * 3_600_000
    if (a.status === 'offline' || silent) {
      problems.push({
        id: `agent:${a.key}`, rule: 'agent_offline', rank: 40, severity: 'medium',
        title: `Agent ${a.name} is not reporting`,
        detail: `Agent ${a.name} is ${a.status}, last heard ${a.lastHeartbeat ?? 'never'}. Devices it covers are not being watched.`,
        solution: 'Check the EagleEye service is running on that computer and that it can reach the internet. Reinstall the agent if it does not recover.',
        evidence: [a.key], count: 1,
      })
    }
  }

  const byAgent = new Map<string, ScanFact[]>()
  for (const s of f.scans) if (s.agentKey) byAgent.set(s.agentKey, [...(byAgent.get(s.agentKey) ?? []), s])
  for (const [agentKey, scans] of byAgent) {
    const recent = [...scans].sort((x, y) => y.startedAt.localeCompare(x.startedAt)).slice(0, 10)
    const failed = recent.filter(s => s.status === 'failed')
    if (failed.length >= FAILED_SCANS) {
      problems.push({
        id: `scan:${agentKey}`, rule: 'scans_failing', rank: 45, severity: 'medium',
        title: `${failed.length} of the last ${recent.length} scans by one agent failed`,
        detail: 'Repeated failures leave the network picture out of date.',
        solution: 'Read the failure reason on the Discovery page. Check the scan target is allowed and that the agent has network access.',
        evidence: [agentKey, ...failed.map(s => s.key)], count: failed.length,
      })
    }
  }

  if (f.postureMeasuredAt && nowMs - new Date(f.postureMeasuredAt).getTime() > POSTURE_STALE_HOURS * 3_600_000) {
    problems.push({
      id: 'stale_posture', rule: 'stale_posture', rank: 20, severity: 'low',
      title: 'The security score is out of date',
      detail: `The last security score was measured ${f.postureMeasuredAt}.`,
      solution: 'The score is refreshed nightly. If it stays old, report it to the UMEagleEye team.',
      evidence: [], count: 1,
    })
  }

  return problems.sort((x, y) => y.rank - x.rank || y.count - x.count)
}

export { DAY }

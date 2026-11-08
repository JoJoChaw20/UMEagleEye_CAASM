// What an agent may be told to probe (active scans from New scan, and the routers a network agent
// starts from). Without a limit, a tenant admin, or anyone holding their session, could aim every
// agent of the tenant at third parties on the internet, from the company's own addresses. Allowed:
// private addresses (RFC 1918, and carrier-grade NAT 100.64.0.0/10), and any network one of the
// tenant's agents reports it is directly on (a company that uses public addresses inside). Active
// scans are at most a /16 at a time, the agent's own limit.
import { contains, parseCidr, type Cidr } from './agentRouting'

export const PRIVATE_V4 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10']
const PRIVATE = PRIVATE_V4.map((n) => parseCidr(n)!)
export const MIN_SCAN_PREFIX = 16

/** Whether `target` lies inside private address space or one of `known` (CIDRs the agents are on). */
export function insideAllowed(target: Cidr, known: readonly string[] = []): boolean {
  const nets = [...PRIVATE, ...known.map(parseCidr).filter((c): c is Cidr => c !== null && c.prefix >= 8)]
  return nets.some((n) => contains(n, target))
}

/** Why an active scan of `value` is refused; null = allowed. */
export function scanTargetRefusal(value: string, known: readonly string[] = []): string | null {
  const t = parseCidr(value)
  if (!t) return 'Enter an IPv4 address or range, e.g. 192.168.1.0/24'
  if (t.prefix < MIN_SCAN_PREFIX) return `Scan at most a /${MIN_SCAN_PREFIX} (65,536 addresses) at a time; split larger ranges`
  if (!insideAllowed(t, known)) {
    return 'Only private addresses (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) or a network one of your agents is on can be scanned'
  }
  return null
}

/** Why a network agent may not start from / crawl within this address or range; null = allowed. */
export function networkTargetRefusal(value: string, known: readonly string[] = []): string | null {
  const t = parseCidr(value)
  if (!t) return null                       // the format is checked elsewhere (lib/agentPolicy.ts)
  return insideAllowed(t, known) ? null : `${value} is not a private address or a network your agents are on`
}

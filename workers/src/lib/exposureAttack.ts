/**
 * How attackers use a weakness a scan found, as MITRE ATT&CK techniques: for exposure alerts (one per
 * rule, lib/exposureRules.ts) and vulnerable services whose CVEs are not on KEV (KEV ones have MITRE
 * CTID's own mapping, lib/kevAttack.ts). UMEagleEye's mapping, from what each weakness allows; shown
 * as such ("mapped from the weakness"), never as documented by MITRE for this device.
 */
import { techniqueName } from './attack'
import type { RuleId } from './exposureRules'

interface Use { id: string; why: string }

const SNIFF: Use = { id: 'T1040', why: 'passwords cross the network in clear text and can be captured' }
const GUESS: Use = { id: 'T1110', why: 'the login can be guessed or sprayed' }
const ACCOUNTS: Use = { id: 'T1078', why: 'captured or guessed passwords are then used as valid accounts' }

export const EXPOSURE_TECHNIQUES: Record<RuleId, Use[]> = {
  telnet: [SNIFF, GUESS, ACCOUNTS, { id: 'T1021', why: 'it is a remote login into the device' }],
  ftp_cleartext: [SNIFF, GUESS, ACCOUNTS],
  http_login_cleartext: [SNIFF, { id: 'T1557', why: 'someone on the path can read or change the login page' }, ACCOUNTS],
  db_no_auth: [
    { id: 'T1213', why: 'anyone who reaches it can read the data' },
    { id: 'T1565.001', why: 'or change it' },
    { id: 'T1486', why: 'open databases are wiped or held for ransom by automated campaigns' },
  ],
  smb_signing_off: [
    { id: 'T1557.001', why: 'unsigned SMB lets an attacker relay a captured NTLM login to this server' },
    { id: 'T1021.002', why: 'and use its shares as that user' },
  ],
  rdp_no_nla: [
    { id: 'T1021.001', why: 'the login screen is offered before anyone authenticates' },
    GUESS,
    { id: 'T1210', why: 'pre-authentication RDP flaws (such as BlueKeep) are reachable' },
  ],
  rdp_internet: [
    { id: 'T1133', why: 'remote access open to the internet is a common way in, including for ransomware' },
    { id: 'T1021.001', why: 'Remote Desktop gives a full session on the computer' },
    GUESS,
  ],
  vnc: [{ id: 'T1021.005', why: 'VNC gives control of the screen' }, GUESS],
  internet_admin_port: [
    { id: 'T1133', why: 'an admin or remote service open to the internet is a way in' },
    { id: 'T1190', why: 'its flaws can be exploited from anywhere' },
    GUESS,
  ],
  tls_expired: [{ id: 'T1557', why: 'users who learn to click through certificate warnings will also accept an attacker\'s certificate' }],
  tls_expiring: [],
}

export interface MappedTechnique { id: string; name: string; why: string }

/** The techniques for an exposure or non-KEV vulnerable-service alert; null when none applies. */
export function exposureAttackOf(eventType: string, d: Record<string, unknown> | null, internetFacing: boolean):
  { techniques: MappedTechnique[]; source: string } | null {
  if (!d) return null
  let uses: Use[] = []
  if (eventType === 'exposure' && typeof d.rule === 'string' && d.rule in EXPOSURE_TECHNIQUES) {
    uses = EXPOSURE_TECHNIQUES[d.rule as RuleId]
  } else if (eventType === 'vulnerable_service' && !d.kev && Number(d.cve_count ?? 0) > 0) {
    uses = [internetFacing
      ? { id: 'T1190', why: 'its known flaws can be exploited from the internet' }
      : { id: 'T1210', why: 'its known flaws can be exploited from inside the network, to spread' }]
  }
  const techniques = uses.flatMap((u) => {
    const name = techniqueName(u.id)
    return name ? [{ id: u.id, name, why: u.why }] : []
  })
  return techniques.length ? { techniques, source: 'UMEagleEye, mapped from the weakness' } : null
}

// Labels shared by the Discovery page parts. Kinds come from the server
// (workers/src/lib/discoveryNetworks.ts scanKind).
export const KIND_LABEL = {
  passive:       'Passive listening',
  network:       'Full scan',
  investigation: 'New-device check',
  host:          'Host scan',
  snmp:          'Network devices (SNMP)',
}

// What a network agent's crawl found ("3 devices · 2 links"), from its record's network_info
// (workers/src/routes/network.ts POST /topology).
export function crawlSummary(scan) {
  const c = scan?.networkInfo?.crawl
  if (!c) return null
  const located = c.located ? ` · ${c.located} on switch ports` : ''
  return `${c.devices} device${c.devices === 1 ? '' : 's'} · ${c.links} link${c.links === 1 ? '' : 's'}${located}`
}

export const KIND_HINT = {
  passive:       'The agent listened to its network (ARP, mDNS, NetBIOS, DHCP, SSDP). One record per agent per hour.',
  network:       'An active Nmap scan of a whole range',
  investigation: 'An automatic scan of one device the agent heard for the first time; its results are on the new-device alert',
  host:          'An active scan of a single address',
  snmp:          'A network agent read the routers and switches over SNMP: their ARP tables, MAC tables and CDP/LLDP neighbours. One record per agent per hour.',
}

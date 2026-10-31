// Labels shared by the Discovery page parts. Kinds come from the server
// (workers/src/lib/discoveryNetworks.ts scanKind).
export const KIND_LABEL = {
  passive:       'Passive listening',
  network:       'Full scan',
  investigation: 'New-device check',
  host:          'Host scan',
}

export const KIND_HINT = {
  passive:       'The agent listened to its network (ARP, mDNS, NetBIOS, DHCP, SSDP). One record per agent per hour.',
  network:       'An active Nmap scan of a whole range',
  investigation: 'An automatic scan of one device the agent heard for the first time; its results are on the new-device alert',
  host:          'An active scan of a single address',
}

import {
  LayoutDashboard, Bell, FileSearch, Globe, FileText,
  Settings, Radar, Bot, Building2, Package, Boxes, Users, Share2, Crown,
} from 'lucide-react'

// One source for the sidebar and the command palette. Items are filtered by the same
// actions the routes in App.jsx are guarded with.
export function buildNavSections(can, role) {
  const item = (action, entry) => (can(action) ? [entry] : [])

  const sections = [
    { label: 'Overview', items: [
      ...item('dashboard.view', { to: '/', icon: LayoutDashboard, label: 'Dashboard', keywords: 'home overview posture' }),
    ]},
    { label: 'Assets', items: [
      ...item('asset.view', { to: '/inventory', icon: Boxes, label: 'Inventory', keywords: 'assets my assets discovered devices graph' }),
      ...item('scan.view', { to: '/discovery', icon: Radar, label: 'Discovery', keywords: 'scan networks nmap passive' }),
      ...item('network.view', { to: '/network-map', icon: Share2, label: 'Network', keywords: 'network map topology routers switches ports cables vlan cdp lldp gateways relationships' }),
    ]},
    { label: 'Security', items: [
      ...item('alert.view', { to: '/alerts', icon: Bell, label: 'Alerts', keywords: 'events findings cve drift' }),
      ...item('advisory.view', { to: '/advisories', icon: FileSearch, label: 'Advisories', keywords: 'remediation ai sla' }),
      ...item('cti.view', { to: '/threat-intel', icon: Globe, label: 'Threat Intel', keywords: 'ioc feeds kev mitre attack' }),
      ...item('sbom.view', { to: '/sbom', icon: Package, label: 'SBOM', keywords: 'software packages syft grype' }),
    ]},
    { label: 'Reports', items: [
      ...item('report.view', { to: '/reports', icon: FileText, label: 'Reports', keywords: 'pdf export' }),
    ]},
    { label: 'System', items: [
      ...item('agent.view', { to: '/agents', icon: Bot, label: 'Agents', keywords: 'eagleeye agent heartbeat connection code' }),
      // Settings is for every signed-in user (profile, password, MFA)
      { to: '/settings', icon: Settings, label: 'Settings', keywords: 'profile mfa password' },
      // Every tenant member: the recipient, successor and approvers are Tenant users
      ...(role === 'tenant_user' || role === 'tenant_superadmin'
        ? [{ to: '/ownership', icon: Crown, label: 'Ownership', keywords: 'transfer owner recovery successor approver handover' }]
        : []),
    ]},
  ]

  const admin = [
    ...(role === 'superadmin' ? [{ to: '/tenants', icon: Building2, label: 'Tenants', keywords: 'organisations' }] : []),
    ...(role === 'tenant_superadmin' ? [{ to: '/users', icon: Users, label: 'Users', keywords: 'tenant invite roles access actions' }] : []),
  ]
  if (admin.length) sections.push({ label: 'Admin', items: admin })

  return sections.filter((s) => s.items.length)
}

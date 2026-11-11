import {
  LayoutDashboard, Bell, FileSearch, Globe, FileText,
  Settings, Radar, Bot, Building2, Package, Boxes, Users, Share2,
} from 'lucide-react'

// One source for the sidebar and the command palette, filtered by role the same way
// the routes in App.jsx are guarded.
export function buildNavSections(role) {
  const isSuperadmin = role === 'superadmin'
  const isTenantSuperadmin = role === 'tenant_superadmin'
  const isTenantAdmin = role === 'tenant_admin'
  const canSeeOps = role !== 'business_owner' // superadmin, tenant_superadmin, tenant_admin

  const sections = [
    { label: 'Overview', items: [
      { to: '/', icon: LayoutDashboard, label: 'Dashboard', keywords: 'home overview posture' },
    ]},
    { label: 'Assets', items: [
      { to: '/inventory', icon: Boxes, label: 'Inventory', keywords: 'assets my assets discovered devices graph' },
      ...(canSeeOps ? [{ to: '/discovery', icon: Radar, label: 'Discovery', keywords: 'scan networks nmap passive' }] : []),
      { to: '/network-map', icon: Share2, label: 'Network', keywords: 'network map topology routers switches ports cables vlan cdp lldp gateways relationships' },
    ]},
    { label: 'Security', items: [
      { to: '/alerts', icon: Bell, label: 'Alerts', keywords: 'events findings cve drift' },
      { to: '/advisories', icon: FileSearch, label: 'Advisories', keywords: 'remediation ai sla' },
      { to: '/threat-intel', icon: Globe, label: 'Threat Intel', keywords: 'ioc feeds kev mitre attack' },
      { to: '/sbom', icon: Package, label: 'SBOM', keywords: 'software packages syft grype' },
    ]},
    { label: 'Reports', items: [
      { to: '/reports', icon: FileText, label: 'Reports', keywords: 'pdf export' },
    ]},
    { label: 'System', items: [
      { to: '/agents', icon: Bot, label: 'Agents', keywords: 'eagleeye agent heartbeat connection code' },
      ...(canSeeOps ? [{ to: '/settings', icon: Settings, label: 'Settings', keywords: 'profile mfa password' }] : []),
    ]},
  ]

  if (isSuperadmin || isTenantSuperadmin || isTenantAdmin) {
    sections.push({ label: 'Admin', items: [
      ...(isSuperadmin ? [{ to: '/tenants', icon: Building2, label: 'Tenants', keywords: 'organisations' }] : []),
      ...(!isSuperadmin ? [{ to: '/users', icon: Users, label: 'Users', keywords: 'tenant invite roles' }] : []),
    ]})
  }

  return sections
}

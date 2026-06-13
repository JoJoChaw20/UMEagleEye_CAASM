import { useState, useEffect } from 'react'
import { Building2, ChevronDown } from 'lucide-react'
import client from '../../api/client'
import { useAuth } from '../../context/AuthContext'

/**
 * Tenant filter dropdown — only renders for superadmin.
 * Props:
 *   value        : currently selected tenant_id ('' = All Tenants)
 *   onChange     : (tenantId: string) => void
 *   className    : optional extra classes
 */
export default function TenantSelector({ value, onChange, className = '' }) {
  const { user } = useAuth()
  const [tenants, setTenants] = useState([])

  useEffect(() => {
    if (user?.role !== 'superadmin') return
    client.get('/tenants')
      .then(res => setTenants(res.data.tenants ?? []))
      .catch(() => {})
  }, [user?.role])

  if (user?.role !== 'superadmin') return null

  return (
    <div className={`relative flex items-center gap-2 ${className}`}>
      <Building2 className="w-4 h-4 text-dark-400 flex-shrink-0" />
      <div className="relative">
        <select
          value={value}
          onChange={e => onChange(e.target.value)}
          className="appearance-none bg-dark-800 border border-dark-700 text-dark-200 text-sm rounded-lg
                     pl-3 pr-8 py-1.5 focus:outline-none focus:ring-1 focus:ring-eagle-500/50
                     focus:border-eagle-500/50 cursor-pointer hover:border-dark-600 transition-colors"
        >
          <option value="">All Tenants</option>
          {tenants.map(t => (
            <option key={t.tenant_id} value={t.tenant_id}>
              {t.name}
            </option>
          ))}
        </select>
        <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dark-400 pointer-events-none" />
      </div>
    </div>
  )
}

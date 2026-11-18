import { useState, useEffect, useCallback } from 'react'
import client from '../api/client'
import { useAuth } from '../context/AuthContext'
import OwnershipSection from '../components/ownership/OwnershipSection'

// Ownership for every tenant member: the recipient of a transfer, the successor and the approvers are Tenant users
// and cannot open the Users page. Only the owner can list the tenant's users (for the transfer and plan forms).
export default function OwnershipPage() {
  const { user } = useAuth()
  const tenantId = user?.tenantId
  const isOwner = user?.role === 'tenant_superadmin'
  const [users, setUsers] = useState([])

  const loadUsers = useCallback(async () => {
    if (!tenantId || !isOwner) { setUsers([]); return }
    try {
      const res = await client.get(`/tenants/${tenantId}/users`)
      setUsers(res.data.users || [])
    } catch { /* the forms stay empty; the section shows its own errors */ }
  }, [tenantId, isOwner])
  useEffect(() => { loadUsers() }, [loadUsers])

  return (
    <div className="space-y-6">
      <h1 className="page-title">Ownership</h1>
      {tenantId
        ? <OwnershipSection tenantId={tenantId} users={users} onChanged={loadUsers} />
        : <p className="text-sm text-dark-300">Ownership belongs to a tenant. This account has none.</p>}
    </div>
  )
}

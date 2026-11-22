// Weekly history: a sub-page of Alerts (sidebar), the week-by-week record of the alert queue and its
// comparison with last week and the baseline week (components/reports/WeeklyHistory.jsx).
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import TenantSelector from '../components/common/TenantSelector'
import WeeklyHistory from '../components/reports/WeeklyHistory'

export default function WeeklyHistoryPage() {
  const { isPlatformSuperadmin, user } = useAuth()
  const [tenantFilter, setTenantFilter] = useState('')
  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          {/* a block of its own: .page-title is inline-flex and would sit beside it */}
          <Link to="/alerts" className="flex w-fit items-center gap-1 text-xs text-dark-400 hover:text-eagle-400"><ArrowLeft className="h-3.5 w-3.5" /> Alerts</Link>
          <h1 className="page-title mt-1">Weekly history</h1>
          <p className="text-dark-400 text-sm mt-1">How the alert queue changes week by week, against last week and your baseline week.</p>
        </div>
        {isPlatformSuperadmin && <TenantSelector value={tenantFilter} onChange={setTenantFilter} />}
      </div>
      <WeeklyHistory title="Week by week" tenantId={isPlatformSuperadmin ? tenantFilter : user?.tenantId} isPlatform={isPlatformSuperadmin} />
    </div>
  )
}

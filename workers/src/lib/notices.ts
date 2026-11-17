// Which tenant notices a user sees. Pure (no clock read: the caller passes `now`), tested in notices.test.ts.

export type NoticeRow = {
  tenantId: string; userId: string | null; expiresAt: Date | null; dismissedAt: Date | null
}

/** A notice is visible when it is for the viewer's tenant, tenant-wide or the viewer's own, undismissed and unexpired. */
export function noticeVisible(notice: NoticeRow, viewer: { userId: string; tenantId?: string | null }, now: Date): boolean {
  if (!viewer.tenantId || notice.tenantId !== viewer.tenantId) return false
  if (notice.userId !== null && notice.userId !== viewer.userId) return false
  if (notice.dismissedAt) return false
  if (notice.expiresAt && notice.expiresAt.getTime() <= now.getTime()) return false
  return true
}

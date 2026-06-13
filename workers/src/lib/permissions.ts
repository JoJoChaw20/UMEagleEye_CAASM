// Centralized RBAC role constants for UMEagleEye 2.0
// 4-role model: superadmin | tenant_superadmin | tenant_admin | business_owner

export const ROLES = {
  SUPERADMIN:        'superadmin',
  TENANT_SUPERADMIN: 'tenant_superadmin',
  TENANT_ADMIN:      'tenant_admin',
  BUSINESS_OWNER:    'business_owner',
} as const

export type Role = typeof ROLES[keyof typeof ROLES]

// All authenticated roles
export const ALL_ROLES = [
  'superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner',
] as const

// ─── Feature permission groups ────────────────────────────────────────────────

// Assets
export const ASSET_READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const ASSET_WRITE_ROLES  = ['tenant_superadmin', 'tenant_admin'] as const
export const ASSET_DELETE_ROLES = ['tenant_superadmin'] as const

// Scans
export const SCAN_READ_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const SCAN_RUN_ROLES  = ['tenant_superadmin', 'tenant_admin'] as const

// Advisories
export const ADVISORY_READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const ADVISORY_ACTION_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// Alerts / Events
export const ALERT_READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const ALERT_ACTION_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// Reports
export const REPORT_READ_ROLES     = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const REPORT_GENERATE_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// SBOM
export const SBOM_READ_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const

// Discovery (business_owner has no access)
export const DISCOVERY_VIEW_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
export const DISCOVERY_RUN_ROLES  = ['tenant_superadmin', 'tenant_admin'] as const

// Network Relationships (business_owner has no access)
export const RELATIONSHIP_VIEW_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
export const RELATIONSHIP_MANAGE_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// CTI / Threat Intel
export const CTI_READ_ROLES   = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const
export const CTI_INGEST_ROLES = ['tenant_superadmin', 'tenant_admin'] as const

// Settings
export const SETTINGS_VIEW_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
export const SETTINGS_EDIT_ROLES = ['tenant_superadmin'] as const

// Audit Logs
export const AUDIT_VIEW_ANY_ROLES = ['superadmin'] as const
export const AUDIT_VIEW_OWN_ROLES = ['superadmin', 'tenant_superadmin'] as const

// User Management
export const USER_VIEW_OWN_ROLES  = ['superadmin', 'tenant_superadmin', 'tenant_admin'] as const
export const USER_MANAGE_ROLES    = ['tenant_superadmin'] as const

// Chatbot
export const CHATBOT_ROLES = ['superadmin', 'tenant_superadmin', 'tenant_admin', 'business_owner'] as const

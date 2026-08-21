// Centralized RBAC definitions.
// Role hierarchy (higher number = more privilege). super_admin is the only
// role permitted to act across organizations.

export const ROLE_RANK: Record<string, number> = {
  viewer: 1,
  user: 2,
  service_account: 2,
  project_admin: 3,
  org_admin: 4,
  super_admin: 5,
}

export type Role =
  | 'viewer'
  | 'user'
  | 'service_account'
  | 'project_admin'
  | 'org_admin'
  | 'super_admin'

export function rankOf(role: string): number {
  return ROLE_RANK[role] ?? 0
}

export function atLeast(role: string, min: Role): boolean {
  return rankOf(role) >= (ROLE_RANK[min] ?? 0)
}

// Per-resource action permissions. "write" covers POST/PUT/PATCH/DELETE/action.
// Scoped resources are always owner-org restricted (enforced separately).
export const RESOURCE_ACTIONS: Record<string, { read: Role[]; write: Role[] }> = {
  organizations: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['org_admin', 'super_admin'] },
  projects: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['project_admin', 'org_admin', 'super_admin'] },
  targets: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  campaigns: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  executions: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  evidence: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  findings: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  attack_graphs: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['analyst' as Role, 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'].filter((r) => r !== 'analyst') as Role[] },
  regression_tests: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  reports: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  knowledge: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  'digital-twins': { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  risk_graphs: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['user', 'service_account', 'project_admin', 'org_admin', 'super_admin'] },
  analytics: { read: ['viewer', 'user', 'service_account', 'project_admin', 'org_admin', 'super_admin'], write: ['org_admin', 'super_admin'] },
  'audit-logs': { read: ['org_admin', 'super_admin'], write: ['super_admin'] },
}

export function can(role: string, resource: string, action: 'read' | 'write'): boolean {
  const def = RESOURCE_ACTIONS[resource]
  if (!def) return false
  return def[action].includes(role as Role)
}

// In-memory tenant-scoped store used by the platform API enforcement layer.
// Every tenant-owned resource carries `organizationId` so that authorization
// can be resolved as:  User -> Organization -> Project -> Resource.

import { randomUUID } from 'crypto'

export interface OrgScoped {
  id: string
  organizationId: string
  projectId?: string
  ownerId?: string
  [key: string]: unknown
}

export interface UserRecord {
  id: string
  email: string
  password: string // in-memory test harness only; never persisted in plaintext in prod
  name: string
  role: string
  organizationId: string
  type: 'user' | 'service_account'
  scopes: string[]
}

export interface OrgRecord {
  id: string
  name: string
  description?: string
}

export interface RefreshRecord {
  jti: string
  family: string
  userId: string
  organizationId: string
  role: string
  scopes?: string[]
  expiresAt: number
  revoked: boolean
}

export interface ServiceAccount {
  id: string
  name: string
  organizationId: string
  scopes: string[]
  jti: string
  revoked: boolean
  createdAt: number
  rotatedAt?: number
}

export interface LoginAttempt {
  count: number
  lockedUntil: number
}

type CollectionName =
  | 'targets'
  | 'campaigns'
  | 'executions'
  | 'evidence'
  | 'findings'
  | 'reports'
  | 'knowledge'
  | 'digital_twins'
  | 'audit_logs'

const RESOURCE_KEYS: Record<string, CollectionName> = {
  targets: 'targets',
  campaigns: 'campaigns',
  executions: 'executions',
  evidence: 'evidence',
  findings: 'findings',
  reports: 'reports',
  knowledge: 'knowledge',
  'digital-twins': 'digital_twins',
  'audit-logs': 'audit_logs',
}

class TenantStore {
  orgs = new Map<string, OrgRecord>()
  users = new Map<string, UserRecord>() // keyed by email
  usersById = new Map<string, UserRecord>()
  projects = new Map<string, OrgScoped>()

  // Revocation: jti of any access/refresh token that has been revoked.
  revokedJtis = new Set<string>()

  // Refresh-token rotation + reuse detection state.
  refreshTokens = new Map<string, RefreshRecord>() // keyed by jti
  refreshFamilies = new Map<string, string>() // family -> current valid jti

  // Service accounts (api keys).
  serviceAccounts = new Map<string, ServiceAccount>() // keyed by id

  // Auth-abuse controls.
  loginAttempts = new Map<string, LoginAttempt>() // keyed by email

  collections: Record<CollectionName, Map<string, OrgScoped>> = {
    targets: new Map(),
    campaigns: new Map(),
    executions: new Map(),
    evidence: new Map(),
    findings: new Map(),
    reports: new Map(),
    knowledge: new Map(),
    digital_twins: new Map(),
    audit_logs: new Map(),
  }

  reset() {
    this.orgs.clear()
    this.users.clear()
    this.usersById.clear()
    this.projects.clear()
    this.revokedJtis.clear()
    this.refreshTokens.clear()
    this.refreshFamilies.clear()
    this.serviceAccounts.clear()
    this.loginAttempts.clear()
    for (const m of Object.values(this.collections)) m.clear()
  }

  isRevoked(jti?: string): boolean {
    return !!jti && this.revokedJtis.has(jti)
  }

  revokeJti(jti?: string) {
    if (jti) this.revokedJtis.add(jti)
  }

  // Revoke an entire refresh-token family (used on reuse detection).
  revokeFamily(family: string) {
    for (const rec of this.refreshTokens.values()) {
      if (rec.family === family) {
        rec.revoked = true
        this.revokedJtis.add(rec.jti)
      }
    }
  }

  // ---- Auth abuse controls ----
  MAX_LOGIN_ATTEMPTS = 5
  LOGIN_LOCK_MS = 15 * 60 * 1000

  recordLoginFailure(email: string) {
    const prev = this.loginAttempts.get(email)
    const count = (prev?.count ?? 0) + 1
    const lockedUntil = count >= this.MAX_LOGIN_ATTEMPTS ? Date.now() + this.LOGIN_LOCK_MS : 0
    this.loginAttempts.set(email, { count, lockedUntil })
  }

  clearLoginFailures(email: string) {
    this.loginAttempts.delete(email)
  }

  loginLockedUntil(email: string): number {
    return this.loginAttempts.get(email)?.lockedUntil ?? 0
  }

  // ---- Service accounts ----
  createServiceAccount(sa: ServiceAccount) {
    this.serviceAccounts.set(sa.id, sa)
    return sa
  }

  getServiceAccount(id: string): ServiceAccount | undefined {
    return this.serviceAccounts.get(id)
  }

  listServiceAccounts(organizationId: string): ServiceAccount[] {
    return [...this.serviceAccounts.values()].filter((s) => s.organizationId === organizationId)
  }

  createOrg(name: string, description?: string): OrgRecord {
    const org: OrgRecord = { id: randomUUID(), name, description }
    this.orgs.set(org.id, org)
    return org
  }

  createUser(u: Omit<UserRecord, 'id'>): UserRecord {
    const user: UserRecord = { ...u, id: randomUUID() }
    this.users.set(user.email, user)
    this.usersById.set(user.id, user)
    return user
  }

  createProject(organizationId: string, name: string): OrgScoped {
    const p: OrgScoped = { id: randomUUID(), organizationId, name }
    this.projects.set(p.id, p)
    return p
  }

  /** All tenant-scoped collections keyed by the URL resource segment. */
  resourceMap(): Record<string, Map<string, OrgScoped>> {
    const out: Record<string, Map<string, OrgScoped>> = {}
    for (const [urlKey, colName] of Object.entries(RESOURCE_KEYS)) {
      out[urlKey] = this.collections[colName]
    }
    return out
  }

  collectionFor(urlKey: string): Map<string, OrgScoped> | undefined {
    const colName = RESOURCE_KEYS[urlKey]
    return colName ? this.collections[colName] : undefined
  }

  insert(urlKey: string, organizationId: string, data: Record<string, unknown>): OrgScoped {
    const col = this.collectionFor(urlKey)
    if (!col) throw new Error(`Unknown resource: ${urlKey}`)
    // Server-derived tenant scoping: any client-supplied organizationId in the
    // body is ignored and overwritten with the authenticated principal's org.
    const record: OrgScoped = { id: randomUUID(), ...data, organizationId }
    col.set(record.id, record)
    return record
  }
}

export const store = new TenantStore()
export { RESOURCE_KEYS }

import express, { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { timingSafeEqual } from 'crypto'
import {
  authenticate,
  requireMinRole,
  requireScopeFor,
  enforceOwnership,
  type AuthedRequest,
} from '../auth/expressAuth'
import { can, type Role } from '../core/rbac'
import { store } from '../core/store'
import {
  issueUserSession,
  rotateRefresh,
  revokeSessionByJti,
  issueServiceAccount,
  rotateServiceAccount,
  revokeServiceAccount,
  TokenReuseError,
  TokenRevokedError,
} from '../auth/sessions'

const app = express()

app.use(helmet())
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }))
app.use(express.json({ limit: '10mb' }))

// Global abuse throttle.
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false })
app.use(limiter)

// Stricter throttle on credential endpoints.
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false })

// Constant-time-ish password compare to avoid trivial timing side channels.
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

// ----- Auth (issues tokens with claims derived from the identity store) -----
app.post('/api/auth/register', authLimiter, async (req: Request, res: Response) => {
  const { email, password, name, organizationId, role } = req.body ?? {}
  if (!email || !password || !organizationId) {
    return res.status(400).json({ error: 'email, password and organizationId are required' })
  }
  if (store.users.has(email)) {
    return res.status(409).json({ error: 'Email already registered' })
  }
  if (!store.orgs.has(organizationId)) {
    return res.status(400).json({ error: 'Unknown organization' })
  }
  const user = store.createUser({
    email,
    password,
    name: name || email,
    role: role || 'user',
    organizationId,
    type: 'user',
    scopes: [],
  })
  const session = await issueUserSession(user)
  return res.status(201).json({
    token: session.accessToken,
    refreshToken: session.refreshToken,
    userId: user.id,
    organizationId: user.organizationId,
    role: user.role,
  })
})

app.post('/api/auth/login', authLimiter, async (req: Request, res: Response) => {
  const { email, password } = req.body ?? {}

  // Account lockout on repeated failures (brute-force protection).
  const lockedUntil = store.loginLockedUntil(email)
  if (lockedUntil && lockedUntil > Date.now()) {
    const retryAfter = Math.ceil((lockedUntil - Date.now()) / 1000)
    res.set('Retry-After', String(retryAfter))
    return res.status(429).json({
      error: 'Account temporarily locked due to repeated failures',
      code: 'ACCOUNT_LOCKED',
      retryAfter,
    })
  }

  const user = store.users.get(email)
  if (!user || !safeEqual(user.password, password)) {
    if (email) store.recordLoginFailure(email)
    return res.status(401).json({ error: 'Invalid credentials', code: 'AUTH_INVALID' })
  }

  store.clearLoginFailures(email)
  const session = await issueUserSession(user)
  return res.json({
    token: session.accessToken,
    refreshToken: session.refreshToken,
    userId: user.id,
    organizationId: user.organizationId,
    role: user.role,
  })
})

// Refresh-token rotation. Presenting a rotated-out token triggers reuse
// detection and family revocation.
app.post('/api/auth/refresh', authLimiter, async (req: Request, res: Response) => {
  const { refreshToken } = req.body ?? {}
  if (!refreshToken) return res.status(400).json({ error: 'refreshToken required' })
  try {
    const session = await rotateRefresh(refreshToken)
    return res.json(session)
  } catch (e) {
    if (e instanceof TokenReuseError) {
      return res.status(401).json({ error: e.message, code: 'TOKEN_REUSE' })
    }
    if (e instanceof TokenRevokedError) {
      return res.status(401).json({ error: e.message, code: 'TOKEN_REVOKED' })
    }
    return res.status(401).json({ error: 'Invalid refresh token', code: 'AUTH_INVALID' })
  }
})

// Logout: revoke the presented access token (and its refresh family).
app.post('/api/auth/revoke', authenticate, (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  revokeSessionByJti(auth.jti)
  res.json({ ok: true })
})

// ----- Service accounts -----
app.get('/api/service-accounts', authenticate, requireMinRole('org_admin'), (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const items = store.listServiceAccounts(auth.organizationId).map((s) => ({
    id: s.id,
    name: s.name,
    scopes: s.scopes,
    revoked: s.revoked,
    createdAt: s.createdAt,
    rotatedAt: s.rotatedAt,
  }))
  res.json(items)
})

app.post('/api/service-accounts', authenticate, requireMinRole('org_admin'), async (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const { name, scopes } = req.body ?? {}
  if (!name || !Array.isArray(scopes) || scopes.some((s: unknown) => typeof s !== 'string')) {
    return res.status(400).json({ error: 'name and scopes[] are required' })
  }
  const sa = await issueServiceAccount({ organizationId: auth.organizationId, name, scopes })
  res.status(201).json({ id: sa.id, token: sa.token })
})

app.post('/api/service-accounts/:id/rotate', authenticate, requireMinRole('org_admin'), async (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const sa = store.getServiceAccount(req.params.id)
  if (!sa || sa.organizationId !== auth.organizationId) {
    return res.status(404).json({ error: 'Not found' })
  }
  try {
    const token = await rotateServiceAccount(sa.id)
    res.json({ id: sa.id, token })
  } catch (e) {
    return res.status(401).json({ error: 'service account revoked' })
  }
})

app.post('/api/service-accounts/:id/revoke', authenticate, requireMinRole('org_admin'), (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const sa = store.getServiceAccount(req.params.id)
  if (!sa || sa.organizationId !== auth.organizationId) {
    return res.status(404).json({ error: 'Not found' })
  }
  revokeServiceAccount(sa.id)
  res.json({ ok: true })
})

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', api: 'platform-enforcement', timestamp: new Date().toISOString() })
})

// ----- Generic tenant-scoped resource routes -----
// Each resource is owned by an organization; orgId is derived from the JWT,
// never from the request body. Service accounts must additionally present an
// explicit <resource>:<read|write> scope.
const RESOURCES: { key: string; read: Role; write: Role }[] = [
  { key: 'targets', read: 'viewer', write: 'user' },
  { key: 'campaigns', read: 'viewer', write: 'user' },
  { key: 'executions', read: 'viewer', write: 'user' },
  { key: 'evidence', read: 'viewer', write: 'user' },
  { key: 'findings', read: 'viewer', write: 'user' },
  { key: 'reports', read: 'viewer', write: 'user' },
  { key: 'knowledge', read: 'viewer', write: 'user' },
  { key: 'digital-twins', read: 'viewer', write: 'user' },
  { key: 'audit-logs', read: 'org_admin', write: 'super_admin' },
]

for (const r of RESOURCES) {
  // LIST — only records owned by the caller's organization (super_admin sees all).
  app.get(
    `/api/${r.key}`,
    authenticate,
    requireMinRole(r.read),
    requireScopeFor(r.key, 'read'),
    (req: Request, res: Response) => {
      const auth = (req as AuthedRequest).auth!
      const col = store.collectionFor(r.key)!
      const items = [...col.values()].filter(
        (rec) => auth.role === 'super_admin' || rec.organizationId === auth.organizationId,
      )
      res.json(items)
    },
  )

  // CREATE — organizationId is forced from the JWT, never the body.
  app.post(
    `/api/${r.key}`,
    authenticate,
    requireMinRole(r.write),
    requireScopeFor(r.key, 'write'),
    (req: Request, res: Response) => {
      const auth = (req as AuthedRequest).auth!
      if (!can(auth.role, r.key, 'write')) {
        return res.status(403).json({ error: 'Forbidden', code: 'INSUFFICIENT_ROLE' })
      }
      const record = store.insert(r.key, auth.organizationId, { ...req.body, ownerId: auth.sub })
      res.status(201).json(record)
    },
  )

  // READ by id — hidden (404) if it belongs to another organization.
  app.get(
    `/api/${r.key}/:id`,
    authenticate,
    requireMinRole(r.read),
    requireScopeFor(r.key, 'read'),
    enforceOwnership(r.key, false),
    (req: Request, res: Response) => {
      res.json((req as AuthedRequest & { resource?: unknown }).resource)
    },
  )

  // UPDATE — denied (403) if it belongs to another organization.
  app.put(
    `/api/${r.key}/:id`,
    authenticate,
    requireMinRole(r.write),
    requireScopeFor(r.key, 'write'),
    enforceOwnership(r.key, true),
    (req: Request, res: Response) => {
      const record = (req as AuthedRequest & { resource?: any }).resource
      Object.assign(record, req.body, { id: record.id, organizationId: record.organizationId })
      res.json(record)
    },
  )
  app.patch(
    `/api/${r.key}/:id`,
    authenticate,
    requireMinRole(r.write),
    requireScopeFor(r.key, 'write'),
    enforceOwnership(r.key, true),
    (req: Request, res: Response) => {
      const record = (req as AuthedRequest & { resource?: any }).resource
      Object.assign(record, req.body, { id: record.id, organizationId: record.organizationId })
      res.json(record)
    },
  )

  // DELETE — denied (403) if it belongs to another organization.
  app.delete(
    `/api/${r.key}/:id`,
    authenticate,
    requireMinRole(r.write),
    requireScopeFor(r.key, 'write'),
    enforceOwnership(r.key, true),
    (req: Request, res: Response) => {
      store.collectionFor(r.key)!.delete(req.params.id)
      res.status(204).end()
    },
  )

  // ACTION — denied (403) if it belongs to another organization.
  app.post(
    `/api/${r.key}/:id/action`,
    authenticate,
    requireMinRole(r.write),
    requireScopeFor(r.key, 'write'),
    enforceOwnership(r.key, true),
    (req: Request, res: Response) => {
      const record = (req as AuthedRequest & { resource?: any }).resource
      res.json({ ok: true, id: record.id, action: req.body?.action })
    },
  )
}

// Projects (org-scoped, used to resolve the hierarchy).
app.get('/api/projects', authenticate, (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const items = [...store.projects.values()].filter(
    (p) => auth.role === 'super_admin' || p.organizationId === auth.organizationId,
  )
  res.json(items)
})
app.post('/api/projects', authenticate, requireMinRole('project_admin'), (req: Request, res: Response) => {
  const auth = (req as AuthedRequest).auth!
  const project = store.createProject(auth.organizationId, req.body?.name || 'project')
  res.status(201).json(project)
})

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found' })
})

const PORT = process.env.PORT || 3000
const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`🚀 Platform API (enforcement) listening on ${PORT}`)
})

export { app, server }

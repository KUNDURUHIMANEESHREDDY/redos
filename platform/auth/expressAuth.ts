import type { Request, Response, NextFunction } from 'express'
import { verifyToken, type AuthClaims } from '../auth/jwt'
import { atLeast, rankOf, type Role } from '../core/rbac'
import { store } from '../core/store'

export interface AuthedRequest extends Request {
  auth?: AuthClaims
}

/** 401 when missing/invalid/expired. Never throws unverified claims forward. */
export function authenticate(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthenticated', code: 'AUTH_REQUIRED' })
  }
  const token = header.slice('Bearer '.length).trim()
  verifyToken(token)
    .then((claims) => {
      // Revocation check (covers access-token logout and reuse-detected families).
      if (store.isRevoked(claims.jti)) {
        return res.status(401).json({ error: 'Token revoked', code: 'TOKEN_REVOKED' })
      }
      ;(req as AuthedRequest).auth = claims
      next()
    })
    .catch(() => res.status(401).json({ error: 'Invalid or expired token', code: 'AUTH_INVALID' }))
}

/** Require the authenticated principal to hold at least `min` role. */
export function requireMinRole(min: Role) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = (req as AuthedRequest).auth
    if (!auth) return res.status(401).json({ error: 'Unauthenticated', code: 'AUTH_REQUIRED' })
    if (!atLeast(auth.role, min)) {
      return res.status(403).json({ error: 'Forbidden: insufficient role', code: 'INSUFFICIENT_ROLE' })
    }
    next()
  }
}

export function requireRole(role: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = (req as AuthedRequest).auth
    if (!auth) return res.status(401).json({ error: 'Unauthenticated', code: 'AUTH_REQUIRED' })
    if (auth.role !== role && rankOf(auth.role) < rankOf('super_admin')) {
      return res.status(403).json({ error: `Forbidden: requires ${role}`, code: 'INSUFFICIENT_ROLE' })
    }
    next()
  }
}

/**
 * Resolve and enforce tenant ownership of a resource addressed by
 *   GET/PUT/PATCH/DELETE /api/:resource/:id
 * The owning organization is taken from the resource record, NEVER from the
 * request body/query (no frontend-supplied orgId). Cross-org reads are hidden
 * (404); cross-org writes/actions are denied (403).
 */
export function enforceOwnership(resourceKey: string, write = false) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = (req as AuthedRequest).auth
    if (!auth) return res.status(401).json({ error: 'Unauthenticated', code: 'AUTH_REQUIRED' })
    const col = store.collectionFor(resourceKey)
    if (!col) return res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' })
    const record = col.get(req.params.id)
    if (!record) return res.status(404).json({ error: 'Not found', code: 'NOT_FOUND' })
    const isSuper = auth.role === 'super_admin'
    if (record.organizationId !== auth.organizationId && !isSuper) {
      // Hide existence for reads, deny for writes/actions.
      return res.status(write ? 403 : 404).json({
        error: write ? 'Forbidden: resource belongs to another organization' : 'Not found',
        code: write ? 'ORG_MISMATCH' : 'NOT_FOUND',
      })
    }
    ;(req as AuthedRequest & { resource?: unknown }).resource = record
    next()
  }
}

/**
 * Scoped authorization for service accounts. Human principals (type 'user')
 * are governed by RBAC roles; service accounts are non-interactive and must
 * hold an explicit scope `<resource>:<read|write>` for the action they invoke.
 */
export function requireScopeFor(resourceKey: string, action: 'read' | 'write') {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = (req as AuthedRequest).auth
    if (!auth) return res.status(401).json({ error: 'Unauthenticated', code: 'AUTH_REQUIRED' })
    if (auth.type !== 'service_account') return next()
    const scope = `${resourceKey}:${action}`
    if (!auth.scopes?.includes(scope)) {
      return res.status(403).json({
        error: `Forbidden: service account missing scope "${scope}"`,
        code: 'MISSING_SCOPE',
      })
    }
    next()
  }
}

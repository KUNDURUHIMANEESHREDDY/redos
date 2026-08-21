// Session + token lifecycle: refresh-token rotation with reuse detection,
// revocation, and service-account issuance/rotation/revocation.
// All token state is tracked server-side so that a leaked/duplicated refresh
// token or service-account key can be invalidated and replay detected.

import { randomUUID } from 'crypto'
import { signToken, verifyToken, type AuthClaims } from '../auth/jwt'
import { store } from '../core/store'

const REFRESH_TTL = '14d'
const ACCESS_TTL = '30m'

export class TokenReuseError extends Error {}
export class TokenRevokedError extends Error {}

export interface SessionTokens {
  accessToken: string
  refreshToken: string
}

// Issue an access + refresh token pair for a user principal and register the
// refresh token. `family` is preserved across rotations so that a leaked/
// duplicated refresh token can be detected via family-current mismatch.
export async function issueUserSession(
  user: {
    id: string
    email: string
    role: string
    organizationId: string
    scopes?: string[]
  },
  family: string = randomUUID(),
): Promise<SessionTokens> {
  const refreshJti = randomUUID()
  const accessJti = randomUUID()

  const accessToken = await signToken(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      type: 'user',
      scopes: user.scopes,
      jti: accessJti,
      tokenUse: 'access',
    },
    ACCESS_TTL,
  )

  const refreshToken = await signToken(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      organizationId: user.organizationId,
      type: 'user',
      scopes: user.scopes,
      jti: refreshJti,
      tokenUse: 'refresh',
    },
    REFRESH_TTL,
  )

  store.refreshTokens.set(refreshJti, {
    jti: refreshJti,
    family,
    userId: user.id,
    organizationId: user.organizationId,
    role: user.role,
    scopes: user.scopes,
    expiresAt: Date.now() + ms(REFRESH_TTL),
    revoked: false,
  })
  store.refreshFamilies.set(family, refreshJti)

  return { accessToken, refreshToken }
}

// Rotate a refresh token: issue a brand-new access+refresh pair while
// invalidating the presented refresh token. If the presented token's jti is no
// longer the current jti for its family, we assume the refresh token was
// duplicated/captured and revoke the entire family (reuse detection).
export async function rotateRefresh(refreshToken: string): Promise<SessionTokens> {
  const claims = await verifyToken(refreshToken)
  if (claims.tokenUse !== 'refresh') throw new TokenRevokedError('invalid token use')

  const jti = claims.jti
  const record = jti ? store.refreshTokens.get(jti) : undefined
  if (!record || record.revoked || store.isRevoked(jti)) {
    throw new TokenRevokedError('refresh token revoked')
  }

  const currentJti = store.refreshFamilies.get(record.family)
  if (currentJti !== jti) {
    // Reuse detected: the token is valid but not the latest issued for the
    // family. Treat the whole family as compromised and revoke it.
    store.revokeFamily(record.family)
    throw new TokenReuseError('refresh token reuse detected; family revoked')
  }

  // Rotate: advance the family pointer to a freshly minted refresh token,
  // keeping the SAME family so a replay of the old token is detected as reuse.
  return issueUserSession(
    {
      id: claims.sub,
      email: claims.email,
      role: claims.role,
      organizationId: claims.organizationId,
      scopes: claims.scopes,
    },
    record.family,
  )
}

// Revoke the current access token (logout) and its refresh family by jti.
export function revokeSessionByJti(jti?: string) {
  if (!jti) return
  store.revokeJti(jti)
  const rec = store.refreshTokens.get(jti)
  if (rec) {
    // If the jti is a refresh token, also revoke its whole family.
    store.revokeFamily(rec.family)
  }
}

// ---- Service accounts ----
export async function issueServiceAccount(params: {
  organizationId: string
  name: string
  scopes: string[]
}): Promise<{ id: string; token: string }> {
  const id = randomUUID()
  const jti = randomUUID()
  const token = await signToken(
    {
      sub: id,
      email: `${params.name}@service-account`,
      role: 'service_account',
      organizationId: params.organizationId,
      type: 'service_account',
      scopes: params.scopes,
      jti,
      tokenUse: 'access',
    },
    '1y',
  )
  store.createServiceAccount({
    id,
    name: params.name,
    organizationId: params.organizationId,
    scopes: params.scopes,
    jti,
    revoked: false,
    createdAt: Date.now(),
  })
  return { id, token }
}

export async function rotateServiceAccount(id: string): Promise<string> {
  const sa = store.getServiceAccount(id)
  if (!sa || sa.revoked) throw new TokenRevokedError('service account not found or revoked')
  // Invalidate the previous key.
  store.revokeJti(sa.jti)
  const jti = randomUUID()
  const token = await signToken(
    {
      sub: id,
      email: `${sa.name}@service-account`,
      role: 'service_account',
      organizationId: sa.organizationId,
      type: 'service_account',
      scopes: sa.scopes,
      jti,
      tokenUse: 'access',
    },
    '1y',
  )
  sa.jti = jti
  sa.rotatedAt = Date.now()
  return token
}

export function revokeServiceAccount(id: string) {
  const sa = store.getServiceAccount(id)
  if (!sa) return
  sa.revoked = true
  store.revokeJti(sa.jti)
}

function ms(duration: string): number {
  const m = /^(\d+)([smhd])$/.exec(duration)
  if (!m) return 0
  const n = parseInt(m[1], 10)
  const unit = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]]
  return n * unit
}

export type { AuthClaims }

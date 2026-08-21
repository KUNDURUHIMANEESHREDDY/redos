import { SignJWT, jwtVerify, type JWTPayload } from 'jose'

// Only HS256 is permitted. Explicitly rejecting "none" and any asymmetric alg
// prevents the classic algorithm-confusion attack (RS256->HS256 key confusion).
const ALG = 'HS256'

export type PrincipalType = 'user' | 'service_account'
export type TokenUse = 'access' | 'refresh'

export interface AuthClaims extends JWTPayload {
  sub: string
  email: string
  role: string
  organizationId: string
  type: PrincipalType
  scopes?: string[]
  // Session/revocation support
  jti?: string
  tokenUse?: TokenUse
}

function getSecret(): Uint8Array {
  const secret = process.env.JWT_SECRET ?? process.env.SECRET_KEY
  if (!secret) {
    throw new Error('JWT_SECRET (or SECRET_KEY) must be configured; refusing to sign/verify tokens')
  }
  return new TextEncoder().encode(secret)
}

export async function signToken(claims: AuthClaims, expiresIn = '30m'): Promise<string> {
  const { sub, email, role, organizationId, type, scopes, jti, tokenUse, ...rest } = claims
  let builder = new SignJWT({ email, role, organizationId, type, scopes, tokenUse, ...rest })
    .setProtectedHeader({ alg: ALG, typ: 'JWT' })
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
  if (jti) builder = builder.setJti(jti)
  return await builder.sign(getSecret())
}

export async function verifyToken(token: string): Promise<AuthClaims> {
  const { payload } = await jwtVerify(token, getSecret(), {
    algorithms: [ALG],
  })
  if (!payload.sub || !payload.organizationId || !payload.role) {
    throw new Error('Token missing required claims')
  }
  return payload as unknown as AuthClaims
}

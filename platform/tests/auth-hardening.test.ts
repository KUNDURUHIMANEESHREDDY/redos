// Authentication-hardening acceptance tests: refresh rotation + reuse
// detection, revocation, service-account issuance/rotation/revocation with
// scoped authorization, and brute-force lockout. This file is additive and does
// not modify the tenant/IDOR/RBAC suite.

process.env.PORT = '3100'

import { store } from '../core/store'
import request from 'supertest'
import { describe, it, expect, beforeEach } from 'vitest'

const { app } = await import('../api/index')

async function registerLogin(email: string, role: string) {
  const org = store.createOrg('Org')
  await request(app)
    .post('/api/auth/register')
    .send({ email, password: 'pw', name: email, organizationId: org.id, role })
  const login = await request(app).post('/api/auth/login').send({ email, password: 'pw' })
  return { orgId: org.id, token: login.body.token, refreshToken: login.body.refreshToken }
}

beforeEach(() => {
  store.reset()
})

describe('refresh-token rotation', () => {
  it('rotates the refresh token and keeps the new family usable', async () => {
    const { refreshToken: rt1 } = await registerLogin('ro@orga.com', 'user')
    const r1 = await request(app).post('/api/auth/refresh').send({ refreshToken: rt1 })
    expect(r1.status).toBe(200)
    expect(r1.body.refreshToken).toBeTruthy()
    expect(r1.body.refreshToken).not.toBe(rt1)

    const r2 = await request(app).post('/api/auth/refresh').send({ refreshToken: r1.body.refreshToken })
    expect(r2.status).toBe(200)
  })

  it('detects reuse of a rotated-out refresh token and revokes the family', async () => {
    const { refreshToken: rt1 } = await registerLogin('reuse@orga.com', 'user')
    const r1 = await request(app).post('/api/auth/refresh').send({ refreshToken: rt1 })
    expect(r1.status).toBe(200)

    // Replay the original token after it was rotated out.
    const replay = await request(app).post('/api/auth/refresh').send({ refreshToken: rt1 })
    expect(replay.status).toBe(401)
    expect(replay.body.code).toBe('TOKEN_REUSE')

    // The rotated token is now also invalid (family revoked).
    const afterFamily = await request(app).post('/api/auth/refresh').send({ refreshToken: r1.body.refreshToken })
    expect(afterFamily.status).toBe(401)
  })
})

describe('revocation', () => {
  it('rejects a revoked access token', async () => {
    const { token } = await registerLogin('rev@orga.com', 'user')
    const revoke = await request(app).post('/api/auth/revoke').set('Authorization', `Bearer ${token}`)
    expect(revoke.status).toBe(200)
    const res = await request(app).get('/api/targets').set('Authorization', `Bearer ${token}`)
    expect(res.status).toBe(401)
    expect(res.body.code).toBe('TOKEN_REVOKED')
  })
})

describe('service-account issuance + scoped authorization', () => {
  it('issues a service account and enforces scopes', async () => {
    const { token: adminToken } = await registerLogin('sa-admin@orga.com', 'org_admin')
    const create = await request(app)
      .post('/api/service-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'ci-bot', scopes: ['targets:read', 'targets:write'] })
    expect(create.status).toBe(201)
    const saToken = create.body.token

    const read = await request(app).get('/api/targets').set('Authorization', `Bearer ${saToken}`)
    expect(read.status).toBe(200)

    const write = await request(app)
      .post('/api/targets')
      .set('Authorization', `Bearer ${saToken}`)
      .send({ name: 'x' })
    expect(write.status).toBe(201)
  })

  it('denies a service account lacking the required scope', async () => {
    const { token: adminToken } = await registerLogin('sa-admin2@orga.com', 'org_admin')
    const create = await request(app)
      .post('/api/service-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'ro-bot', scopes: ['targets:read'] })
    const saToken = create.body.token

    const write = await request(app)
      .post('/api/targets')
      .set('Authorization', `Bearer ${saToken}`)
      .send({ name: 'x' })
    expect(write.status).toBe(403)
    expect(write.body.code).toBe('MISSING_SCOPE')

    const other = await request(app).get('/api/findings').set('Authorization', `Bearer ${saToken}`)
    expect(other.status).toBe(403)
    expect(other.body.code).toBe('MISSING_SCOPE')
  })

  it('rejects service-account creation by a non-admin', async () => {
    const { token: userToken } = await registerLogin('sa-user@orga.com', 'user')
    const create = await request(app)
      .post('/api/service-accounts')
      .set('Authorization', `Bearer ${userToken}`)
      .send({ name: 'no', scopes: ['targets:read'] })
    expect(create.status).toBe(403)
  })
})

describe('service-account rotation + revocation', () => {
  it('rotates a service account and revokes the old key', async () => {
    const { token: adminToken } = await registerLogin('sa-rot-admin@orga.com', 'org_admin')
    const create = await request(app)
      .post('/api/service-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'rot-bot', scopes: ['targets:read'] })
    const id = create.body.id
    const oldToken = create.body.token

    const rotate = await request(app)
      .post(`/api/service-accounts/${id}/rotate`)
      .set('Authorization', `Bearer ${adminToken}`)
    expect(rotate.status).toBe(200)
    const newToken = rotate.body.token
    expect(newToken).not.toBe(oldToken)

    const oldUse = await request(app).get('/api/targets').set('Authorization', `Bearer ${oldToken}`)
    expect(oldUse.status).toBe(401)
    const newUse = await request(app).get('/api/targets').set('Authorization', `Bearer ${newToken}`)
    expect(newUse.status).toBe(200)
  })

  it('revokes a service account', async () => {
    const { token: adminToken } = await registerLogin('sa-rev-admin@orga.com', 'org_admin')
    const create = await request(app)
      .post('/api/service-accounts')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: 'rev-bot', scopes: ['targets:read'] })
    const id = create.body.id
    const saToken = create.body.token

    const rev = await request(app)
      .post(`/api/service-accounts/${id}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
    expect(rev.status).toBe(200)

    const use = await request(app).get('/api/targets').set('Authorization', `Bearer ${saToken}`)
    expect(use.status).toBe(401)
  })
})

describe('authentication abuse controls', () => {
  it('locks the account after repeated failed logins', async () => {
    const attempts = []
    for (let i = 0; i < 5; i++) {
      attempts.push(await request(app).post('/api/auth/login').send({ email: 'brute@orga.com', password: 'wrong' }))
    }
    attempts.forEach((a) => expect(a.status).toBe(401))

    const locked = await request(app).post('/api/auth/login').send({ email: 'brute@orga.com', password: 'wrong' })
    expect(locked.status).toBe(429)
    expect(locked.body.code).toBe('ACCOUNT_LOCKED')
  })
})

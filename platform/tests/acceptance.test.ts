import request from 'supertest'
import { app, server } from '../api/index'
import { store } from '../core/store'
import { describe, it, beforeAll, afterAll, expect } from 'vitest'

// Acceptance gate: Org A user cannot access Org B's tenant-scoped resources.
// Resources covered: targets, executions, evidence, findings, reports,
// campaigns, digital twins, knowledge.

interface Ctx {
  token: string
  orgId: string
  userId: string
}

const RESOURCE_KEYS = [
  'targets',
  'executions',
  'evidence',
  'findings',
  'reports',
  'campaigns',
  'digital-twins',
  'knowledge',
  // audit-logs omitted: write is super_admin-only; route stays tenant-scoped.
]

async function registerAndLogin(email: string, orgId: string, role: string): Promise<Ctx> {
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ email, password: 'password', name: email, organizationId: orgId, role })
  expect(reg.status).toBe(201)
  const login = await request(app).post('/api/auth/login').send({ email, password: 'password' })
  expect(login.status).toBe(200)
  expect(login.body.token).toBeDefined()
  return { token: login.body.token, orgId, userId: reg.body.userId }
}

describe('Tenant Isolation & RBAC Acceptance Gate', () => {
  let orgA: Ctx
  let orgB: Ctx
  const orgBResourceIds: Record<string, string> = {}

  beforeAll(async () => {
    store.reset()
    const a = store.createOrg('Org A')
    const b = store.createOrg('Org B')
    orgA = await registerAndLogin('user-a@orga.com', a.id, 'org_admin')
    orgB = await registerAndLogin('user-b@orgb.com', b.id, 'org_admin')

    // Org B creates one resource of every type.
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .post(`/api/${key}`)
        .set('Authorization', `Bearer ${orgB.token}`)
        .send({ name: `OrgB ${key}`, payload: 'secret' })
      expect(resp.status).toBe(201)
      orgBResourceIds[key] = resp.body.id
    }
  })

  afterAll(() => {
    server.close()
  })

  it('401 when no token is presented', async () => {
    const resp = await request(app).get('/api/targets')
    expect(resp.status).toBe(401)
  })

  it('Org A cannot READ any Org B resource (404 — hidden)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .get(`/api/${key}/${orgBResourceIds[key]}`)
        .set('Authorization', `Bearer ${orgA.token}`)
      expect(resp.status).toBe(404)
      expect(resp.body.organizationId).toBeUndefined()
    }
  })

  it('Org A cannot UPDATE any Org B resource (403)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .put(`/api/${key}/${orgBResourceIds[key]}`)
        .set('Authorization', `Bearer ${orgA.token}`)
        .send({ name: 'hacked' })
      expect(resp.status).toBe(403)
    }
  })

  it('Org A cannot PATCH any Org B resource (403)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .patch(`/api/${key}/${orgBResourceIds[key]}`)
        .set('Authorization', `Bearer ${orgA.token}`)
        .send({ name: 'hacked' })
      expect(resp.status).toBe(403)
    }
  })

  it('Org A cannot DELETE any Org B resource (403)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .delete(`/api/${key}/${orgBResourceIds[key]}`)
        .set('Authorization', `Bearer ${orgA.token}`)
      expect(resp.status).toBe(403)
    }
  })

  it('Org A cannot ACTION any Org B resource (403)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .post(`/api/${key}/${orgBResourceIds[key]}/action`)
        .set('Authorization', `Bearer ${orgA.token}`)
        .send({ action: 'run' })
      expect(resp.status).toBe(403)
    }
  })

  it('Org A never receives Org B data in LIST responses (no leak)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app).get(`/api/${key}`).set('Authorization', `Bearer ${orgA.token}`)
      expect(resp.status).toBe(200)
      expect(Array.isArray(resp.body)).toBe(true)
      expect(resp.body.length).toBe(0)
    }
  })

  it('Org B CAN access its own resources (sanity)', async () => {
    for (const key of RESOURCE_KEYS) {
      const resp = await request(app)
        .get(`/api/${key}/${orgBResourceIds[key]}`)
        .set('Authorization', `Bearer ${orgB.token}`)
      expect(resp.status).toBe(200)
      expect(resp.body.id).toBe(orgBResourceIds[key])
      expect(resp.body.organizationId).toBe(orgB.orgId)
    }
  })

  it('RBAC: viewer cannot create resources (403)', async () => {
    const viewer = await registerAndLogin('viewer@orga.com', orgA.orgId, 'viewer')
    const resp = await request(app)
      .post('/api/targets')
      .set('Authorization', `Bearer ${viewer.token}`)
      .send({ name: 'x' })
    expect(resp.status).toBe(403)
  })

  it('RBAC: org_admin can create resources (201)', async () => {
    const resp = await request(app)
      .post('/api/targets')
      .set('Authorization', `Bearer ${orgA.token}`)
      .send({ name: 'A target' })
    expect(resp.status).toBe(201)
    expect(resp.body.organizationId).toBe(orgA.orgId)
  })

  it('Backend derives orgId from token, ignoring any client-supplied orgId', async () => {
    const resp = await request(app)
      .post('/api/targets')
      .set('Authorization', `Bearer ${orgA.token}`)
      .send({ name: 'ignored', organizationId: orgB.orgId })
    expect(resp.status).toBe(201)
    // Created resource must belong to Org A despite the spoofed body field.
    expect(resp.body.organizationId).toBe(orgA.orgId)
    expect(resp.body.organizationId).not.toBe(orgB.orgId)
  })
})

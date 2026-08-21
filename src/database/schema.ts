import { relations, sql } from 'drizzle-orm'
import { pgTable, text, serial, integer, timestamp, boolean, jsonb } from 'drizzle-orm/pg-core'
import { createInsertSchema } from 'drizzle-zod'
import { z } from 'zod'

// Users table
export const users = pgTable('users', {
  id: text('id').primaryKey().defaultRandom(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  name: text('name'),
  role: text('role').default('user'),
  organizationId: text('organization_id'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
})

// Organizations table
export const organizations = pgTable('organizations', {
  id: text('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
})

// Projects table
export const projects = pgTable('projects', {
  id: text('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  organizationId: text('organization_id').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
})

// Targets table
export const targets = pgTable('targets', {
  id: text('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  organizationId: text('organization_id').notNull(),
  projectId: text('project_id'),
  status: text('status').default('active'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
})

// Attack campaigns table
export const attackCampaigns = pgTable('attack_campaigns', {
  id: text('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  description: text('description'),
  organizationId: text('organization_id').notNull(),
  projectId: text('project_id'),
  status: text('status').default('planning'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
})

// Executions table
export const executions = pgTable('executions', {
  id: text('id').primaryKey().defaultRandom(),
  campaignId: text('campaign_id').notNull(),
  targetId: text('target_id').notNull(),
  status: text('status').default('running'),
  startedAt: timestamp('started_at').defaultNow(),
  completedAt: timestamp('completed_at'),
  output: jsonb('output'),
  exitCode: integer('exit_code'),
})

// Findings table
export const findings = pgTable('findings', {
  id: text('id').primaryKey().defaultRandom(),
  executionId: text('execution_id').notNull(),
  title: text('title').notNull(),
  severity: text('severity').notNull(),
  description: text('description'),
  discoveredAt: timestamp('discovered_at').defaultNow(),
  reproducedAt: timestamp('reproduced_at'),
  status: text('status').default('active'),
})

// Evidence table
export const evidence = pgTable('evidence', {
  id: text('id').primaryKey().defaultRandom(),
  findingId: text('finding_id').notNull(),
  type: text('type').notNull(), // model_output, retrieved_document, tool_call, execution_trace
  content: text('content').notNull(),
  metadata: jsonb('metadata'),
  createdAt: timestamp('created_at').defaultNow(),
})

// API keys table
export const apiKeys = pgTable('api_keys', {
  id: text('id').primaryKey().defaultRandom(),
  keyHash: text('key_hash').notNull(),
  organizationId: text('organization_id').notNull(),
  name: text('name').notNull(),
  permissions: text('permissions').array().default(['read']),
  lastUsed: timestamp('last_used'),
  expiresAt: timestamp('expires_at'),
  createdAt: timestamp('created_at').defaultNow(),
})

// Audit logs table
export const auditLogs = pgTable('audit_logs', {
  id: text('id').primaryKey().defaultRandom(),
  userId: text('user_id').notNull(),
  action: text('action').notNull(),
  resourceType: text('resource_type').notNull(),
  resourceId: text('resource_id').notNull(),
  details: jsonb('details'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').defaultNow(),
})

// Tenant isolation - organization membership
export const organizationMembers = pgTable('organization_members', {
  id: text('id').primaryKey().defaultRandom(),
  organizationId: text('organization_id').notNull(),
  userId: text('user_id').notNull(),
  role: text('role').default('member'),
  createdAt: timestamp('created_at').defaultNow(),
})

// RBAC permissions
export const permissions = pgTable('permissions', {
  id: text('id').primaryKey().defaultRandom(),
  role: text('role').notNull(),
  resource: text('resource').notNull(),
  action: text('action').notNull(),
  conditions: jsonb('conditions'),
})

export const relations = {
  users: relations(users, ({many, one}) => ({
    organization: one(organizations, {
      fields: [users.organizationId],
      references: [organizations.id],
    }),
    members: many(organizationMembers),
  })),
  organizations: relations(organizations, ({many}) => ({
    users: many(organizationMembers),
    projects: many(projects),
    targets: many(targets),
    attackCampaigns: many(attackCampaigns),
    apiKeys: many(apiKeys),
    auditLogs: many(auditLogs),
  })),
  projects: relations(projects, ({one, many}) => ({
    organization: one(organizations, {
      fields: [projects.organizationId],
      references: [organizations.id],
    }),
    targets: many(targets),
    attackCampaigns: many(attackCampaigns),
  })),
  targets: relations(targets, ({one, many}) => ({
    organization: one(organizations, {
      fields: [targets.organizationId],
      references: [organizations.id],
    }),
    project: one(projects, {
      fields: [targets.projectId],
      references: [projects.id],
    }),
    executions: many(executions),
    findings: many(findings),
  })),
  attackCampaigns: relations(attackCampaigns, ({one, many}) => ({
    organization: one(organizations, {
      fields: [attackCampaigns.organizationId],
      references: [organizations.id],
    }),
    project: one(projects, {
      fields: [attackCampaigns.projectId],
      references: [projects.id],
    }),
    executions: many(executions),
  })),
  executions: relations(executions, ({one, many}) => ({
    campaign: one(attackCampaigns, {
      fields: [executions.campaignId],
      references: [attackCampaigns.id],
    }),
    target: one(targets, {
      fields: [executions.targetId],
      references: [targets.id],
    }),
    findings: many(findings),
  })),
  findings: relations(findings, ({one}) => ({
    execution: one(executions, {
      fields: [findings.executionId],
      references: [executions.id],
    }),
    evidence: many(evidence),
  })),
  evidence: relations(evidence, ({one}) => ({
    finding: one(findings, {
      fields: [evidence.findingId],
      references: [findings.id],
    }),
  })),
  apiKeys: relations(apiKeys, ({one}) => ({
    organization: one(organizations, {
      fields: [apiKeys.organizationId],
      references: [organizations.id],
    }),
  })),
  auditLogs: relations(auditLogs, ({one}) => ({
    user: one(users, {
      fields: [auditLogs.userId],
      references: [users.id],
    }),
  })),
}

export const insertUsers = createInsertSchema(users)
export const insertOrganizations = createInsertSchema(organizations)
export const insertProjects = createInsertSchema(projects)
export const insertTargets = createInsertSchema(targets)
export const insertAttackCampaigns = createInsertSchema(attackCampaigns)
export const insertExecutions = createInsertSchema(executions)
export const insertFindings = createInsertSchema(findings)
export const insertEvidence = createInsertSchema(evidence)
export const insertApiKeys = createInsertSchema(apiKeys)
export const insertAuditLogs = createInsertSchema(auditLogs)
export const insertPermissions = createInsertSchema(permissions)
export const insertOrganizationMembers = createInsertSchema(organizationMembers)

// Types
export type User = typeof users.$inferSelect
export type Organization = typeof organizations.$inferSelect
export type Project = typeof projects.$inferSelect
export type Target = typeof targets.$inferSelect
export type AttackCampaign = typeof attackCampaigns.$inferSelect
export type Execution = typeof executions.$inferSelect
export type Finding = typeof findings.$inferSelect
export type Evidence = typeof evidence.$inferSelect
export type ApiKey = typeof apiKeys.$inferSelect
export type AuditLog = typeof auditLogs.$inferSelect
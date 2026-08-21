import { pool } from '../database/connection'
import { users, organizations, projects, targets, attackCampaigns, executions, findings, evidence, apiKeys, auditLogs, organizationMembers } from './schema'
import { AuditTrail } from '../security/hardening'

export interface AuditLogEntry {
  id: string
  userId: string
  action: string
  resourceType: string
  resourceId: string
  details: any
  ipAddress?: string
  userAgent?: string
  createdAt: Date
}

export class AuditLogger {
  static async logAccess(
    userId: string,
    action: string,
    resourceType: 'organization' | 'project' | 'target' | 'campaign' | 'execution' | 'finding' | 'evidence' | 'api-key',
    resourceId: string,
    details?: any
  ): Promise<void> {
    await AuditTrail.logAction(
      userId,
      action,
      resourceType,
      resourceId,
      details
    )

    // Also store in database for persistence
    try {
      await pool.query(
        `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          userId,
          action,
          resourceType,
          resourceId,
          details ? JSON.stringify(details) : null,
          details?.ipAddress,
          details?.userAgent
        ]
      )
    } catch (error) {
      console.error('Failed to write audit log to database:', error)
    }
  }

  static async logAuthentication(
    userId: string,
    action: 'login' | 'logout' | 'failed',
    success: boolean,
    ipAddress: string,
    userAgent: string
  ): Promise<void> {
    await AuditTrail.logAction(
      userId,
      `auth_${action}`,
      'auth',
      'session',
      { action, success },
      ipAddress,
      userAgent
    )
  }

  static async logPermissionCheck(
    userId: string,
    resourceType: string,
    resourceId: string,
    allowed: boolean,
    reason?: string
  ): Promise<void> {
    await AuditTrail.logAction(
      userId,
      `rbac_${allowed ? 'grant' : 'deny'}`,
      'rbac',
      resourceId,
      { resourceType, allowed, reason }
    )
  }
}

export async function logExecutionStart(
  userId: string,
  executionId: string,
  targetId: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  await AuditLogger.logAccess(
    userId,
    'execution_start',
    'execution',
    executionId,
    { targetId, timestamp: new Date().toISOString() },
    ipAddress,
    userAgent
  )
}

export async function logExecutionComplete(
  userId: string,
  executionId: string,
  status: 'completed' | 'failed',
  durationMs: number,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  await AuditLogger.logAccess(
    userId,
    `execution_${status}`,
    'execution',
    executionId,
    { status, durationMs, timestamp: new Date().toISOString() },
    ipAddress,
    userAgent
  )
}

export async function logFindingCreated(
  userId: string,
  findingId: string,
  executionId: string,
  severity: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  await AuditLogger.logAccess(
    userId,
    'finding_create',
    'finding',
    findingId,
    { executionId, severity, timestamp: new Date().toISOString() },
    ipAddress,
    userAgent
  )
}

export async function logEvidenceAccessed(
  userId: string,
  evidenceId: string,
  findingId: string,
  ipAddress: string,
  userAgent: string
): Promise<void> {
  await AuditLogger.logAccess(
    userId,
    'evidence_access',
    'evidence',
    evidenceId,
    { findingId, timestamp: new Date().toISOString() },
    ipAddress,
    userAgent
  )
}
import Bull from 'bull'
import { pool } from '../database/connection'

// Job queues
export const executionQueue = new Bull<'any'>('execution', {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: Number(process.env.REDIS_PORT) || 6379,
  },
})

export const analysisQueue = new Bull<'any'>('analysis', {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: Number(process.env.REDIS_PORT) || 6379,
  },
})

// Process execution jobs
executionQueue.process(async (job) => {
  const { executionId } = job.data
  // TODO: Execute the attack campaign against the target
  console.log(`Processing execution job: ${executionId}`)
  // Mark as completed
  await pool.query(
    'UPDATE executions SET status = $1, completed_at = $2 WHERE id = $3',
    ['completed', new Date(), executionId]
  )
})

// Process analysis jobs
analysisQueue.process(async (job) => {
  const { findingId } = job.data
  // TODO: Analyze findings and generate evidence
  console.log(`Processing analysis job: ${findingId}`)
})

// Queue job functions
export const enqueueExecution = async (executionId: string) => {
  await executionQueue.add({ executionId })
}

export const enqueueAnalysis = async (findingId: string) => {
  await analysisQueue.add({ findingId })
}

// Track job completion and restart survival
export interface JobStatus {
  executionId: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  result?: any
  error?: string
  restarted: boolean
}

// Check if job survived worker restart
export const checkJobRecovery = async (executionId: string): Promise<JobStatus> => {
  const result = await pool.query(
    'SELECT * FROM executions WHERE id = $1',
    [executionId]
  )
  if (result.rows.length === 0) {
    return { executionId, status: 'not_found', progress: 0, restarted: false }
  }
  const row = result.rows[0]
  return {
    executionId,
    status: row.status as JobStatus['status'],
    progress: row.status === 'completed' ? 100 : row.status === 'running' ? 50 : 0,
    restarted: false, // Track via metadata if needed
  }
}
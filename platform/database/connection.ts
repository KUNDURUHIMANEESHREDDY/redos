import { Pool } from 'pg'

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
})

pool.on('connect', () => {
  console.log('📦 Database connection pool created')
})

pool.on('error', (err) => {
  console.error('📦 Database pool error', err)
  process.exit(1)
})
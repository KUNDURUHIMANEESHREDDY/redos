import { Pool } from 'pg'

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
})

pool.on('connect', () => {
  console.log('📦 Database connected')
})

pool.on('error', (err) => {
  console.error('📦 Database error', err)
  process.exit(1)
})
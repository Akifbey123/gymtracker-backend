import { serve } from '@hono/node-server'
import dotenv from 'dotenv'
import app from './app.js'

dotenv.config()

const port = 5001
console.log(`Server is running on port ${port}`)

serve({
  fetch: app.fetch,
  port
})
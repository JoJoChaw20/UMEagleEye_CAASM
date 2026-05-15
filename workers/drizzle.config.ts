import { defineConfig } from 'drizzle-kit'
import * as fs from 'fs'
import * as path from 'path'

// Load .env from project root (parent of workers/)
const envFile = path.resolve(__dirname, '../.env')
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf-8').split('\n')) {
    const m = line.match(/^([^#\s][^=]*)=(.*)$/)
    if (m) process.env[m[1]!.trim()] = m[2]!.trim()
  }
}

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env['DATABASE_URL']!,
  },
})

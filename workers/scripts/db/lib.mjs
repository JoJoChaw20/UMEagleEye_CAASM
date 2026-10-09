// Shared helpers for the db scripts: env-file loading with target checks.
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

export function die(msg) {
  console.error(`\nERROR: ${msg}`)
  process.exit(1)
}

export function parseEnvFile(file) {
  const vars = {}
  for (const raw of readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq < 1) continue
    vars[line.slice(0, eq).trim()] = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2')
  }
  return vars
}

export function loadEnvFile(target) {
  const file = path.join(ROOT, `.env.${target}`)
  if (!existsSync(file)) die(`${file} not found. Copy .env.${target}.example and fill it in.`)
  const vars = parseEnvFile(file)
  if (vars.DB_TARGET !== target) {
    die(`${path.basename(file)} has DB_TARGET="${vars.DB_TARGET ?? ''}" but you asked for "${target}". Refusing.`)
  }
  const url = vars.DATABASE_URL
  if (!url || !/^postgres(ql)?:\/\//.test(url)) {
    die('DATABASE_URL must start with postgresql:// (not postgresql+asyncpg://).')
  }
  return vars
}

export function describe(url) {
  const u = new URL(url)
  return `${u.hostname}${u.pathname}`
}

// Hostname of the production database from .env.production, or null if that file is absent.
export function productionHost() {
  const file = path.join(ROOT, '.env.production')
  if (!existsSync(file)) return null
  const url = parseEnvFile(file).DATABASE_URL
  return url ? new URL(url).hostname : null
}

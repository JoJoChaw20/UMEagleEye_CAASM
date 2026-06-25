const fs = require('fs');
const { Pool } = require('pg');
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL env var is required, e.g. DATABASE_URL=postgresql://... node import-csv.js');
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
      else { inQuotes = !inQuotes; }
    } else if (ch === ',' && !inQuotes) {
      result.push(current.trim()); current = '';
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

async function importCsv(tenantId, filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  const headers = parseCSVLine(lines[0]);
  
  for (let i = 1; i < lines.length; i++) {
    const row = parseCSVLine(lines[i]);
    const d = {};
    headers.forEach((h, idx) => d[h] = row[idx]);
    
    const ipAddress = d.ip_address;
    if (!ipAddress) continue;
    
    const hostname = d.hostname || null;
    const macAddress = d.mac_address || null;
    const owner = d.owner || null;
    const deviceType = d.device_type || 'unknown';
    const criticalityScore = parseInt(d.criticality_score, 10) || 5;
    const isInternetFacing = d.is_internet_facing === 'true';
    
    const osInfo = {
      name: d.os_name || '',
      version: d.os_version || '',
      vendor: d.hardware_vendor || '',
      ports: (d.open_ports || '').split(' ').filter(p => p.trim())
    };
    
    await pool.query(
      `INSERT INTO assets (
        tenant_id, ip_address, hostname, mac_address, owner,
        device_type, criticality_score, is_internet_facing, os_info,
        source, last_scanned, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW());`,
      [tenantId, ipAddress, hostname, macAddress, owner, deviceType, criticalityScore, isInternetFacing, osInfo, 'manual']
    );
  }
  console.log(`Imported ${lines.length - 1} rows from ${filePath}`);
}

async function run() {
  try {
    const vanillaId = 'd2d3519c-4b18-4c12-812e-2ac1ba605552';
    const cyberforceId = '6942d0b8-47c3-4137-aa6a-e6f1d99e7552';
    
    await importCsv(vanillaId, '../vanilla_corporation_assets.csv');
    await importCsv(cyberforceId, '../cyberforce_corporation_assets.csv');
    
  } catch (err) {
    console.error('Error:', err);
  } finally {
    pool.end();
  }
}

run();

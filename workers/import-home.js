const fs = require('fs');
const { Pool } = require('pg');
const pool = new Pool({
  connectionString: 'postgresql://REDACTED:REDACTED@REDACTED/neondb?sslmode=require'
});

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
  
  let count = 0;
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
    count++;
  }
  console.log(`Imported ${count} rows from ${filePath}`);
}

async function run() {
  try {
    // Clear all existing assets
    const delRes = await pool.query('DELETE FROM assets;');
    console.log(`Wiped ${delRes.rowCount} assets.`);
    await pool.query('DELETE FROM topology_nodes;');
    
    const homeId = '72bf382c-cf44-47fc-b600-322ccbd9a7ff';
    
    await importCsv(homeId, '../vanilla_corporation_assets.csv');
    await importCsv(homeId, '../cyberforce_corporation_assets.csv');
    
  } catch (err) {
    console.error('Error:', err);
  } finally {
    pool.end();
  }
}

run();

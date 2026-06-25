import { Client } from "pg";
import { runSchema, copyTable, verifyAll, discoverTables, getDestTableDetails, TABLE_ORDER } from "./migrate";

export interface Env {
  HYPERDRIVE: Hyperdrive;
  NEON_HYPERDRIVE: Hyperdrive;
}

// pg's Client emits 'error' on the underlying socket asynchronously; with no
// listener, Node's EventEmitter throws and crashes the whole Worker invocation
// instead of rejecting the connect()/query() promise we're awaiting.
let lastSocketError: string | null = null;
function newClient(connectionString: string) {
  const client = new Client({ connectionString });
  client.on("error", (err) => {
    lastSocketError = err instanceof Error ? err.message : String(err);
  });
  return client;
}

function errorResponse(e: unknown): Response {
  const message = e instanceof Error ? e.message : String(e);
  const body: Record<string, unknown> = { error: message };
  if (lastSocketError) {
    body.socketError = lastSocketError;
    lastSocketError = null;
  }
  return Response.json(body, { status: 500 });
}

async function handleMigrate(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;

  if (path === "/migrate/debug-neon" && request.method === "GET") {
    const neon = newClient(env.NEON_HYPERDRIVE.connectionString);
    try {
      await neon.connect();
      const result = await neon.query("SELECT current_database() AS db, count(*)::int AS tenant_count FROM tenants");
      return Response.json(result.rows[0]);
    } catch (e) {
      return errorResponse(e);
    } finally {
      await neon.end().catch(() => {});
    }
  }

  if (path === "/migrate/tables" && request.method === "GET") {
    const neon = newClient(env.NEON_HYPERDRIVE.connectionString);
    try {
      await neon.connect();
      const tables = await discoverTables(neon);
      return Response.json({ tables });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await neon.end().catch(() => {});
    }
  }

  if (path === "/migrate/rows" && request.method === "GET") {
    const table = url.searchParams.get("table");
    if (!table || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      return Response.json({ error: "Invalid table name" }, { status: 400 });
    }
    const limit = Math.min(Number(url.searchParams.get("limit") ?? "25"), 200);
    const offset = Number(url.searchParams.get("offset") ?? "0");
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      const result = await dest.query(
        `SELECT * FROM "${table}" LIMIT $1 OFFSET $2 -- ${Date.now()}`,
        [limit, offset]
      );
      return Response.json({ table, limit, offset, rows: result.rows });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/dest-tables" && request.method === "GET") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      // Unique comment per request defeats Hyperdrive's exact-query-text cache.
      const result = await dest.query(
        `SELECT table_name FROM information_schema.tables WHERE table_schema = 'eagleeye' AND table_type = 'BASE TABLE' ORDER BY table_name -- ${Date.now()}`
      );
      return Response.json({ tables: result.rows.map((r) => r.table_name) });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/tables-detail" && request.method === "GET") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      const tables = await getDestTableDetails(dest);
      return Response.json({ tables });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/inspect" && request.method === "GET") {
    const table = url.searchParams.get("table");
    if (!table) {
      return Response.json({ error: "table param required" }, { status: 400 });
    }
    const neon = newClient(env.NEON_HYPERDRIVE.connectionString);
    try {
      await neon.connect();
      const columns = await neon.query(
        `SELECT column_name, data_type, udt_name, is_nullable, column_default, character_maximum_length, numeric_precision, numeric_scale
         FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position`,
        [table]
      );
      const constraints = await neon.query(
        `SELECT tc.constraint_type, kcu.column_name, ccu.table_name AS foreign_table, ccu.column_name AS foreign_column
         FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
         LEFT JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name = ccu.constraint_name AND tc.constraint_type = 'FOREIGN KEY'
         WHERE tc.table_schema = 'public' AND tc.table_name = $1`,
        [table]
      );
      return Response.json({ table, columns: columns.rows, constraints: constraints.rows });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await neon.end().catch(() => {});
    }
  }

  if (path === "/migrate/schema-chat-sessions" && request.method === "POST") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      await dest.query(`
        CREATE TABLE IF NOT EXISTS chat_sessions (
          session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id uuid NOT NULL,
          tenant_id uuid,
          advisory_id uuid,
          name varchar(200) NOT NULL DEFAULT 'Advisory Session',
          emoji varchar(10) NOT NULL DEFAULT '🔴',
          category varchar(100),
          messages jsonb NOT NULL DEFAULT '[]'::jsonb,
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          CONSTRAINT chat_sessions_tenant_id_tenants_tenant_id_fk FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
        )
      `);
      return Response.json({ ok: true });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/debug" && request.method === "GET") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      const searchPath = await dest.query("SHOW search_path");
      const schemas = await dest.query(
        "SELECT schema_name, schema_owner FROM information_schema.schemata"
      );
      const grants = await dest.query(
        "SELECT grantee, privilege_type FROM information_schema.role_usage_grants WHERE object_schema = 'public'"
      );
      return Response.json({
        search_path: searchPath.rows[0],
        schemas: schemas.rows,
        public_grants: grants.rows,
      });
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/schema" && request.method === "POST") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    try {
      await dest.connect();
      const offset = Number(url.searchParams.get("offset") ?? "0");
      const limit = Number(url.searchParams.get("limit") ?? "8");
      const result = await runSchema(dest, offset, limit);
      return Response.json(result);
    } catch (e) {
      return errorResponse(e);
    } finally {
      await dest.end().catch(() => {});
    }
  }

  if (path === "/migrate/copy" && request.method === "POST") {
    const table = url.searchParams.get("table");
    if (!table || !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      return Response.json({ error: "Invalid table name" }, { status: 400 });
    }
    const dest = newClient(env.HYPERDRIVE.connectionString);
    const neon = newClient(env.NEON_HYPERDRIVE.connectionString);
    try {
      await Promise.all([dest.connect(), neon.connect()]);
      const result = await copyTable(neon, dest, table);
      return Response.json(result);
    } catch (e) {
      return errorResponse(e);
    } finally {
      await Promise.allSettled([dest.end(), neon.end()]);
    }
  }

  if (path === "/migrate/verify" && request.method === "GET") {
    const dest = newClient(env.HYPERDRIVE.connectionString);
    const neon = newClient(env.NEON_HYPERDRIVE.connectionString);
    try {
      await Promise.all([dest.connect(), neon.connect()]);
      const tablesParam = url.searchParams.get("tables");
      const tables = tablesParam ? tablesParam.split(",") : TABLE_ORDER;
      const result = await verifyAll(neon, dest, tables);
      return Response.json(result);
    } catch (e) {
      return errorResponse(e);
    } finally {
      await Promise.allSettled([dest.end(), neon.end()]);
    }
  }

  return Response.json({ error: "Not found" }, { status: 404 });
}

const UI_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Supabase Tables</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f1117; color: #e5e7eb; margin: 0; padding: 2rem; }
  h1 { font-size: 1.25rem; margin-bottom: 1rem; }
  #status { color: #9ca3af; margin-bottom: 1rem; }
  .table-card { background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .table-header { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; cursor: pointer; }
  .table-header:hover { background: #21242f; }
  .table-name { font-weight: 600; }
  .row-count { color: #9ca3af; font-size: 0.875rem; }
  .columns { display: none; padding: 0 1rem 0.75rem 1rem; }
  .columns.open { display: block; }
  .col { display: flex; justify-content: space-between; padding: 0.25rem 0; font-size: 0.85rem; border-top: 1px solid #2a2d3a; }
  .col-type { color: #9ca3af; }
  .actions { padding: 0 1rem 0.75rem 1rem; display: flex; gap: 0.5rem; align-items: center; }
  button { background: #2563eb; color: white; border: none; border-radius: 6px; padding: 0.5rem 1rem; cursor: pointer; font-size: 0.875rem; }
  button:hover { background: #1d4ed8; }
  button.secondary { background: #374151; }
  button.secondary:hover { background: #4b5563; }
  .data-view { display: none; padding: 0 1rem 1rem 1rem; overflow-x: auto; }
  .data-view.open { display: block; }
  table.data-grid { border-collapse: collapse; width: 100%; font-size: 0.8rem; }
  table.data-grid th, table.data-grid td { border: 1px solid #2a2d3a; padding: 0.4rem 0.6rem; text-align: left; white-space: nowrap; max-width: 300px; overflow: hidden; text-overflow: ellipsis; }
  table.data-grid th { background: #21242f; position: sticky; top: 0; }
  .page-info { color: #9ca3af; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>Supabase Tables (eagleeye schema)</h1>
  <div id="status">Loading...</div>
  <button id="refreshBtn" onclick="syncAndRefresh()">Refresh</button>
  <div id="tables" style="margin-top: 1rem;"></div>
  <script>
    const PAGE_SIZE = 25;
    const pageState = {};

    async function syncAndRefresh() {
      const status = document.getElementById('status');
      const btn = document.getElementById('refreshBtn');
      btn.disabled = true;
      try {
        status.textContent = 'Checking Neon for new data...';
        const tablesRes = await fetch('/migrate/tables');
        const tablesData = await tablesRes.json();
        if (tablesData.error) {
          status.textContent = 'Sync error: ' + tablesData.error;
          btn.disabled = false;
          return;
        }
        const tables = tablesData.tables;
        let totalUpserted = 0;
        let totalDeleted = 0;
        const syncErrors = [];
        for (let i = 0; i < tables.length; i++) {
          const name = tables[i];
          status.textContent = 'Syncing ' + (i + 1) + '/' + tables.length + ': ' + name + '...';
          const copyRes = await fetch('/migrate/copy?table=' + encodeURIComponent(name), { method: 'POST' });
          const copyData = await copyRes.json();
          if (copyData.error) syncErrors.push(name + ': ' + copyData.error);
          else {
            totalUpserted += copyData.upserted || 0;
            totalDeleted += copyData.deleted || 0;
          }
        }
        const summary = 'Synced ' + totalUpserted + ' row(s), removed ' + totalDeleted + ' stale row(s) from Neon' +
          (syncErrors.length ? ' (' + syncErrors.length + ' table(s) failed: ' + syncErrors.join('; ') + ')' : '');
        btn.disabled = false;
        await load(summary);
        return;
      } catch (e) {
        status.textContent = 'Sync error: ' + e.message + ' (showing last known data)';
        btn.disabled = false;
        await load();
        return;
      }
    }

    async function load(prefixMessage) {
      const status = document.getElementById('status');
      const container = document.getElementById('tables');
      status.textContent = (prefixMessage ? prefixMessage + ' — ' : '') + 'loading tables...';
      container.innerHTML = '';
      try {
        const res = await fetch('/migrate/tables-detail');
        const data = await res.json();
        if (data.error) {
          status.textContent = 'Error: ' + data.error;
          return;
        }
        status.textContent = (prefixMessage ? prefixMessage + ' — ' : '') + data.tables.length + ' tables';
        data.tables.forEach((t, i) => {
          pageState[t.name] = 0;
          const card = document.createElement('div');
          card.className = 'table-card';

          const header = document.createElement('div');
          header.className = 'table-header';
          header.innerHTML = '<span class="table-name">' + t.name + '</span><span class="row-count">' + t.rowCount + ' rows</span>';
          const cols = document.createElement('div');
          cols.className = 'columns';
          cols.id = 'cols-' + i;
          cols.innerHTML = t.columns.map(c => '<div class="col"><span>' + c.name + '</span><span class="col-type">' + c.type + '</span></div>').join('');
          header.onclick = () => cols.classList.toggle('open');

          const actions = document.createElement('div');
          actions.className = 'actions';
          const viewBtn = document.createElement('button');
          viewBtn.className = 'secondary';
          viewBtn.textContent = 'View Data';
          const dataView = document.createElement('div');
          dataView.className = 'data-view';
          dataView.id = 'data-' + t.name;
          viewBtn.onclick = () => {
            const isOpen = dataView.classList.toggle('open');
            if (isOpen) loadRows(t.name, dataView);
          };
          actions.appendChild(viewBtn);

          card.appendChild(header);
          card.appendChild(cols);
          card.appendChild(actions);
          card.appendChild(dataView);
          container.appendChild(card);
        });
      } catch (e) {
        status.textContent = 'Error: ' + e.message;
      }
    }

    async function loadRows(tableName, container) {
      container.innerHTML = '<div class="page-info">Loading rows...</div>';
      const offset = pageState[tableName];
      try {
        const res = await fetch('/migrate/rows?table=' + encodeURIComponent(tableName) + '&limit=' + PAGE_SIZE + '&offset=' + offset);
        const data = await res.json();
        if (data.error) {
          container.innerHTML = '<div class="page-info">Error: ' + data.error + '</div>';
          return;
        }
        if (data.rows.length === 0) {
          container.innerHTML = '<div class="page-info">No rows' + (offset > 0 ? ' on this page' : '') + '.</div>';
          return;
        }
        const cols = Object.keys(data.rows[0]);
        let html = '<table class="data-grid"><thead><tr>' + cols.map(c => '<th>' + c + '</th>').join('') + '</tr></thead><tbody>';
        for (const row of data.rows) {
          html += '<tr>' + cols.map(c => {
            let v = row[c];
            if (v === null || v === undefined) v = '';
            else if (typeof v === 'object') v = JSON.stringify(v);
            else v = String(v);
            if (v.length > 80) v = v.slice(0, 80) + '...';
            return '<td title="' + v.replace(/"/g, '&quot;') + '">' + v + '</td>';
          }).join('') + '</tr>';
        }
        html += '</tbody></table>';
        html += '<div class="actions" style="padding: 0.5rem 0;">' +
          '<button class="secondary" onclick="changePage(\\'' + tableName + '\\', ' + (offset - PAGE_SIZE) + ', \\'' + 'data-' + tableName + '\\')" ' + (offset === 0 ? 'disabled' : '') + '>Prev</button>' +
          '<span class="page-info">rows ' + (offset + 1) + '-' + (offset + data.rows.length) + '</span>' +
          '<button class="secondary" onclick="changePage(\\'' + tableName + '\\', ' + (offset + PAGE_SIZE) + ', \\'' + 'data-' + tableName + '\\')" ' + (data.rows.length < PAGE_SIZE ? 'disabled' : '') + '>Next</button>' +
          '</div>';
        container.innerHTML = html;
      } catch (e) {
        container.innerHTML = '<div class="page-info">Error: ' + e.message + '</div>';
      }
    }

    function changePage(tableName, newOffset, containerId) {
      pageState[tableName] = Math.max(0, newOffset);
      loadRows(tableName, document.getElementById(containerId));
    }

    load();
  </script>
</body>
</html>`;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    if (url.pathname === "/ui") {
      return new Response(UI_HTML, { headers: { "Content-Type": "text/html" } });
    }

    if (url.pathname.startsWith("/migrate/")) {
      return handleMigrate(request, env, url);
    }

    const table = url.searchParams.get("table") ?? "hyperdrive_test";
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      return Response.json({ error: "Invalid table name" }, { status: 400 });
    }

    const client = newClient(env.HYPERDRIVE.connectionString);
    await client.connect();

    try {
      // Safety check: confirm which database we're actually talking to
      // before doing anything else (must NOT be your Neon "neondb").
      const dbCheck = await client.query(
        "SELECT current_database() AS database, current_user AS user"
      );

      if (request.method === "DELETE") {
        await client.query(`DROP TABLE IF EXISTS ${table}`);
      }

      if (request.method === "POST") {
        await client.query(`
          CREATE TABLE IF NOT EXISTS ${table} (
            id SERIAL PRIMARY KEY,
            note TEXT,
            created_at TIMESTAMP DEFAULT now()
          )
        `);
        await client.query(`INSERT INTO ${table} (note) VALUES ($1)`, [
          "hello from hyperdrive demo",
        ]);
      }

      let rows = null;
      try {
        const result = await client.query(`SELECT * FROM ${table} ORDER BY id`);
        rows = result.rows;
      } catch {
        // table doesn't exist yet
      }

      const tableExists = await client.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1) AS table_exists",
        [table]
      );

      return Response.json({
        table,
        connectedTo: dbCheck.rows[0],
        rows,
        table_exists: tableExists.rows[0].table_exists,
      });
    } catch (e) {
      return Response.json({ error: e instanceof Error ? e.message : e }, { status: 500 });
    } finally {
      ctx.waitUntil(client.end());
    }
  },
};

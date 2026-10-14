def render_dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>latch-proxy // console</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #0c0c0e;
            color: #d4d4d8;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        /* Top System Bar */
        .topbar {
            height: 36px;
            background: #141417;
            border-bottom: 1px solid #27272a;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 14px;
            user-select: none;
        }
        .brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            color: #f4f4f5;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            background: #22c55e;
            display: inline-block;
        }
        .meta-tag {
            color: #71717a;
            font-weight: 400;
            font-size: 11px;
        }
        .stats-strip {
            display: flex;
            gap: 18px;
            font-size: 11px;
        }
        .stat-item span { color: #71717a; margin-right: 4px; }
        .stat-item strong { color: #e4e4e7; }
        .stat-item.err strong { color: #ef4444; }
        .stat-item.warn strong { color: #eab308; }

        /* Filter Toolbar */
        .toolbar {
            height: 34px;
            background: #101013;
            border-bottom: 1px solid #27272a;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 14px;
            gap: 12px;
        }
        .filter-group {
            display: flex;
            gap: 4px;
        }
        .btn {
            background: #18181b;
            color: #a1a1aa;
            border: 1px solid #27272a;
            padding: 3px 10px;
            font-family: inherit;
            font-size: 11px;
            cursor: pointer;
        }
        .btn:hover { background: #27272a; color: #f4f4f5; }
        .btn.active {
            background: #27272a;
            color: #f4f4f5;
            border-color: #52525b;
        }
        .search-input {
            background: #09090b;
            border: 1px solid #27272a;
            color: #e4e4e7;
            padding: 3px 8px;
            font-family: inherit;
            font-size: 11px;
            width: 260px;
            outline: none;
        }
        .search-input:focus { border-color: #52525b; }

        /* Main Log Table Area */
        .table-container {
            flex: 1;
            overflow-y: auto;
            background: #0c0c0e;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
        }
        thead {
            position: sticky;
            top: 0;
            background: #141417;
            z-index: 1;
        }
        th {
            text-align: left;
            padding: 6px 10px;
            color: #71717a;
            font-weight: 600;
            font-size: 11px;
            border-bottom: 1px solid #27272a;
            border-right: 1px solid #1f1f23;
            white-space: nowrap;
        }
        td {
            padding: 5px 10px;
            border-bottom: 1px solid #18181b;
            border-right: 1px solid #141417;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            color: #d4d4d8;
        }
        tbody tr { cursor: pointer; }
        tbody tr:hover { background: #141418; }
        tbody tr.selected { background: #1e1e24; }
        tbody tr.row-blocked td { color: #fca5a5; }

        .tag {
            display: inline-block;
            padding: 1px 5px;
            font-size: 10px;
            font-weight: 700;
            border: 1px solid transparent;
        }
        .tag-allow { color: #4ade80; border-color: #14532d; background: #052e16; }
        .tag-block { color: #f87171; border-color: #7f1d1d; background: #450a0a; }
        .tag-taint { color: #facc15; border-color: #713f12; background: #422006; }
        .tag-clean { color: #71717a; }

        /* Bottom Split-Pane Packet Inspector */
        .inspector {
            height: 230px;
            background: #101013;
            border-top: 1px solid #27272a;
            display: grid;
            grid-template-columns: 1fr 1fr;
            overflow: hidden;
        }
        .pane {
            display: flex;
            flex-direction: column;
            border-right: 1px solid #27272a;
            overflow: hidden;
        }
        .pane-header {
            background: #141417;
            padding: 5px 12px;
            font-size: 11px;
            font-weight: 600;
            color: #a1a1aa;
            border-bottom: 1px solid #27272a;
            display: flex;
            justify-content: space-between;
        }
        .pane-body {
            padding: 10px 12px;
            overflow-y: auto;
            flex: 1;
        }
        .kv-row {
            display: grid;
            grid-template-columns: 130px 1fr;
            padding: 3px 0;
            border-bottom: 1px solid #18181b;
        }
        .kv-key { color: #71717a; }
        .kv-val { color: #e4e4e7; word-break: break-all; }
        pre {
            color: #a1a1aa;
            font-size: 11px;
            line-height: 1.4;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div class="brand">
            <span class="status-dot" id="poll-dot"></span>
            <span>LATCH-PROXY</span>
            <span class="meta-tag">v1.2.0 // 127.0.0.1:8000 // SIEM STREAM</span>
        </div>
        <div class="stats-strip">
            <div class="stat-item"><span>EVENTS:</span><strong id="m-total">0</strong></div>
            <div class="stat-item err"><span>DENY(403):</span><strong id="m-blocked">0</strong></div>
            <div class="stat-item warn"><span>TAINTED:</span><strong id="m-tainted">0</strong></div>
            <div class="stat-item"><span>DLP_SCRUB:</span><strong id="m-redacted">0</strong></div>
            <div class="stat-item"><span style="color:#71717a;">LEDGER:</span><strong id="m-chain" style="color:#4ade80;">SHA256_OK</strong></div>
        </div>
    </div>

    <div class="toolbar">
        <div class="filter-group">
            <button class="btn active" onclick="setFilter('ALL', this)">ALL</button>
            <button class="btn" onclick="setFilter('BLOCKED', this)">403 BLOCKED</button>
            <button class="btn" onclick="setFilter('TAINTED', this)">TAINTED</button>
            <button class="btn" onclick="setFilter('DLP', this)">DLP REDACTED</button>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
            <input type="text" id="search" class="search-input" placeholder="grep user, tool, rule, event_id..." oninput="renderTable()">
            <button class="btn" onclick="loadTelemetry()">POLL NOW</button>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th style="width: 85px;">ID</th>
                    <th style="width: 155px;">TIMESTAMP</th>
                    <th style="width: 85px;">VERDICT</th>
                    <th style="width: 110px;">PRINCIPAL</th>
                    <th style="width: 75px;">ROLE</th>
                    <th style="width: 85px;">CONTEXT</th>
                    <th style="width: 175px;">TARGET TOOL</th>
                    <th style="width: 230px;">RULE TRIGGERED</th>
                    <th>OWASP CLASSIFICATION</th>
                </tr>
            </thead>
            <tbody id="events-body"></tbody>
        </table>
    </div>

    <div class="inspector">
        <div class="pane">
            <div class="pane-header">
                <span>PACKET / ENFORCEMENT INSPECTOR</span>
                <span id="insp-id" style="color:#71717a;">NO EVENT SELECTED</span>
            </div>
            <div class="pane-body" id="inspector-kv">
                <div style="color:#52525b; padding-top:8px;">Select a row in the event stream above to inspect enforcement details.</div>
            </div>
        </div>
        <div class="pane" style="border-right:none;">
            <div class="pane-header">
                <span>RAW SIEM RECORD (security_audit.jsonl)</span>
            </div>
            <div class="pane-body">
                <pre id="inspector-json">// Click an event row to view raw JSON</pre>
            </div>
        </div>
    </div>

    <script>
        let allEvents = [];
        let activeFilter = 'ALL';
        let selectedEventId = null;

        function setFilter(filter, btnEl) {
            activeFilter = filter;
            document.querySelectorAll('.filter-group .btn').forEach(b => b.classList.remove('active'));
            btnEl.classList.add('active');
            renderTable();
        }

        function selectEvent(eventId) {
            selectedEventId = eventId;
            renderTable();
            const ev = allEvents.find(e => e.event_id === eventId);
            if (!ev) return;

            document.getElementById('insp-id').innerText = `EVENT_ID: ${ev.event_id}`;
            document.getElementById('inspector-kv').innerHTML = `
                <div class="kv-row"><div class="kv-key">timestamp</div><div class="kv-val">${ev.timestamp}</div></div>
                <div class="kv-row"><div class="kv-key">principal</div><div class="kv-val">${ev.user_id} (role=${ev.role})</div></div>
                <div class="kv-row"><div class="kv-key">verdict</div><div class="kv-val">${ev.verdict}</div></div>
                <div class="kv-row"><div class="kv-key">taint_state</div><div class="kv-val">${ev.is_tainted ? 'TAINTED (Untrusted External Input)' : 'CLEAN (Trusted Internal)'}</div></div>
                <div class="kv-row"><div class="kv-key">target_tool</div><div class="kv-val">${ev.tool_name}</div></div>
                <div class="kv-row"><div class="kv-key">rule_triggered</div><div class="kv-val">${ev.rule_triggered}</div></div>
                <div class="kv-row"><div class="kv-key">owasp_mapping</div><div class="kv-val">${ev.owasp_category}</div></div>
                <div class="kv-row"><div class="kv-key">dlp_redactions</div><div class="kv-val">${ev.secrets_redacted}</div></div>
                <div class="kv-row"><div class="kv-key">reason_trace</div><div class="kv-val">${ev.reason}</div></div>
            `;
            document.getElementById('inspector-json').innerText = JSON.stringify(ev, null, 2);
        }

        function renderTable() {
            const query = document.getElementById('search').value.toLowerCase();
            const tbody = document.getElementById('events-body');

            const filtered = allEvents.filter(e => {
                if (activeFilter === 'BLOCKED' && e.verdict !== 'BLOCKED') return false;
                if (activeFilter === 'TAINTED' && !e.is_tainted) return false;
                if (activeFilter === 'DLP' && e.secrets_redacted === 0) return false;
                if (query) {
                    const hay = `${e.event_id} ${e.user_id} ${e.role} ${e.tool_name} ${e.rule_triggered} ${e.owasp_category}`.toLowerCase();
                    if (!hay.includes(query)) return false;
                }
                return true;
            });

            tbody.innerHTML = filtered.map(e => {
                const isSelected = e.event_id === selectedEventId ? 'selected' : '';
                const isBlocked = e.verdict === 'BLOCKED' ? 'row-blocked' : '';
                return `
                    <tr class="${isSelected} ${isBlocked}" onclick="selectEvent('${e.event_id}')">
                        <td style="color:#71717a;">${e.event_id}</td>
                        <td style="color:#a1a1aa;">${e.timestamp}</td>
                        <td><span class="tag ${e.verdict === 'ALLOWED' ? 'tag-allow' : 'tag-block'}">${e.verdict === 'ALLOWED' ? '200 OK' : '403 DENY'}</span></td>
                        <td>${e.user_id}</td>
                        <td style="color:#a1a1aa;">${e.role}</td>
                        <td>${e.is_tainted ? '<span class="tag tag-taint">TAINTED</span>' : '<span class="tag-clean">CLEAN</span>'}</td>
                        <td>${e.tool_name}</td>
                        <td>${e.rule_triggered}</td>
                        <td style="color:#a1a1aa;">${e.owasp_category}</td>
                    </tr>
                `;
            }).join('');

            if (!selectedEventId && filtered.length > 0) {
                selectEvent(filtered[0].event_id);
            }
        }

        async function loadTelemetry() {
            const res = await fetch('/v1/audit');
            const data = await res.json();
            allEvents = data.events;

            document.getElementById('m-total').innerText = data.metrics.total_requests;
            document.getElementById('m-blocked').innerText = data.metrics.blocked_attacks;
            document.getElementById('m-tainted').innerText = data.metrics.tainted_contexts;
            document.getElementById('m-redacted').innerText = data.metrics.secrets_redacted;

            const chainEl = document.getElementById('m-chain');
            if (data.chain_integrity && data.chain_integrity.chain_valid) {
                chainEl.innerText = 'SHA256_OK';
                chainEl.style.color = '#4ade80';
            } else {
                chainEl.innerText = 'TAMPERED';
                chainEl.style.color = '#ef4444';
            }

            renderTable();
        }

        loadTelemetry();
        setInterval(loadTelemetry, 3000);
    </script>
</body>
</html>"""
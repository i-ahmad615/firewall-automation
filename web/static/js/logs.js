const state = { search: '', severity: '', module: '', date_from: '', date_to: '', sort_dir: 'desc', page: 1, page_size: 50 };
let debounceTimer;
let modulesPopulated = false;

function rowHtml(r) {
  return `
    <tr>
      <td class="cell-mono">${fmtTime(r.timestamp)}</td>
      <td>${severityBadge(r.severity)}</td>
      <td class="cell-muted">${escapeHtml(r.module)}</td>
      <td>${escapeHtml(r.action || '—')}</td>
      <td class="cell-wrap">${escapeHtml(r.message)}</td>
    </tr>`;
}

async function load() {
  const data = await fetchJson(`/api/logs?${qs(state)}`);
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="5"><div class="empty-state">No log entries match the current filters.</div></td></tr>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} · ${data.total} total`;
  document.getElementById('prev-page').disabled = data.page <= 1;
  document.getElementById('next-page').disabled = data.page >= totalPages;

  if (!modulesPopulated && data.modules && data.modules.length) {
    const sel = document.getElementById('f-module');
    data.modules.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m; opt.textContent = m;
      sel.appendChild(opt);
    });
    modulesPopulated = true;
  }
}

document.getElementById('f-search').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { state.search = e.target.value; state.page = 1; load(); }, 300);
});
document.getElementById('f-severity').addEventListener('change', (e) => { state.severity = e.target.value; state.page = 1; load(); });
document.getElementById('f-module').addEventListener('change', (e) => { state.module = e.target.value; state.page = 1; load(); });
document.getElementById('f-from').addEventListener('change', (e) => { state.date_from = e.target.value; state.page = 1; load(); });
document.getElementById('f-to').addEventListener('change', (e) => { state.date_to = e.target.value; state.page = 1; load(); });
document.getElementById('prev-page').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); load(); });
document.getElementById('next-page').addEventListener('click', () => { state.page += 1; load(); });

document.getElementById('clear-all').addEventListener('click', async () => {
  const confirmed = await confirmDialog({
    title: 'Clear Logs',
    message: 'Do you want to clear all the logs? This permanently deletes every log entry from the database.',
  });
  if (!confirmed) return;
  await fetchJson('/api/logs', { method: 'DELETE' });
  state.page = 1;
  load();
});

load();
setInterval(() => { if (document.getElementById('f-auto').checked) load(); }, 10000);

const state = { search: '', result: '', status: '', sort_by: 'occurred_at', sort_dir: 'desc', page: 1, page_size: 25 };
let debounceTimer;

function boolBadge(v) {
  return v ? '<span class="badge success">Yes</span>' : '<span class="badge neutral">No</span>';
}

function rowHtml(r) {
  return `
    <tr>
      <td class="cell-mono">${fmtDate(r.occurred_at)}<br><span class="cell-muted">${fmtClock(r.occurred_at)}</span></td>
      <td class="cell-mono">${escapeHtml(r.ip)}</td>
      <td>${escapeHtml(r.rule_name)}</td>
      <td>${badgeHtml(r.result)}</td>
      <td>${boolBadge(r.duplicate)}</td>
      <td>${boolBadge(r.allowed_list)}</td>
      <td>${boolBadge(r.notification_sent)}</td>
      <td>${badgeHtml(r.status)}</td>
    </tr>`;
}

async function load() {
  const data = await fetchJson(`/api/firewall-actions?${qs(state)}`);
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="8"><div class="empty-state">No firewall actions match the current filters.</div></td></tr>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} · ${data.total} total`;
  document.getElementById('prev-page').disabled = data.page <= 1;
  document.getElementById('next-page').disabled = data.page >= totalPages;

  document.querySelectorAll('#table thead th[data-key]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.key === state.sort_by);
    th.classList.toggle('asc', th.dataset.key === state.sort_by && state.sort_dir === 'asc');
  });
}

document.getElementById('f-search').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { state.search = e.target.value; state.page = 1; load(); }, 300);
});
document.getElementById('f-result').addEventListener('change', (e) => { state.result = e.target.value; state.page = 1; load(); });
document.getElementById('f-status').addEventListener('change', (e) => { state.status = e.target.value; state.page = 1; load(); });
document.getElementById('prev-page').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); load(); });
document.getElementById('next-page').addEventListener('click', () => { state.page += 1; load(); });
document.querySelectorAll('#table thead th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.key;
    if (state.sort_by === key) { state.sort_dir = state.sort_dir === 'asc' ? 'desc' : 'asc'; }
    else { state.sort_by = key; state.sort_dir = 'desc'; }
    load();
  });
});

document.getElementById('clear-all').addEventListener('click', async () => {
  const confirmed = await confirmDialog({
    title: 'Clear Firewall Actions',
    message: 'Do you want to clear all the firewall actions? This permanently deletes every firewall action record from the database.',
  });
  if (!confirmed) return;
  await fetchJson('/api/firewall-actions', { method: 'DELETE' });
  state.page = 1;
  load();
});

load();
setInterval(load, 20000);

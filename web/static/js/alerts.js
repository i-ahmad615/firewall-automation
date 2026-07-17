const state = {
  search: '', status: '', action_taken: '', classification: '', notification_sent: '',
  sort_by: 'received_at', sort_dir: 'desc', page: 1, page_size: 25,
};
let debounceTimer;

function applyStateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  ['search', 'status', 'action_taken', 'classification', 'notification_sent'].forEach(key => {
    if (params.has(key)) state[key] = params.get(key);
  });
  document.getElementById('f-search').value = state.search;
  document.getElementById('f-status').value = state.status;
  document.getElementById('f-action').value = state.action_taken;
}

function renderActiveFilterBanner() {
  const banner = document.getElementById('active-filter-banner');
  const active = [];
  if (state.status) active.push(['Status', state.status]);
  if (state.action_taken) active.push(['Action', state.action_taken]);
  if (state.classification) active.push(['Classification', state.classification]);
  if (state.notification_sent !== '') active.push(['Notified', state.notification_sent === '1' ? 'Yes' : 'No']);

  if (!active.length) { banner.innerHTML = ''; banner.style.display = 'none'; return; }

  banner.style.display = 'flex';
  banner.innerHTML = `
    <span class="text-sm text-muted">Filtered by:</span>
    ${active.map(([label, value]) => `<span class="badge info">${escapeHtml(label)}: ${escapeHtml(value)}</span>`).join('')}
    <button class="btn" id="clear-filters" type="button">Clear filters</button>
  `;
  document.getElementById('clear-filters').addEventListener('click', () => {
    state.status = ''; state.action_taken = ''; state.classification = ''; state.notification_sent = '';
    document.getElementById('f-status').value = '';
    document.getElementById('f-action').value = '';
    state.page = 1;
    history.replaceState(null, '', '/alerts');
    load();
  });
}

function rowHtml(r) {
  return `
    <tr>
      <td class="cell-mono">${fmtDate(r.received_at)}<br><span class="cell-muted">${fmtClock(r.received_at)}</span></td>
      <td class="cell-wrap">${escapeHtml(r.subject)}</td>
      <td>${escapeHtml(r.sender)}</td>
      <td class="cell-mono">${escapeHtml(r.origin_ip || '—')}</td>
      <td>${escapeHtml(r.classification || '—')}</td>
      <td>${badgeHtml(r.status)}</td>
      <td>${badgeHtml(r.action_taken)}</td>
      <td class="cell-wrap cell-muted">${escapeHtml(r.reason || '')}</td>
    </tr>`;
}

async function load() {
  renderActiveFilterBanner();
  const data = await fetchJson(`/api/alerts?${qs(state)}`);
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="8"><div class="empty-state">No alerts match the current filters.</div></td></tr>`;

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
document.getElementById('f-status').addEventListener('change', (e) => { state.status = e.target.value; state.page = 1; load(); });
document.getElementById('f-action').addEventListener('change', (e) => { state.action_taken = e.target.value; state.page = 1; load(); });
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
    title: 'Clear Alerts',
    message: 'Do you want to clear all the alerts? This permanently deletes every alert record from the database.',
  });
  if (!confirmed) return;
  await fetchJson('/api/alerts', { method: 'DELETE' });
  state.page = 1;
  load();
});

applyStateFromUrl();
load();
setInterval(load, 20000);

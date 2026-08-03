const state = {
  search: '', status: '', action_taken: '', decision_status: '', classification: '', notification_sent: '',
  sort_by: 'received_at', sort_dir: 'desc', page: 1, page_size: 25,
};
let debounceTimer;
const selectedIds = new Set();
let visibleIds = [];

function showBulkActionMessage(message, isError = false) {
  const banner = document.getElementById('bulk-action-message');
  banner.style.display = message ? 'flex' : 'none';
  banner.className = `alert-banner ${isError ? 'error' : 'success'}`;
  banner.textContent = message;
}

function applyStateFromUrl() {
  const params = new URLSearchParams(window.location.search);
  ['search', 'status', 'action_taken', 'decision_status', 'classification', 'notification_sent'].forEach(key => {
    if (params.has(key)) state[key] = params.get(key);
  });
  ['page', 'page_size'].forEach(key => {
    if (params.has(key) && Number.isFinite(Number(params.get(key)))) state[key] = Math.max(1, Number(params.get(key)));
  });
  ['sort_by', 'sort_dir'].forEach(key => { if (params.has(key)) state[key] = params.get(key); });
  document.getElementById('f-search').value = state.search;
  document.getElementById('f-status').value = state.status;
  document.getElementById('f-action').value = state.action_taken;
}

function renderActiveFilterBanner() {
  const banner = document.getElementById('active-filter-banner');
  const active = [];
  if (state.status) active.push(['Status', state.status]);
  if (state.action_taken) active.push(['Action', state.action_taken]);
  if (state.decision_status) {
    const decisionLabels = {
      both_trusted: 'Protected endpoints ignored',
      both_untrusted: 'Neither endpoint trusted',
    };
    active.push(['Decision', decisionLabels[state.decision_status] || state.decision_status]);
  }
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
    state.status = ''; state.action_taken = ''; state.decision_status = ''; state.classification = ''; state.notification_sent = '';
    document.getElementById('f-status').value = '';
    document.getElementById('f-action').value = '';
    state.page = 1;
    history.replaceState(null, '', '/alerts');
    load();
  });
}

function rowHtml(r) {
  return `
    <tr class="clickable-row" data-alert-id="${escapeHtml(r.id)}" tabindex="0" aria-label="Open alert ${escapeHtml(r.id)} details">
      <td class="selection-cell"><input class="row-select" type="checkbox" data-select-id="${escapeHtml(r.id)}" aria-label="Select alert ${escapeHtml(r.id)}" ${selectedIds.has(Number(r.id)) ? 'checked' : ''}></td>
      <td class="cell-mono" data-label="Date / Time">${fmtDate(r.received_at)}<br><span class="cell-muted">${fmtClock(r.received_at)}</span></td>
      <td class="cell-wrap" data-label="Subject">${escapeHtml(r.subject)}</td>
      <td class="cell-wrap" data-label="Sender">${escapeHtml(r.sender)}</td>
      <td class="cell-mono" data-label="Blocked IP">${escapeHtml(r.blocked_ip || '-')}</td>
      <td class="cell-wrap" data-label="Classification">${escapeHtml(r.classification || '—')}</td>
      <td data-label="Status">${badgeHtml(r.status)}</td>
      <td data-label="Action Taken">${badgeHtml(r.action_taken)}</td>
      <td class="cell-wrap cell-muted" data-label="Reason">${escapeHtml(r.reason || '')}</td>
    </tr>`;
}

async function load() {
  const query = qs(state);
  history.replaceState(null, '', query ? `/alerts?${query}` : '/alerts');
  renderActiveFilterBanner();
  const data = await fetchJson(`/api/alerts?${qs(state)}`);
  visibleIds = data.rows.map(row => Number(row.id));
  const visibleSet = new Set(visibleIds);
  [...selectedIds].forEach(id => { if (!visibleSet.has(id)) selectedIds.delete(id); });
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="9"><div class="empty-state">No alerts match the current filters.</div></td></tr>`;
  updateSelectionUi();

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} · ${data.total} total`;
  document.getElementById('prev-page').disabled = data.page <= 1;
  document.getElementById('next-page').disabled = data.page >= totalPages;

  document.querySelectorAll('#table thead th[data-key]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.key === state.sort_by);
    th.classList.toggle('asc', th.dataset.key === state.sort_by && state.sort_dir === 'asc');
  });
}

function updateSelectionUi() {
  const button = document.getElementById('delete-selected');
  button.disabled = selectedIds.size === 0;
  button.textContent = `Delete Selected (${selectedIds.size})`;
  const selectPage = document.getElementById('select-page');
  const selectedVisible = visibleIds.filter(id => selectedIds.has(id)).length;
  selectPage.checked = visibleIds.length > 0 && selectedVisible === visibleIds.length;
  selectPage.indeterminate = selectedVisible > 0 && selectedVisible < visibleIds.length;
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
  selectedIds.clear();
  state.page = 1;
  load();
});

document.getElementById('delete-selected').addEventListener('click', async () => {
  if (!selectedIds.size) return;
  const count = selectedIds.size;
  const confirmed = await confirmDialog({
    title: 'Delete Selected Alerts',
    message: `Permanently delete ${count} selected alert record${count === 1 ? '' : 's'} from the database?`,
    confirmLabel: 'Delete Selected',
  });
  if (!confirmed) return;
  const button = document.getElementById('delete-selected');
  button.disabled = true;
  showBulkActionMessage('');
  try {
    const result = await fetchJson('/api/alerts/delete-selected', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: [...selectedIds] }),
    });
    if (!result.deleted) throw new Error('No selected records were found');
    selectedIds.clear();
    state.page = 1;
    showBulkActionMessage(`${result.deleted} alert record${result.deleted === 1 ? '' : 's'} deleted.`);
    await load();
  } catch (error) {
    showBulkActionMessage(`Unable to delete the selected alerts: ${error.message}.`, true);
    updateSelectionUi();
  }
});

document.getElementById('select-page').addEventListener('change', event => {
  visibleIds.forEach(id => event.target.checked ? selectedIds.add(id) : selectedIds.delete(id));
  document.querySelectorAll('[data-select-id]').forEach(input => { input.checked = event.target.checked; });
  updateSelectionUi();
});

function openAlertRow(row) {
  const returnTo = window.location.pathname + window.location.search;
  window.location.href = `/alerts/${encodeURIComponent(row.dataset.alertId)}?return=${encodeURIComponent(returnTo)}`;
}
document.getElementById('table-body').addEventListener('click', event => {
  if (event.target.closest('[data-select-id]')) return;
  const row = event.target.closest('[data-alert-id]');
  if (row) openAlertRow(row);
});
document.getElementById('table-body').addEventListener('change', event => {
  const input = event.target.closest('[data-select-id]');
  if (!input) return;
  const id = Number(input.dataset.selectId);
  input.checked ? selectedIds.add(id) : selectedIds.delete(id);
  updateSelectionUi();
});
document.getElementById('table-body').addEventListener('keydown', event => {
  if (event.target.closest('[data-select-id]')) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  const row = event.target.closest('[data-alert-id]');
  if (row) { event.preventDefault(); openAlertRow(row); }
});

applyStateFromUrl();
load();
setInterval(load, 20000);

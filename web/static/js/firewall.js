const state = { search: '', result: '', status: '', sort_by: 'occurred_at', sort_dir: 'desc', page: 1, page_size: 25 };
let debounceTimer;
const selectedIds = new Set();
let visibleIds = [];

function showBulkActionMessage(message, isError = false) {
  const banner = document.getElementById('bulk-action-message');
  banner.style.display = message ? 'flex' : 'none';
  banner.className = `alert-banner ${isError ? 'error' : 'success'}`;
  banner.textContent = message;
}

function boolBadge(v) {
  return v ? '<span class="badge success">Yes</span>' : '<span class="badge neutral">No</span>';
}

function rowHtml(r) {
  return `
    <tr>
      <td class="selection-cell"><input class="row-select" type="checkbox" data-select-id="${escapeHtml(r.id)}" aria-label="Select firewall action ${escapeHtml(r.id)}" ${selectedIds.has(Number(r.id)) ? 'checked' : ''}></td>
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
  visibleIds = data.rows.map(row => Number(row.id));
  const visibleSet = new Set(visibleIds);
  [...selectedIds].forEach(id => { if (!visibleSet.has(id)) selectedIds.delete(id); });
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="9"><div class="empty-state">No firewall actions match the current filters.</div></td></tr>`;
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
  selectedIds.clear();
  state.page = 1;
  load();
});

document.getElementById('delete-selected').addEventListener('click', async () => {
  if (!selectedIds.size) return;
  const count = selectedIds.size;
  const confirmed = await confirmDialog({
    title: 'Delete Selected Firewall Actions',
    message: `Permanently delete ${count} selected firewall action record${count === 1 ? '' : 's'} from the database?`,
    confirmLabel: 'Delete Selected',
  });
  if (!confirmed) return;
  const button = document.getElementById('delete-selected');
  button.disabled = true;
  showBulkActionMessage('');
  try {
    const result = await fetchJson('/api/firewall-actions/delete-selected', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: [...selectedIds] }),
    });
    if (!result.deleted) throw new Error('No selected records were found');
    selectedIds.clear();
    state.page = 1;
    showBulkActionMessage(`${result.deleted} firewall action record${result.deleted === 1 ? '' : 's'} deleted.`);
    await load();
  } catch (error) {
    showBulkActionMessage(`Unable to delete the selected firewall actions: ${error.message}.`, true);
    updateSelectionUi();
  }
});

document.getElementById('select-page').addEventListener('change', event => {
  visibleIds.forEach(id => event.target.checked ? selectedIds.add(id) : selectedIds.delete(id));
  document.querySelectorAll('[data-select-id]').forEach(input => { input.checked = event.target.checked; });
  updateSelectionUi();
});

document.getElementById('table-body').addEventListener('change', event => {
  const input = event.target.closest('[data-select-id]');
  if (!input) return;
  const id = Number(input.dataset.selectId);
  input.checked ? selectedIds.add(id) : selectedIds.delete(id);
  updateSelectionUi();
});

load();
setInterval(load, 20000);

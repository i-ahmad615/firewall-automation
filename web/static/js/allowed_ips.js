const TYPE_LABELS = { IP: 'IP Address', CIDR: 'CIDR Range', HOSTNAME: 'Hostname' };
const CATEGORY_LABELS = { CENTURY_OWNED: 'Century-Owned', EXTERNAL_ALLOWLIST: 'External Allowlist' };
let editingId = null;
let endpointRows = [];

function showMessage(message) {
  const el = document.getElementById('form-error');
  el.hidden = !message;
  el.textContent = message || '';
}
function resetForm() {
  editingId = null;
  document.getElementById('endpoint-form').reset();
  document.getElementById('endpoint-active').checked = true;
  document.getElementById('save-endpoint').textContent = 'Add Endpoint';
  document.getElementById('cancel-edit').hidden = true;
}
function rowHtml(item) {
  return `<tr>
    <td class="cell-mono">${escapeHtml(item.value)}</td>
    <td>${escapeHtml(TYPE_LABELS[item.value_type] || item.value_type)}</td>
    <td>${escapeHtml(CATEGORY_LABELS[item.category] || item.category)}</td>
    <td class="cell-muted">${escapeHtml(item.description || '—')}</td>
    <td><label><input type="checkbox" data-active="${item.id}" ${item.is_active ? 'checked' : ''}> ${item.is_active ? 'Active' : 'Inactive'}</label></td>
    <td>${fmtDate(item.created_at)}</td><td>${fmtDate(item.updated_at)}</td>
    <td class="table-actions"><button class="btn" data-edit="${item.id}" type="button">Edit</button>
      <button class="btn btn-danger" data-delete="${item.id}" type="button">Delete</button></td>
  </tr>`;
}
async function load() {
  const params = new URLSearchParams({
    search: document.getElementById('endpoint-search').value.trim(),
    category: document.getElementById('filter-category').value,
    value_type: document.getElementById('filter-type').value,
  });
  try {
    const data = await fetchJson(`/api/allowed-ips?${params}`);
    endpointRows = data.endpoints || [];
    const body = document.getElementById('table-body');
    body.innerHTML = endpointRows.length ? endpointRows.map(rowHtml).join('') :
      '<tr><td colspan="8"><div class="empty-state"><span>No protected endpoints found.</span></div></td></tr>';
    document.getElementById('page-info').textContent = `${endpointRows.length} protected endpoint${endpointRows.length === 1 ? '' : 's'}`;
    bindRows(body);
  } catch (error) { showMessage(error.message || 'Could not load protected endpoints.'); }
}
function bindRows(body) {
  body.querySelectorAll('[data-active]').forEach(input => input.addEventListener('change', async () => {
    try {
      await fetchJson(`/api/allowed-ips/${input.dataset.active}`, { method: 'PATCH', headers: {'Content-Type':'application/json'}, body: JSON.stringify({is_active: input.checked}) });
      load();
    } catch (error) { showMessage(error.message || 'Could not update endpoint.'); load(); }
  }));
  body.querySelectorAll('[data-edit]').forEach(button => button.addEventListener('click', () => {
    const item = endpointRows.find(row => row.id === Number(button.dataset.edit));
    if (!item) return;
    editingId = item.id;
    document.getElementById('endpoint-value').value = item.value;
    document.getElementById('value-type').value = item.value_type;
    document.getElementById('endpoint-category').value = item.category;
    document.getElementById('endpoint-description').value = item.description || '';
    document.getElementById('endpoint-active').checked = Boolean(item.is_active);
    document.getElementById('save-endpoint').textContent = 'Save Changes';
    document.getElementById('cancel-edit').hidden = false;
  }));
  body.querySelectorAll('[data-delete]').forEach(button => button.addEventListener('click', async () => {
    const item = endpointRows.find(row => row.id === Number(button.dataset.delete));
    const confirmed = await confirmDialog({title:'Delete Protected Endpoint', message:`Delete ${item?.value || 'this endpoint'}?`});
    if (!confirmed) return;
    try { await fetchJson(`/api/allowed-ips/${button.dataset.delete}`, {method:'DELETE'}); resetForm(); load(); }
    catch (error) { showMessage(error.message || 'Could not delete endpoint.'); }
  }));
}
document.getElementById('endpoint-form').addEventListener('submit', async event => {
  event.preventDefault(); showMessage('');
  const payload = {value: document.getElementById('endpoint-value').value.trim(),
    value_type: document.getElementById('value-type').value,
    category: document.getElementById('endpoint-category').value,
    description: document.getElementById('endpoint-description').value.trim(),
    is_active: document.getElementById('endpoint-active').checked};
  try {
    await fetchJson(editingId ? `/api/allowed-ips/${editingId}` : '/api/allowed-ips', {
      method: editingId ? 'PUT' : 'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    resetForm(); load();
  } catch (error) { showMessage(error.message || 'Could not save endpoint.'); }
});
document.getElementById('cancel-edit').addEventListener('click', resetForm);
let searchTimer;
document.getElementById('endpoint-search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer=setTimeout(load,250); });
document.getElementById('filter-category').addEventListener('change', load);
document.getElementById('filter-type').addEventListener('change', load);
document.getElementById('import-button').addEventListener('click', () => document.getElementById('import-file').click());
document.getElementById('import-file').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  try {
    const summary = await fetchJson('/api/protected-endpoints/import', {method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({format:file.name.toLowerCase().endsWith('.json')?'json':'csv', content:await file.text()})});
    const failures = summary.errors.map(item => `Row ${item.row}: ${item.value || '(empty)'} — ${item.error}`).join('\n');
    showMessage(`Import complete — Imported: ${summary.imported}, Duplicates: ${summary.duplicates}, Conflicts: ${summary.conflicts}, Invalid: ${summary.invalid}${failures ? `\n${failures}` : ''}`);
    load();
  } catch (error) { showMessage(error.message || 'Could not import endpoints.'); }
  event.target.value='';
});
load();

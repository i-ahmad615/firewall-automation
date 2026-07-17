function rowHtml(ip, i) {
  return `
    <tr>
      <td class="cell-muted">${i + 1}</td>
      <td class="cell-mono">${escapeHtml(ip)}</td>
      <td>
        <button class="btn btn-danger" data-remove="${escapeHtml(ip)}" type="button" title="Remove ${escapeHtml(ip)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><path d="M6 6l12 12M18 6L6 18" stroke-linecap="round"/></svg>
        </button>
      </td>
    </tr>`;
}

function showError(message) {
  const el = document.getElementById('form-error');
  if (!message) { el.style.display = 'none'; el.textContent = ''; return; }
  el.textContent = message;
  el.style.display = 'flex';
}

async function load() {
  showError('');
  const data = await fetchJson('/api/allowed-ips');
  const body = document.getElementById('table-body');
  body.innerHTML = data.ips.length
    ? data.ips.map(rowHtml).join('')
    : `<tr><td colspan="3"><div class="empty-state">
         <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20 6L9 17l-5-5"/></svg>
         <span>No allowed IPs yet. Add one above.</span>
       </div></td></tr>`;
  document.getElementById('page-info').textContent = `${data.ips.length} IP${data.ips.length === 1 ? '' : 's'} on the allow list`;

  body.querySelectorAll('[data-remove]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.remove;
      const confirmed = await confirmDialog({
        title: 'Remove Allowed IP',
        message: `Do you want to remove ${ip} from the allow list? It will become eligible for blocking again.`,
      });
      if (!confirmed) return;
      try {
        await fetchJson(`/api/allowed-ips/${encodeURIComponent(ip)}`, { method: 'DELETE' });
        load();
      } catch (e) {
        showError(`Failed to remove ${ip}.`);
      }
    });
  });
}

document.getElementById('add-ip-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('new-ip');
  const ip = input.value.trim();
  if (!ip) return;
  try {
    const res = await fetch('/api/allowed-ips', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    });
    if (res.status === 401) { window.location.href = '/login'; return; }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      showError(body.detail || `Could not add ${ip}.`);
      return;
    }
    input.value = '';
    load();
  } catch (e) {
    showError(`Could not add ${ip}.`);
  }
});

load();

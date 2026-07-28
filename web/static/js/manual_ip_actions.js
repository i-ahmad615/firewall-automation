// ── Manual Block ────────────────────────────────────────────────────────

function showBlockMessage(message, isError) {
  const el = document.getElementById('block-message');
  if (!message) { el.style.display = 'none'; return; }
  el.className = `alert-banner ${isError ? 'error' : 'success'}`;
  el.style.display = 'flex';
  el.textContent = message;
}

document.getElementById('block-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ipInput = document.getElementById('block-ip');
  const reasonInput = document.getElementById('block-reason');
  const submitBtn = document.getElementById('block-submit');
  const submitLabel = document.getElementById('block-submit-label');
  const ip = ipInput.value.trim();
  const reason = reasonInput.value.trim();
  if (!ip) { showBlockMessage('Enter an IP address.', true); return; }

  const confirmed = await confirmDialog({
    title: 'Block IP Address',
    message: `Block ${ip} on the firewall now?${reason ? ` Reason: ${reason}` : ''}`,
    confirmLabel: 'Block',
  });
  if (!confirmed) return;

  submitBtn.disabled = true;
  ipInput.disabled = true;
  reasonInput.disabled = true;
  submitLabel.textContent = 'Blocking…';
  showBlockMessage('', false);

  try {
    const res = await fetch('/api/manual-block', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason }),
    });
    if (res.status === 401) { window.location.href = '/login'; return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showBlockMessage(data.detail || `Could not block ${ip}.`, true);
      return;
    }
    showBlockMessage(data.detail || `${ip} has been blocked.`, false);
    ipInput.value = '';
    reasonInput.value = '';
    loadBlockedIps();
  } catch (err) {
    showBlockMessage(`Could not block ${ip} -- check firewall connectivity.`, true);
  } finally {
    submitBtn.disabled = false;
    ipInput.disabled = false;
    reasonInput.disabled = false;
    submitLabel.textContent = 'Block IP';
  }
});

// ── Manual Unblock ──────────────────────────────────────────────────────

const state = { search: '', status: 'blocked', sort_by: 'blocked_at', sort_dir: 'desc', page: 1, page_size: 25 };
let debounceTimer;

function showUnblockMessage(message, isError) {
  const el = document.getElementById('unblock-message');
  if (!message) { el.style.display = 'none'; return; }
  el.className = `alert-banner ${isError ? 'error' : 'success'}`;
  el.style.display = 'flex';
  el.textContent = message;
}

function statusBadge(status) {
  return status === 'blocked'
    ? '<span class="badge warning">Blocked</span>'
    : '<span class="badge neutral">Unblocked</span>';
}

function sourceBadge(source) {
  return source === 'manual'
    ? '<span class="badge info">Manual</span>'
    : '<span class="badge neutral">Automatic</span>';
}

function rowHtml(r) {
  const isBlocked = r.status === 'blocked';
  const isProtected = !!r.protected;
  let actionCell = '';
  if (isBlocked) {
    actionCell = isProtected
      ? `<button class="btn btn-danger btn-sm" disabled title="Protected -- cannot be unblocked">Unblock</button>`
      : `<button class="btn btn-danger btn-sm" data-unblock="${escapeHtml(r.ip)}" type="button">Unblock</button>`;
  }
  return `
    <tr>
      <td class="cell-mono">${escapeHtml(r.ip)}</td>
      <td class="cell-mono">${escapeHtml(r.host_name || '—')}</td>
      <td class="cell-wrap">${escapeHtml(r.reason || '—')}</td>
      <td class="cell-mono">${fmtDate(r.blocked_at)}<br><span class="cell-muted">${fmtClock(r.blocked_at)}</span></td>
      <td>${sourceBadge(r.source)}${isProtected ? ' <span class="badge danger">Protected</span>' : ''}</td>
      <td>${statusBadge(r.status)}</td>
      <td>${actionCell}</td>
    </tr>`;
}

async function loadBlockedIps() {
  // `qs` removes empty values, but an omitted status makes this endpoint
  // default to "blocked". Keep the empty status parameter when "All" is
  // selected so FastAPI receives status="" and does not apply a filter.
  const params = new URLSearchParams(qs(state));
  params.set('status', state.status);
  const data = await fetchJson(`/api/blocked-ips?${params.toString()}`);
  document.getElementById('table-body').innerHTML =
    data.rows.length ? data.rows.map(rowHtml).join('') :
    `<tr><td colspan="7"><div class="empty-state">No IPs match the current filters.</div></td></tr>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} · ${data.total} total`;
  document.getElementById('prev-page').disabled = data.page <= 1;
  document.getElementById('next-page').disabled = data.page >= totalPages;

  document.querySelectorAll('#table thead th[data-key]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.key === state.sort_by);
    th.classList.toggle('asc', th.dataset.key === state.sort_by && state.sort_dir === 'asc');
  });

  document.querySelectorAll('[data-unblock]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.unblock;
      const confirmed = await confirmDialog({
        title: 'Unblock IP Address',
        message: `Remove the firewall block for ${ip}? This IP will be allowed through again.`,
        confirmLabel: 'Unblock',
      });
      if (!confirmed) return;

      showUnblockMessage('', false);
      btn.disabled = true;
      const originalLabel = btn.textContent;
      btn.textContent = 'Unblocking…';
      try {
        const res = await fetch(`/api/blocked-ips/${encodeURIComponent(ip)}`, {
          method: 'DELETE', credentials: 'same-origin',
        });
        if (res.status === 401) { window.location.href = '/login'; return; }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showUnblockMessage(data.detail || `Could not unblock ${ip}.`, true);
          btn.disabled = false;
          btn.textContent = originalLabel;
          return;
        }
        showUnblockMessage(data.detail || `${ip} has been unblocked.`, false);
        loadBlockedIps();
      } catch (err) {
        showUnblockMessage(`Could not unblock ${ip} -- check firewall connectivity.`, true);
        btn.disabled = false;
        btn.textContent = originalLabel;
      }
    });
  });
}

document.getElementById('f-search').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { state.search = e.target.value; state.page = 1; loadBlockedIps(); }, 300);
});
document.getElementById('f-status').addEventListener('change', (e) => { state.status = e.target.value; state.page = 1; loadBlockedIps(); });
document.getElementById('prev-page').addEventListener('click', () => { state.page = Math.max(1, state.page - 1); loadBlockedIps(); });
document.getElementById('next-page').addEventListener('click', () => { state.page += 1; loadBlockedIps(); });
document.querySelectorAll('#table thead th[data-key]').forEach(th => {
  th.addEventListener('click', () => {
    const key = th.dataset.key;
    if (state.sort_by === key) { state.sort_dir = state.sort_dir === 'asc' ? 'desc' : 'asc'; }
    else { state.sort_by = key; state.sort_dir = 'desc'; }
    loadBlockedIps();
  });
});

loadBlockedIps();
setInterval(loadBlockedIps, 20000);

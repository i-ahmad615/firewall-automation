const state = { search: '', status: '', sort_by: 'last_attempt_at', sort_dir: 'desc', page: 1, page_size: 25 };
let debounceTimer;

function statusBadge(status) {
  if (status === 'retrying') return '<span class="badge warning">Retrying</span>';
  if (status === 'paused') return '<span class="badge neutral">Paused</span>';
  return '<span class="badge info">Pending</span>';
}

function showQueueActionMessage(message, isError = false) {
  const banner = document.getElementById('queue-action-message');
  banner.style.display = message ? 'flex' : 'none';
  banner.className = `alert-banner ${isError ? 'error' : 'success'}`;
  banner.textContent = message;
}

function rowHtml(r) {
  const error = r.last_error || '';
  const stateAction = r.active
    ? `<button class="btn btn-sm" data-queue-action="pause" data-ip="${escapeHtml(r.ip)}" type="button">Pause</button>`
    : `<button class="btn btn-sm" data-queue-action="resume" data-ip="${escapeHtml(r.ip)}" type="button">Resume</button>`;
  return `
    <tr>
      <td class="cell-mono" data-label="IP Address">${escapeHtml(r.ip)}</td>
      <td class="cell-mono" data-label="Alarm ID">${escapeHtml(r.alarm_id || '—')}</td>
      <td class="retry-count" data-label="Retry Count">${escapeHtml(String(r.attempts))}</td>
      <td class="cell-mono retry-date" data-label="Last Attempt">${fmtDate(r.last_attempt_at)}<br><span class="cell-muted">${fmtClock(r.last_attempt_at)}</span></td>
      <td class="cell-mono retry-date" data-label="Next Retry">${fmtDate(r.next_retry_at)}<br><span class="cell-muted">${fmtClock(r.next_retry_at)}</span></td>
      <td class="cell-muted retry-error" data-label="Last Error" title="${escapeHtml(error)}">${escapeHtml(error)}</td>
      <td class="retry-status" data-label="Status">${statusBadge(r.status)}</td>
      <td data-label="Actions"><div class="retry-actions">${stateAction}<button class="btn btn-danger btn-sm" data-queue-action="remove" data-ip="${escapeHtml(r.ip)}" type="button">Remove</button></div></td>
    </tr>`;
}

async function load() {
  const data = await fetchJson(`/api/pending-blocks?${qs({ search: state.search, sort_by: state.sort_by, sort_dir: state.sort_dir, page: state.page, page_size: state.page_size })}`);
  const rows = state.status ? data.rows.filter(r => r.status === state.status) : data.rows;

  document.getElementById('table-body').innerHTML =
    rows.length ? rows.map(rowHtml).join('') :
    `<tr class="retry-empty-row"><td colspan="8"><div class="empty-state">No failed IPs are currently queued for retry.</div></td></tr>`;

  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById('page-info').textContent = `Page ${data.page} of ${totalPages} · ${data.total} total`;
  document.getElementById('prev-page').disabled = data.page <= 1;
  document.getElementById('next-page').disabled = data.page >= totalPages;

  document.querySelectorAll('#table thead th[data-key]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.key === state.sort_by);
    th.classList.toggle('asc', th.dataset.key === state.sort_by && state.sort_dir === 'asc');
  });

  document.querySelectorAll('[data-queue-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.ip;
      const action = btn.dataset.queueAction;
      const isRemove = action === 'remove';
      const confirmed = await confirmDialog({
        title: isRemove ? 'Remove IP from Retry Queue' : action === 'pause' ? 'Pause Automatic Retries' : 'Resume Automatic Retries',
        message: isRemove
          ? `Stop retrying ${ip} and remove it from the retry queue permanently? This IP will not be retried again unless a new security alert is received for it.`
          : action === 'pause'
            ? `Pause automatic retries for ${ip}? Its retry count and history will be preserved.`
            : `Resume automatic retries for ${ip}? It will be attempted again during the next monitoring cycle.`,
        confirmLabel: isRemove ? 'Remove' : action === 'pause' ? 'Pause' : 'Resume',
        danger: isRemove,
      });
      if (!confirmed) return;
      btn.disabled = true;
      showQueueActionMessage('');
      try {
        const url = isRemove
          ? `/api/pending-blocks/${encodeURIComponent(ip)}`
          : `/api/pending-blocks/${encodeURIComponent(ip)}/${action}`;
        await fetchJson(url, { method: isRemove ? 'DELETE' : 'POST' });
        showQueueActionMessage(
          isRemove ? `${ip} removed from the retry queue.` : `Automatic retries for ${ip} ${action === 'pause' ? 'paused' : 'resumed'}.`
        );
        await load();
      } catch (error) {
        showQueueActionMessage(`Unable to ${action} retries for ${ip}: ${error.message}.`, true);
        btn.disabled = false;
      }
    });
  });
}

document.getElementById('f-search').addEventListener('input', (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => { state.search = e.target.value; state.page = 1; load(); }, 300);
});
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

load();
setInterval(load, 10000);

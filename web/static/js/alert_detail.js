const alertId = window.ALERT_DETAIL_ID;
let detailData = null;

function display(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return value == null || value === '' ? '—' : String(value);
}

function kvItem(label, value, { date = false, copy = false } = {}) {
  const rendered = date && value ? fmtTime(value) : display(value);
  return `<div class="kv-item"><span class="kv-label">${escapeHtml(label)}</span><span class="kv-value">${escapeHtml(rendered)}${copy && value ? ` <button class="copy-inline" type="button" data-copy-value="${escapeHtml(String(value))}" aria-label="Copy ${escapeHtml(label)}">Copy</button>` : ''}</span></div>`;
}

function renderKV(target, items) {
  document.getElementById(target).innerHTML = items.map(item => kvItem(...item)).join('');
}

function validationTone(result) {
  return result === 'Passed' ? 'success' : result === 'Failed' ? 'danger' : 'neutral';
}

function decisionLabel(value) {
  return ({ approved: 'Approved for blocking', ignored: 'Ignored', rejected: 'Rejected', failed_validation: 'Failed validation' })[value] || display(value);
}

function renderRetries(data) {
  const retry = data.retry;
  renderKV('retry-summary', [
    ['Total retries', retry.total_attempts], ['Current retry status', retry.status],
    ['Next scheduled retry', retry.next_retry_at, { date: true }], ['Retries active', retry.active],
  ]);
  document.getElementById('retry-table').innerHTML = retry.history.length ? retry.history.map(row => `
    <tr><td>${escapeHtml(row.attempt_number)}</td><td>${escapeHtml(fmtTime(row.attempted_at))}</td><td>${badgeHtml(row.status)}</td>
    <td class="cell-wrap">${escapeHtml(row.error || '—')}</td><td>${escapeHtml(row.next_retry_at ? fmtTime(row.next_retry_at) : '—')}</td><td>${escapeHtml(row.source || '—')}</td></tr>`).join('') :
    '<tr><td colspan="6"><div class="empty-state">No retry attempts are recorded for this alert or IP.</div></td></tr>';

  const actions = document.getElementById('retry-actions');
  if (!retry.pending) { actions.innerHTML = ''; return; }
  actions.innerHTML = `${retry.active ? '<button class="btn" data-retry-action="retry" type="button">Retry Now</button><button class="btn" data-retry-action="stop" type="button">Stop Retry</button>' : ''}<button class="btn btn-danger" data-retry-action="remove" type="button">Remove from Failed Queue</button>`;
}

function render(data) {
  detailData = data;
  const a = data.alert;
  document.getElementById('detail-alert-label').textContent = `Database alert #${a.id}`;
  document.getElementById('summary-status').innerHTML = badgeHtml(a.current_status);
  renderKV('summary-grid', [
    ['Alert ID', a.alert_id, { copy: true }], ['Received date and time', a.received_at, { date: true }],
    ['Email sender', a.sender], ['Email subject', a.subject], ['Classification', a.classification],
    ['Current status', a.current_status], ['Processing source', a.processing_source],
    ['Created date', a.created_at, { date: true }], ['Last updated date', a.updated_at, { date: true }],
  ]);
  renderKV('email-meta', [['Subject', data.email.subject], ['Sender', data.email.sender], ['Received', data.email.received_at, { date: true }]]);
  const emailBody = document.getElementById('email-body');
  emailBody.innerHTML = data.email.body_sanitized;
  document.getElementById('email-empty').hidden = data.email.has_body;
  emailBody.hidden = !data.email.has_body;
  document.getElementById('toggle-email').hidden = !data.email.has_body;

  const ip = data.ip_info;
  renderKV('ip-grid', [
    ['Extracted source IP', ip.origin_ip, { copy: true }], ['Impacted IP', ip.impacted_ip, { copy: true }],
    ['IP type', ip.ip_type], ['Public IP', ip.is_public], ['Trusted', ip.is_trusted],
    ['Already blocked', ip.already_blocked], ['Sophos host object', ip.host_name],
    ['First seen', ip.first_seen, { date: true }], ['Last seen', ip.last_seen, { date: true }],
    ['Previous alerts for same IP', ip.previous_alert_count],
  ]);
  document.getElementById('validation-decision').innerHTML = badgeHtml(decisionLabel(data.validation.decision));
  document.getElementById('validation-list').innerHTML = data.validation.checks.length ? data.validation.checks.map(check => `
    <div class="validation-row"><span>${escapeHtml(check.check)}</span><span class="badge ${validationTone(check.result)}">${escapeHtml(check.result)}</span><span class="cell-muted">${escapeHtml(check.message || '')}</span></div>`).join('') : '<div class="empty-state">No validation checks were stored for this older alert.</div>';
  renderRetries(data);
}

async function loadDetail() {
  try {
    const data = await fetchJson(`/api/alerts/${alertId}`);
    render(data);
    document.getElementById('detail-loading').hidden = true;
    document.getElementById('detail-content').hidden = false;
  } catch (error) {
    document.getElementById('detail-loading').hidden = true;
    const banner = document.getElementById('detail-error');
    banner.hidden = false;
    banner.textContent = error.message.includes('404') ? 'Alert not found.' : 'Unable to load alert details. Please try again.';
  }
}

document.getElementById('toggle-email').addEventListener('click', event => {
  const body = document.getElementById('email-body');
  const expanded = body.classList.toggle('expanded');
  body.classList.toggle('collapsed', !expanded);
  event.currentTarget.textContent = expanded ? 'Collapse email' : 'Expand full email';
});

document.addEventListener('click', async event => {
  const copy = event.target.closest('[data-copy-value], .copy-btn');
  if (copy) {
    const value = copy.dataset.copyValue != null ? copy.dataset.copyValue : document.getElementById(copy.dataset.copyTarget).textContent;
    await navigator.clipboard.writeText(value);
    const original = copy.textContent; copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = original; }, 1200);
    return;
  }
  const action = event.target.closest('[data-retry-action]');
  if (!action || !detailData.ip_info.block_candidate) return;
  const ip = detailData.ip_info.block_candidate;
  const kind = action.dataset.retryAction;
  const destructive = kind !== 'retry';
  const confirmed = await confirmDialog({
    title: kind === 'retry' ? 'Retry firewall action now?' : kind === 'stop' ? 'Stop automatic retries?' : 'Remove from failed queue?',
    message: kind === 'remove' ? `This permanently removes ${ip} from the failed queue.` : `Apply this action to ${ip}?`,
    confirmLabel: kind === 'retry' ? 'Retry Now' : kind === 'stop' ? 'Stop Retry' : 'Remove', danger: destructive,
  });
  if (!confirmed) return;
  action.disabled = true;
  try {
    if (kind === 'remove') await fetchJson(`/api/pending-blocks/${encodeURIComponent(ip)}`, { method: 'DELETE' });
    else await fetchJson(`/api/pending-blocks/${encodeURIComponent(ip)}/${kind === 'retry' ? 'retry-now' : 'stop'}`, { method: 'POST' });
    await loadDetail();
  } finally { action.disabled = false; }
});

const returnTo = new URLSearchParams(window.location.search).get('return');
if (returnTo && returnTo.startsWith('/alerts') && !returnTo.startsWith('//')) document.getElementById('back-to-alerts').href = returnTo;
loadDetail();

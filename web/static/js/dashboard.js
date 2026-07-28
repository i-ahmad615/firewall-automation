const STAT_DEFS = [
  { key: 'total_emails_processed', label: 'Total Emails Processed', tone: 'primary', icon: 'mail', filter: {} },
  { key: 'attack_emails_detected', label: 'Attack Emails Detected', tone: 'danger', icon: 'alert', filter: { status: 'processed' } },
  { key: 'successful_blocks', label: 'Successful Blocks', tone: 'success', icon: 'shield', filter: { action_taken: 'blocked' } },
  { key: 'failed_blocks', label: 'Failed Blocks', tone: 'warning', icon: 'x', href: '/failed-ip-queue' },
  { key: 'duplicate_ips', label: 'Duplicate IPs', tone: 'neutral', icon: 'copy', filter: { action_taken: 'duplicate' } },
  { key: 'allowed_ips_ignored', label: 'Allowed IPs Ignored', tone: 'neutral', icon: 'check', filter: { action_taken: 'allowed' } },
  { key: 'firewall_rule_updates', label: 'Firewall Rule Updates', tone: 'primary', icon: 'refresh', filter: { action_taken: 'blocked' } },
  { key: 'total_notifications_sent', label: 'Notifications Sent', tone: 'success', icon: 'bell', filter: { notification_sent: '1' } },
];

function goToAlertsWithFilter(filter) {
  const query = qs(filter);
  window.location.href = query ? `/alerts?${query}` : '/alerts';
}

const ICONS = {
  mail: '<path d="M4 4h16v16H4z" rx="2"/><path d="M4 6l8 6 8-6" />',
  alert: '<path d="M12 2l9 18H3z" stroke-linejoin="round"/><path d="M12 9v5" stroke-linecap="round"/>',
  shield: '<path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/>',
  x: '<path d="M6 6l12 12M18 6L6 18" stroke-linecap="round"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><rect x="4" y="4" width="11" height="11" rx="2"/>',
  check: '<path d="M20 6L9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/>',
  refresh: '<path d="M3 12a9 9 0 0115.5-6.3M21 12a9 9 0 01-15.5 6.3" stroke-linecap="round"/><path d="M3 5v5h5M21 19v-5h-5" stroke-linecap="round" stroke-linejoin="round"/>',
  bell: '<path d="M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 01-3.4 0"/>',
};

let statsGridBuilt = false;
const lastStatValue = {};

function animateCount(el, from, to, duration = 700) {
  const start = performance.now();
  const diff = to - from;
  if (diff === 0) { el.textContent = to.toLocaleString(); return; }
  function tick(now) {
    const t = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
    const value = Math.round(from + diff * eased);
    el.textContent = value.toLocaleString();
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderStats(stats) {
  const grid = document.getElementById('stat-grid');

  if (!statsGridBuilt) {
    grid.innerHTML = STAT_DEFS.map((def, i) => `
      <div class="card stat-card tone-${def.tone} enter" style="animation-delay:${i * 60}ms" data-stat-key="${def.key}" title="${def.href ? 'Double-click to view Failed IP Queue' : 'Double-click to view in Alert History'}">
        <span class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ICONS[def.icon]}</svg></span>
        <span class="stat-label">${def.label}</span>
        <span class="stat-value" data-key="${def.key}">0</span>
      </div>
    `).join('');
    grid.querySelectorAll('.stat-card').forEach(card => {
      const def = STAT_DEFS.find(d => d.key === card.dataset.statKey);
      if (def) card.addEventListener('dblclick', () => def.href ? (window.location.href = def.href) : goToAlertsWithFilter(def.filter));
    });
    statsGridBuilt = true;
  }

  STAT_DEFS.forEach(def => {
    const value = stats[def.key] ?? 0;
    const el = grid.querySelector(`[data-key="${def.key}"]`);
    const from = lastStatValue[def.key] ?? 0;
    if (el && from !== value) animateCount(el, from, value);
    else if (el && from === undefined) el.textContent = value.toLocaleString();
    lastStatValue[def.key] = value;
  });
}

async function loadStats() {
  try {
    const stats = await fetchJson('/api/stats');
    renderStats(stats);
  } catch (e) { /* ignore transient errors */ }
}

const BREAKDOWN_COLORS = {
  ignored: '#5AA9E6',   // ignored mails
  blocked: '#7BC9A0',   // blocked successfully
  allowed: '#B3A6E0',   // allowed IP
  duplicate: '#E3B97A', // duplicate IP
  failed: '#E3A0AD',    // block failed
};

async function loadCharts() {
  try {
    const data = await fetchJson('/api/stats/timeseries?days=14');
    drawLineChart(document.getElementById('chart-timeseries'), data.series, {
      lines: [
        { key: 'total', color: '#5aa9e6', label: 'Total processed' },
        { key: 'blocked', color: '#7bc9a0', label: 'Blocked' },
      ],
    });
    drawBarChart(document.getElementById('chart-breakdown'), data.breakdown, {
      valueKey: 'value', labelKey: 'label',
      colorMap: BREAKDOWN_COLORS,
      onBarDblClick: (d) => goToAlertsWithFilter({ action_taken: d.label }),
    });
  } catch (e) { /* ignore */ }
}

function pushFeedItem(evt) {
  const feed = document.getElementById('live-feed');
  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();

  const item = document.createElement('div');
  item.className = 'feed-item';
  item.innerHTML = `
    <span class="feed-time">${fmtClock(evt.timestamp)}</span>
    <span class="feed-dot ${evt.success ? 'ok' : 'fail'}"></span>
    <span class="feed-body">
      <span class="category">${escapeHtml(evt.category)}</span>
      <div class="message">${escapeHtml(evt.message)}</div>
    </span>
  `;
  feed.prepend(item);
  while (feed.children.length > 60) feed.removeChild(feed.lastChild);
}

function connectLiveFeed() {
  const source = new EventSource('/api/events');
  source.onmessage = (e) => {
    try {
      const evt = JSON.parse(e.data);
      pushFeedItem(evt);
      loadStats();
    } catch (err) { /* ignore malformed event */ }
  };
  source.onerror = () => { source.close(); setTimeout(connectLiveFeed, 3000); };
}

loadStats();
loadCharts();
connectLiveFeed();
setInterval(loadStats, 15000);
setInterval(loadCharts, 60000);

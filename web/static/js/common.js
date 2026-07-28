// Shared dashboard utilities: clock, formatting, badges, sidebar collapse
// behavior, and lightweight dependency-free SVG charting (no CDN, no build step).

// ── Collapsible sidebar (icon rail by default, expands on hover or pin) ────
(function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const pinBtn = document.getElementById('sidebar-pin');
  if (!sidebar || !pinBtn) return;

  const root = document.documentElement;
  let pinned = root.classList.contains('sidebar-pinned');
  pinBtn.setAttribute('aria-pressed', String(pinned));

  sidebar.addEventListener('mouseenter', () => {
    if (!pinned) root.classList.add('sidebar-hover');
  });
  sidebar.addEventListener('mouseleave', () => {
    if (!pinned) root.classList.remove('sidebar-hover');
  });

  pinBtn.addEventListener('click', () => {
    pinned = !pinned;
    root.classList.toggle('sidebar-pinned', pinned);
    root.classList.remove('sidebar-hover');
    pinBtn.setAttribute('aria-pressed', String(pinned));
    try { localStorage.setItem('sidebarPinned', String(pinned)); } catch (e) {}
  });
})();

// ── Firewall connectivity status pill (topbar, all pages) ──────────────────
function initConnectivityStatus(service, displayName) {
  const pill = document.getElementById(`${service}-status-pill`);
  const label = document.getElementById(`${service}-status-label`);
  if (!pill || !label) return;

  function render(state, text) {
    pill.classList.remove('checking', 'online', 'offline');
    pill.classList.add(state);
    label.textContent = text;
  }

  function applyStatus(status) {
    if (status.online === true) {
      render('online', `${displayName}: online`);
    } else if (status.online === false) {
      render('offline', `${displayName}: unavailable`);
    } else {
      render('checking', `${displayName}: checking…`);
    }
  }

  async function refresh() {
    try {
      const status = await fetchJson(`/api/${service}-status`);
      applyStatus(status);
    } catch (e) { /* ignore transient errors */ }
  }

  async function testNow() {
    render('checking', `${displayName}: checking…`);
    pill.disabled = true;
    try {
      const status = await fetchJson(`/api/${service}-status/check`, { method: 'POST' });
      applyStatus(status);
    } catch (e) {
      render('offline', `${displayName}: unavailable`);
    } finally {
      pill.disabled = false;
    }
  }

  pill.addEventListener('click', testNow);
  refresh();
  setInterval(refresh, 20000);
}

initConnectivityStatus('firewall', 'Firewall');
initConnectivityStatus('imap', 'IMAP');
initConnectivityStatus('smtp', 'SMTP');

// ── Reusable confirmation modal (for destructive actions) ──────────────────
function confirmDialog({ title = 'Are you sure?', message = '', confirmLabel = 'Yes', cancelLabel = 'No', danger = true } = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal-card" role="alertdialog" aria-modal="true" aria-labelledby="modal-title">
        <h3 id="modal-title">${escapeHtml(title)}</h3>
        <p>${escapeHtml(message)}</p>
        <div class="modal-actions">
          <button class="btn" type="button" data-action="cancel">${escapeHtml(cancelLabel)}</button>
          <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" type="button" data-action="confirm">${escapeHtml(confirmLabel)}</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    function onKeydown(e) {
      if (e.key === 'Escape') close(false);
    }
    function close(result) {
      document.removeEventListener('keydown', onKeydown);
      overlay.remove();
      resolve(result);
    }

    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(false); });
    overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => close(false));
    overlay.querySelector('[data-action="confirm"]').addEventListener('click', () => close(true));
    document.addEventListener('keydown', onKeydown);
    overlay.querySelector('[data-action="confirm"]').focus();
  });
}

function tickClock() {
  const el = document.getElementById('clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleString(undefined, {
    weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}
setInterval(tickClock, 1000 * 30);
tickClock();

function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString();
}

function fmtClock(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleTimeString();
}

const BADGE_MAP = {
  blocked: 'success', duplicate: 'warning', allowed: 'info', failed: 'danger',
  ignored: 'neutral', processed: 'info', success: 'success', failure: 'danger',
  sent: 'success', stopped: 'neutral', paused: 'neutral', pending: 'warning', retrying: 'info',
  'pending retry': 'warning', unblocked: 'info', removed: 'neutral',
  passed: 'success', skipped: 'neutral', rejected: 'danger',
};

function badgeHtml(value) {
  if (!value) return '<span class="badge neutral">—</span>';
  const tone = BADGE_MAP[value.toLowerCase()] || 'neutral';
  return `<span class="badge ${tone}">${escapeHtml(value)}</span>`;
}

function severityBadge(sev) {
  const tone = { ERROR: 'danger', CRITICAL: 'danger', WARNING: 'warning', SUCCESS: 'success', INFO: 'info', DEBUG: 'neutral' }[sev] || 'neutral';
  return `<span class="badge ${tone}">${sev}</span>`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, { credentials: 'same-origin', ...options });
  if (res.status === 401) {
    window.location.href = '/login';
    throw new Error('unauthenticated');
  }
  if (!res.ok) throw new Error(`request failed: ${res.status}`);
  return res.json();
}

function qs(params) {
  const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== '' && v != null));
  return new URLSearchParams(clean).toString();
}

// ── Minimal SVG line/area chart (no external dependency) ─────────────────

function drawLineChart(svgEl, data, opts = {}) {
  // Backward-compatible single-line shorthand: { color, valueKey, labelKey }
  const lines = opts.lines || [{ key: opts.valueKey || 'total', color: opts.color || '#5aa9e6' }];
  const labelKey = opts.labelKey || 'day';

  svgEl.innerHTML = '';
  const width = svgEl.clientWidth || 600;
  const height = svgEl.clientHeight || 220;
  const padding = { top: 16, right: 12, bottom: 26, left: 12 };
  const w = width - padding.left - padding.right;
  const h = height - padding.top - padding.bottom;

  svgEl.setAttribute('viewBox', `0 0 ${width} ${height}`);

  if (!data.length) {
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', width / 2);
    text.setAttribute('y', height / 2);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', 'var(--color-muted)');
    text.setAttribute('font-size', '13');
    text.textContent = 'No data yet';
    svgEl.appendChild(text);
    return;
  }

  const ns = 'http://www.w3.org/2000/svg';
  const maxVal = Math.max(1, ...lines.flatMap(l => data.map(d => d[l.key] || 0)));
  const stepX = data.length > 1 ? w / (data.length - 1) : 0;
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const xFor = (i) => padding.left + i * stepX;
  const yFor = (v) => padding.top + h - (v / maxVal) * h;

  lines.forEach((lineDef, lineIndex) => {
    const points = data.map((d, i) => [xFor(i), yFor(d[lineDef.key] || 0)]);
    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${p[0]},${p[1]}`).join(' ');

    // Area fill only under the first (primary) line, to keep multi-line charts legible
    if (lineIndex === 0) {
      const areaPath = `${linePath} L${points[points.length - 1][0]},${padding.top + h} L${points[0][0]},${padding.top + h} Z`;
      const defs = document.createElementNS(ns, 'defs');
      const gradId = 'grad-' + Math.random().toString(36).slice(2);
      defs.innerHTML = `<linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${lineDef.color}" stop-opacity="0.35"/>
        <stop offset="100%" stop-color="${lineDef.color}" stop-opacity="0"/>
      </linearGradient>`;
      svgEl.appendChild(defs);

      const area = document.createElementNS(ns, 'path');
      area.setAttribute('d', areaPath);
      area.setAttribute('fill', `url(#${gradId})`);
      svgEl.appendChild(area);
      if (!reduceMotion) {
        area.style.opacity = '0';
        area.style.transition = 'opacity 700ms ease 400ms';
        requestAnimationFrame(() => { area.style.opacity = '1'; });
      }
    }

    const line = document.createElementNS(ns, 'path');
    line.setAttribute('d', linePath);
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', lineDef.color);
    line.setAttribute('stroke-width', '2.5');
    line.setAttribute('stroke-linecap', 'round');
    line.setAttribute('stroke-linejoin', 'round');
    svgEl.appendChild(line);

    if (!reduceMotion) {
      const length = line.getTotalLength();
      line.style.strokeDasharray = `${length}`;
      line.style.strokeDashoffset = `${length}`;
      line.getBoundingClientRect(); // force reflow
      line.style.transition = `stroke-dashoffset 900ms cubic-bezier(0.16, 1, 0.3, 1) ${lineIndex * 120}ms`;
      requestAnimationFrame(() => { line.style.strokeDashoffset = '0'; });
    }

    points.forEach((p, i) => {
      const circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('cx', p[0]);
      circle.setAttribute('cy', p[1]);
      circle.setAttribute('r', 3.5);
      circle.setAttribute('fill', lineDef.color);
      circle.setAttribute('stroke', 'var(--color-surface)');
      circle.setAttribute('stroke-width', '1.5');
      const title = document.createElementNS(ns, 'title');
      title.textContent = `${lineDef.label || lineDef.key} — ${data[i][labelKey]}: ${data[i][lineDef.key] || 0}`;
      circle.appendChild(title);
      svgEl.appendChild(circle);
    });
  });

  data.forEach((d, i) => {
    if (data.length <= 20 || i % Math.ceil(data.length / 10) === 0) {
      const label = document.createElementNS(ns, 'text');
      label.setAttribute('x', xFor(i));
      label.setAttribute('y', height - 6);
      label.setAttribute('text-anchor', 'middle');
      label.setAttribute('font-size', '10');
      label.setAttribute('fill', 'var(--color-muted)');
      label.textContent = (d[labelKey] || '').slice(5);
      svgEl.appendChild(label);
    }
  });
}

const PALETTE = ['#5aa9e6', '#7bc9a0', '#b3a6e0', '#e3b97a', '#e3a0ad', '#a9b8c8'];

function drawBarChart(svgEl, data, { valueKey = 'value', labelKey = 'label', onBarDblClick = null, colorMap = null } = {}) {
  svgEl.innerHTML = '';
  const width = svgEl.clientWidth || 400;
  const height = svgEl.clientHeight || 220;
  const padding = { top: 16, right: 12, bottom: 30, left: 12 };
  const w = width - padding.left - padding.right;
  const h = height - padding.top - padding.bottom;
  svgEl.setAttribute('viewBox', `0 0 ${width} ${height}`);

  if (!data.length) {
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', width / 2);
    text.setAttribute('y', height / 2);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', 'var(--color-muted)');
    text.setAttribute('font-size', '13');
    text.textContent = 'No data yet';
    svgEl.appendChild(text);
    return;
  }

  const ns = 'http://www.w3.org/2000/svg';
  const maxVal = Math.max(1, ...data.map(d => d[valueKey]));
  const bandWidth = w / data.length;
  const barWidth = Math.min(48, bandWidth * 0.5);
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  data.forEach((d, i) => {
    const barHeight = (d[valueKey] / maxVal) * h;
    const x = padding.left + i * bandWidth + (bandWidth - barWidth) / 2;
    const y = padding.top + h - barHeight;
    const rect = document.createElementNS(ns, 'rect');
    rect.setAttribute('x', x);
    rect.setAttribute('width', barWidth);
    rect.setAttribute('rx', 6);
    const barColor = (colorMap && colorMap[d[labelKey]]) || PALETTE[i % PALETTE.length];
    rect.setAttribute('fill', barColor);
    const title = document.createElementNS(ns, 'title');
    title.textContent = onBarDblClick
      ? `${d[labelKey]}: ${d[valueKey]} (double-click to view)`
      : `${d[labelKey]}: ${d[valueKey]}`;
    rect.appendChild(title);

    if (onBarDblClick) {
      rect.style.cursor = 'pointer';
      rect.addEventListener('dblclick', () => onBarDblClick(d));
    }

    if (reduceMotion) {
      rect.setAttribute('y', y);
      rect.setAttribute('height', Math.max(barHeight, 1));
    } else {
      rect.setAttribute('y', padding.top + h);
      rect.setAttribute('height', 0);
      rect.style.transition = `y 550ms cubic-bezier(0.16, 1, 0.3, 1) ${i * 60}ms, height 550ms cubic-bezier(0.16, 1, 0.3, 1) ${i * 60}ms`;
    }
    svgEl.appendChild(rect);
    if (!reduceMotion) {
      requestAnimationFrame(() => {
        rect.setAttribute('y', y);
        rect.setAttribute('height', Math.max(barHeight, 1));
      });
    }

    const valueLabel = document.createElementNS(ns, 'text');
    valueLabel.setAttribute('x', x + barWidth / 2);
    valueLabel.setAttribute('y', y - 6);
    valueLabel.setAttribute('text-anchor', 'middle');
    valueLabel.setAttribute('font-size', '11');
    valueLabel.setAttribute('font-weight', '600');
    valueLabel.setAttribute('fill', 'var(--color-foreground)');
    valueLabel.textContent = d[valueKey];
    svgEl.appendChild(valueLabel);

    const label = document.createElementNS(ns, 'text');
    label.setAttribute('x', x + barWidth / 2);
    label.setAttribute('y', height - 8);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '10.5');
    label.setAttribute('fill', 'var(--color-muted)');
    label.textContent = d[labelKey];
    svgEl.appendChild(label);
  });
}

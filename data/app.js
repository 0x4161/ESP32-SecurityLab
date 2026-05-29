/* ═══════════════════════════════════════════════════════════
   ESP32 Security Lab — Shared JS utilities
   ═══════════════════════════════════════════════════════════ */


// ── Toast notifications ──────────────────────────────────────
(function () {
  var box = document.createElement('div');
  box.id = 'toast-box';
  document.body.appendChild(box);

  var COLORS = { info:'#00ccff', success:'#00ff88', error:'#ff3355', warn:'#ffaa00' };
  var ICONS  = { info:'ℹ', success:'✓', error:'✗', warn:'⚠' };

  window.toast = function (msg, type) {
    type = type || 'info';
    var el   = document.createElement('div');
    var icon = document.createElement('span');
    var txt  = document.createElement('span');

    el.className   = 'toast';
    el.style.borderLeft = '3px solid ' + (COLORS[type] || COLORS.info);
    icon.style.color    = COLORS[type] || COLORS.info;
    icon.textContent    = ICONS[type]  || 'ℹ';
    txt.textContent     = msg;

    el.appendChild(icon);
    el.appendChild(txt);
    box.appendChild(el);

    setTimeout(function () {
      el.style.transition = 'opacity .3s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 320);
    }, 3200);
  };
}());

// ── Fetch wrapper ────────────────────────────────────────────
// Authentication uses an httpOnly session cookie set by the ESP32 server.
// The browser sends it automatically — no JS credential management needed.
window.api = async function (path, method, body) {
  method = method || 'GET';
  try {
    var opts = { method: method, headers: {}, credentials: 'same-origin' };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    var res  = await fetch(path, opts);
    var data = await res.json();
    return { ok: res.ok, status: res.status, data: data };
  } catch (e) {
    return { ok: false, error: e.message, data: {} };
  }
};

// ── Format helpers ───────────────────────────────────────────
window.fmtBytes = function (b) {
  b = b || 0;
  if (b < 1024)    return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
};

window.pctColor = function (n) {
  if (n < 60) return 'var(--green)';
  if (n < 80) return 'var(--warn)';
  return 'var(--danger)';
};

// Signal quality (0-100) → 5-bar HTML string (no user data, static template)
window.sigBars = function (q) {
  var thresholds = [20, 40, 60, 80, 100];
  var inner = thresholds.map(function (t) {
    return '<span class="' + (q >= t ? 'on' : '') + '"></span>';
  }).join('');
  return '<div class="sig">' + inner + '</div>';
};

// Encryption type → badge HTML (enc is a server-controlled enum string)
window.encBadge = function (enc) {
  var safe = enc.replace(/[^A-Za-z0-9/\-]/g, '');   // strip anything unexpected
  var cls  = safe === 'OPEN'               ? 'badge-red'  :
             safe === 'WPA3'               ? 'badge-green' :
             safe.indexOf('WPA2') >= 0     ? 'badge-blue'  : 'badge-warn';
  return '<span class="badge ' + cls + '">' + safe + '</span>';
};

// HTML-escape a string before inserting into innerHTML
window.esc = function (s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
};

// RSSI value → CSS colour variable
window.rssiColor = function (r) {
  if (r >= -50) return 'var(--green)';
  if (r >= -70) return 'var(--warn)';
  return 'var(--danger)';
};

// ── Active nav link ──────────────────────────────────────────
(function () {
  var page = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav a').forEach(function (a) {
    if (a.getAttribute('href') === page) a.classList.add('active');
  });
}());

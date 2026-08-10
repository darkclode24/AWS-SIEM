/* SIGNAL / INTERCEPT — honeypot console
   Plain vanilla JS. No framework, no chart library.
   Network: relative fetch of meta.json, live.json, archive.json only. */
(function () {
  'use strict';

  /* ================= utilities ================= */

  function $(id) { return document.getElementById(id); }

  function escapeHTML(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      switch (c) {
        case '&': return '&amp;';
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '"': return '&quot;';
        default: return '&#39;';
      }
    });
  }

  function fmt(n) {
    n = Number(n) || 0;
    return n.toLocaleString('en-US');
  }

  function pad2(n) { return n < 10 ? '0' + n : '' + n; }

  function localDateStr(d) {
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  }

  function todayStr() { return localDateStr(new Date()); }

  function addDaysStr(dateStr, days) {
    var d = new Date(dateStr + 'T00:00:00');
    d.setDate(d.getDate() + days);
    return localDateStr(d);
  }

  /* ================= country flags (tiny inline SVGs, solid fills) ================= */

  function flagURI(vRows, hStripes) {
    var svg;
    if (hStripes) {
      // horizontal tricolor: vRows = [top, mid, bottom]
      svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">' +
        '<rect width="14" height="3.34" fill="' + vRows[0] + '"/>' +
        '<rect y="3.33" width="14" height="3.34" fill="' + vRows[1] + '"/>' +
        '<rect y="6.66" width="14" height="3.34" fill="' + vRows[2] + '"/></svg>';
    } else {
      // vertical tricolor: vRows = [left, mid, right]
      svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">' +
        '<rect width="4.67" height="10" fill="' + vRows[0] + '"/>' +
        '<rect x="4.66" width="4.67" height="10" fill="' + vRows[1] + '"/>' +
        '<rect x="9.33" width="4.67" height="10" fill="' + vRows[2] + '"/></svg>';
    }
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  }

  function flagPlain(color) {
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">' +
      '<rect width="14" height="10" fill="' + color + '"/></svg>';
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  }

  // backgroundImage covers every draw (incl. HK star / JP+KR discs / GB diagonals)
  var FLAGS = {
    CN: { backgroundImage: flagPlain('#de2910') },   // China
    HK: { backgroundImage: flagPlain('#de2910') },   // Hong Kong
    TW: { backgroundImage: flagPlain('#000095') },   // Taiwan
    JP: { backgroundImage: flagPlain('#bc002d') },   // Japan
    KR: { backgroundImage: flagPlain('#cd2e3a') },   // South Korea
    RU: { backgroundImage: flagURI(['#ffffff', '#0039a6', '#d52b1e'], true) },
    DE: { backgroundImage: flagURI(['#000000', '#dd0000', '#ffce00'], true) },
    NL: { backgroundImage: flagURI(['#ae1c28', '#ffffff', '#21468b'], true) },
    FR: { backgroundImage: flagURI(['#0055a4', '#ffffff', '#ef4135'], false) },
    IT: { backgroundImage: flagURI(['#009246', '#ffffff', '#ce2b37'], false) },
    IE: { backgroundImage: flagURI(['#169b62', '#ffffff', '#ff883e'], false) },
    BE: { backgroundImage: flagURI(['#000000', '#fdda24', '#ef3340'], false) },
    UA: { backgroundImage: flagURI(['#0057b7', '#ffd700', '#ffd700'], true) },
    IN: { backgroundImage: flagURI(['#ff9933', '#ffffff', '#138808'], true) },
    BG: { backgroundImage: flagURI(['#ffffff', '#00966e', '#d62612'], true) },
    GB: { backgroundImage: flagPlain('#012169') },    // United Kingdom
    US: { // United States — 7 red stripes + canton
      backgroundColor: '#ffffff',
      backgroundImage: flagURI(['#b22234', '#b22234', '#b22234'], true),
      backgroundSize: '100% 53.85%',
      overlay: { inset: '0 46% 53.8% 0', background: '#3c3b6e' }
    },
    BR: { backgroundImage: flagPlain('#009c3b') },    // Brazil
    VN: { backgroundImage: flagPlain('#da251d') },    // Vietnam
    SG: { backgroundImage: flagURI(['#ef3340', '#ffffff', '#ffffff'], true) },
    PL: { backgroundImage: flagURI(['#ffffff', '#dc143c', '#dc143c'], true) }
  };

  var UNKNOWN_FLAG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">' +
    '<rect width="14" height="10" fill="#1e2328"/>' +
    '<rect x="6.5" y="4.5" width="1" height="1" fill="#6b7280"/></svg>'
  );

  var CC_NAMES = {
    CN: 'China', HK: 'Hong Kong', TW: 'Taiwan', JP: 'Japan', KR: 'South Korea',
    RU: 'Russia', DE: 'Germany', NL: 'Netherlands', FR: 'France', IT: 'Italy',
    IE: 'Ireland', BE: 'Belgium', UA: 'Ukraine', IN: 'India', BG: 'Bulgaria',
    GB: 'United Kingdom', US: 'United States', BR: 'Brazil', VN: 'Vietnam',
    SG: 'Singapore', PL: 'Poland'
  };

  function countryName(code) {
    return CC_NAMES[code] || code || '??';
  }

  function makeFlag(code) {
    var span = document.createElement('span');
    span.className = 'lflag';
    span.setAttribute('aria-hidden', 'true');
    var css = {
      display: 'inline-block', width: '14px', height: '10px',
      border: '1px solid #1e2328', position: 'relative', overflow: 'hidden',
      backgroundRepeat: 'no-repeat'
    };
    var f = FLAGS[code];
    for (var k in css) span.style[k] = css[k];
    if (f) {
      if (f.backgroundColor) span.style.backgroundColor = f.backgroundColor;
      if (f.backgroundImage) span.style.backgroundImage = 'url("' + f.backgroundImage + '")';
      if (f.backgroundSize) span.style.backgroundSize = f.backgroundSize;
      if (f.overlay) {
        var o = document.createElement('i');
        o.style.position = 'absolute';
        var ins = f.overlay.inset.split(' ');
        o.style.top = ins[0]; o.style.right = ins[1];
        o.style.bottom = ins[2]; o.style.left = ins[3];
        o.style.background = f.overlay.background;
        span.appendChild(o);
      }
    } else {
      span.style.backgroundImage = 'url("' + UNKNOWN_FLAG + '")';
    }
    return span;
  }

  /* ================= state ================= */

  var REFRESH_MS = 60000;
  var TOP_N = 8;
  var TICKER_MAX = 60;

  var state = {
    preset: 'all',
    customStart: null,
    customEnd: null,
    firstDate: null,
    live: null,
    archive: null,
    view: null,       // { mode:'live'|'archive', stats, countries, ips, usernames, passwords, commands, recent, points, timeline }
    tickerSeen: [],
    lastFetchOk: null,
    lastFetchAt: null
  };

  /* ================= fetch ================= */

  function fetchJSON(url) {
    return fetch(url, { cache: 'no-store' }).then(function (r) {
      if (!r.ok) throw new Error(url + ' -> HTTP ' + r.status);
      return r.json();
    });
  }

  function loadData() {
    return Promise.all([
      fetchJSON('meta.json'),
      fetchJSON('live.json'),
      fetchJSON('archive.json')
    ]).then(function (res) {
      var meta = res[0] || {};
      state.firstDate = meta.first_data_date || (res[2] && res[2].first_data_date) || null;
      state.live = res[1] || null;
      state.archive = res[2] || null;
      state.lastFetchOk = true;
      state.lastFetchAt = new Date();
      setLiveDot(true);
      setUpdated(state.lastFetchAt, false);
      clampCustomInputs();
    }).catch(function (err) {
      state.lastFetchOk = false;
      setLiveDot(false);
      showError('Feed unreachable — ' + (err && err.message ? err.message : 'network error') + '. Retrying every 60s.');
      setUpdated(state.lastFetchAt, true);
    });
  }

  function setLiveDot(ok) {
    var d = $('liveDot');
    if (d) d.classList.toggle('err', !ok);
  }

  function setUpdated(when, stale) {
    var el = $('updated');
    if (!el) return;
    if (!when) { el.textContent = '—'; return; }
    el.textContent = when.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    el.classList.toggle('stale', !!stale);
  }

  function showError(msg) {
    var b = $('errBanner');
    if (!b) return;
    b.textContent = msg;
    b.classList.add('show');
  }

  function hideError() {
    var b = $('errBanner');
    if (b) b.classList.remove('show');
  }

  /* ================= data shaping ================= */

  function liveView(live) {
    var t = live && live.totals ? live.totals : {};
    return {
      mode: 'live',
      stats: {
        connections: t.connections || 0,
        auth: t.auth_attempts || 0,
        ips: t.unique_ips || 0,
        commands: t.commands || 0
      },
      countries: (live.top_countries || []).map(function (c) {
        return { label: c.country || countryName(c.code), code: c.code || '', count: c.count || 0 };
      }),
      ips: (live.top_ips || []).map(function (x) {
        return { label: x.ip, code: x.country || '', count: x.count || 0 };
      }),
      usernames: (live.top_usernames || []).map(function (x) {
        return { label: x.username, count: x.count || 0 };
      }),
      passwords: (live.top_passwords || []).map(function (x) {
        return { label: x.password, count: x.count || 0 };
      }),
      commands: (live.top_commands || []).map(function (x) {
        return { label: (x.command != null ? x.command : x.input), count: x.count || 0 };
      }),
      recent: live.recent_attacks || [],
      points: live.geo_points || [],
      timeline: (live.timeline || []).map(function (b) {
        return { t: String(b.t || ''), connections: b.connections || 0, auth: b.auth || 0 };
      })
    };
  }

  function sumMapInto(acc, obj) {
    if (!obj) return;
    for (var k in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, k)) {
        acc[k] = (acc[k] || 0) + (Number(obj[k]) || 0);
      }
    }
  }

  function mapToSortedRows(map, labelFn) {
    var rows = [];
    for (var k in map) {
      if (Object.prototype.hasOwnProperty.call(map, k)) {
        rows.push({ label: labelFn ? labelFn(k) : k, code: k, count: map[k] });
      }
    }
    rows.sort(function (a, b) { return b.count - a.count; });
    return rows.slice(0, TOP_N);
  }

  function archiveView(days) {
    var stats = { connections: 0, auth: 0, ips: 0, commands: 0 };
    var countries = {}, usernames = {}, commands = {};
    var geo = {}; // rounded lat,lon -> {lat,lon,count}
    var timeline = [];

    (days || []).forEach(function (d) {
      stats.connections += d.connections || 0;
      stats.auth += d.auth || 0;
      stats.ips += d.unique_ips || 0; // summed per day; may overcount — acceptable
      stats.commands += d.commands || 0;
      sumMapInto(countries, d.countries);
      sumMapInto(usernames, d.usernames);
      sumMapInto(commands, d.top_commands);
      (d.geo || []).forEach(function (g) {
        var lat = Math.round(Number(g.lat) * 10) / 10;
        var lon = Math.round(Number(g.lon) * 10) / 10;
        if (!isFinite(lat) || !isFinite(lon)) return;
        var key = lat + ',' + lon;
        if (!geo[key]) geo[key] = { lat: lat, lon: lon, count: 0 };
        geo[key].count += g.count || 0;
      });
      timeline.push({ t: d.date, connections: d.connections || 0, auth: d.auth || 0 });
    });

    var points = [];
    for (var gk in geo) {
      if (Object.prototype.hasOwnProperty.call(geo, gk)) points.push(geo[gk]);
    }

    return {
      mode: 'archive',
      stats: stats,
      countries: mapToSortedRows(countries, countryName),
      usernames: mapToSortedRows(usernames),
      commands: mapToSortedRows(commands),
      ips: null,        // 24h only
      passwords: null,  // 24h only
      recent: null,     // 24h only
      points: points,
      timeline: timeline
    };
  }

  function computeView() {
    if (state.preset === '24h') {
      return state.live ? liveView(state.live) : liveView({});
    }
    var days = state.archive && state.archive.days ? state.archive.days : [];
    var end = todayStr();
    var start = null;
    if (state.preset === '7d') start = addDaysStr(end, -6);
    else if (state.preset === '30d') start = addDaysStr(end, -29);
    else if (state.preset === 'custom') {
      start = state.customStart;
      end = state.customEnd || end;
    }
    var sel = days.filter(function (d) {
      if (!d || !d.date) return false;
      if (start && d.date < start) return false;
      if (end && d.date > end) return false;
      return true;
    });
    return archiveView(sel);
  }

  /* ================= stats (flicker + count-up) ================= */

  function animateValue(el, target) {
    if (!el) return;
    target = Math.max(0, Math.floor(Number(target) || 0));
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      el.textContent = fmt(target);
      return;
    }
    // per-element handle so concurrent stat animations don't cancel each other
    if (el._raf) cancelAnimationFrame(el._raf);
    var start = performance.now();
    var FLICKER = 260, COUNT = 640;
    function frame(now) {
      var t = now - start;
      if (t < FLICKER) {
        var digits = Math.max(1, String(target).length);
        var s = '';
        for (var i = 0; i < digits; i++) s += String((Math.random() * 10) | 0);
        el.textContent = s;
      } else if (t < FLICKER + COUNT) {
        var p = (t - FLICKER) / COUNT;
        p = 1 - Math.pow(1 - p, 3); // ease-out cubic
        el.textContent = fmt(Math.round(target * p));
      } else {
        el.textContent = fmt(target);
        el._raf = null;
        return;
      }
      el._raf = requestAnimationFrame(frame);
    }
    el._raf = requestAnimationFrame(frame);
  }

  function renderStats(stats) {
    animateValue($('statConnections'), stats.connections);
    animateValue($('statAuth'), stats.auth);
    animateValue($('statIps'), stats.ips);
    animateValue($('statCommands'), stats.commands);
  }

  /* ================= leader lists ================= */

  function renderLeader(el, rows, opts) {
    opts = opts || {};
    if (!el) return;
    el.textContent = '';
    if (!rows) {
      var hint = document.createElement('div');
      hint.className = 'hint';
      hint.textContent = 'available in the Last 24h view';
      el.appendChild(hint);
      return;
    }
    if (!rows.length) {
      var empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'awaiting first intercept';
      el.appendChild(empty);
      return;
    }
    var max = rows[0].count || 1;
    rows.slice(0, TOP_N).forEach(function (r, i) {
      var row = document.createElement('div');
      row.className = 'lrow' + (i === 0 ? ' lead' : '');

      var rank = document.createElement('span');
      rank.className = 'lrank';
      rank.textContent = pad2(i + 1);
      row.appendChild(rank);

      if (opts.flags) {
        row.appendChild(makeFlag(r.code));
      } else {
        var spacer = document.createElement('span');
        spacer.setAttribute('aria-hidden', 'true');
        row.appendChild(spacer);
      }

      var label = document.createElement('span');
      label.className = 'llabel';
      label.textContent = r.label == null || r.label === '' ? '(blank)' : String(r.label);
      label.title = label.textContent;
      row.appendChild(label);

      var track = document.createElement('span');
      track.className = 'ltrack';
      var fill = document.createElement('span');
      fill.className = 'lfill';
      track.appendChild(fill);
      row.appendChild(track);

      var count = document.createElement('span');
      count.className = 'lcount';
      count.textContent = fmt(r.count);
      row.appendChild(count);

      el.appendChild(row);

      // animate after insert
      var pct = Math.max(1, Math.round((r.count / max) * 100));
      requestAnimationFrame(function () {
        requestAnimationFrame(function () { fill.style.width = pct + '%'; });
      });
    });
  }

  /* ================= timeline (hand-rolled SVG) ================= */

  var SVG_NS = 'http://www.w3.org/2000/svg';

  function renderTimeline(view) {
    var svg = $('tlChart');
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    var modeEl = $('activityMode');
    if (modeEl) modeEl.textContent = view.mode === 'live' ? 'hourly · connections + auth' : 'daily · connections + auth';

    var rows = view.timeline || [];
    var W = 960, H = 200, padL = 42, padR = 8, padT = 14, padB = 26;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);

    function textEl(x, y, str, anchor) {
      var t = document.createElementNS(SVG_NS, 'text');
      t.setAttribute('x', x); t.setAttribute('y', y);
      t.setAttribute('fill', '#6b7280');
      t.setAttribute('font-size', '9');
      t.setAttribute('font-family', 'Plex Mono, ui-monospace, monospace');
      t.setAttribute('letter-spacing', '1');
      if (anchor) t.setAttribute('text-anchor', anchor);
      t.textContent = str;
      return t;
    }

    var startEl = $('activityStart'), endEl = $('activityEnd');
    if (!rows.length) {
      var base = document.createElementNS(SVG_NS, 'line');
      base.setAttribute('x1', padL); base.setAttribute('x2', W - padR);
      base.setAttribute('y1', H - padB); base.setAttribute('y2', H - padB);
      base.setAttribute('stroke', '#1e2328'); base.setAttribute('stroke-width', '1');
      svg.appendChild(base);
      svg.appendChild(textEl((W + padL) / 2, H / 2, 'AWAITING FIRST INTERCEPT', 'middle'));
      if (startEl) startEl.textContent = '';
      if (endEl) endEl.textContent = '';
      return;
    }

    var maxV = 1;
    rows.forEach(function (r) {
      maxV = Math.max(maxV, r.connections, r.auth);
    });

    var innerW = W - padL - padR;
    var innerH = H - padT - padB;
    var baseY = H - padB;
    var n = rows.length;
    var band = innerW / n;
    var tickW = Math.max(1.5, Math.min(4, band * 0.38));

    // y gridlines + labels
    var gridVals = [0, Math.round(maxV / 2), maxV];
    gridVals.forEach(function (v) {
      var y = baseY - (v / maxV) * innerH;
      var ln = document.createElementNS(SVG_NS, 'line');
      ln.setAttribute('x1', padL); ln.setAttribute('x2', W - padR);
      ln.setAttribute('y1', y); ln.setAttribute('y2', y);
      ln.setAttribute('stroke', v === 0 ? '#1e2328' : '#161a1e');
      ln.setAttribute('stroke-width', '1');
      svg.appendChild(ln);
      svg.appendChild(textEl(padL - 6, y + 3, fmt(v), 'end'));
    });

    // tick marks: auth (dim, left half) + connections (orange, right half)
    rows.forEach(function (r, i) {
      var cx = padL + band * i + band / 2;
      var hC = (r.connections / maxV) * innerH;
      var hA = (r.auth / maxV) * innerH;
      var half = tickW / 2;
      if (r.auth > 0) {
        var ra = document.createElementNS(SVG_NS, 'rect');
        ra.setAttribute('x', cx - half); ra.setAttribute('width', half);
        ra.setAttribute('y', baseY - hA); ra.setAttribute('height', Math.max(1, hA));
        ra.setAttribute('fill', '#6b7280');
        svg.appendChild(ra);
      }
      if (r.connections > 0) {
        var rc = document.createElementNS(SVG_NS, 'rect');
        rc.setAttribute('x', cx); rc.setAttribute('width', half);
        rc.setAttribute('y', baseY - hC); rc.setAttribute('height', Math.max(1, hC));
        rc.setAttribute('fill', '#ff7a18');
        svg.appendChild(rc);
      }
      if (r.connections === 0 && r.auth === 0) {
        var dot = document.createElementNS(SVG_NS, 'rect');
        dot.setAttribute('x', cx - 0.5); dot.setAttribute('width', 1);
        dot.setAttribute('y', baseY - 1); dot.setAttribute('height', 1);
        dot.setAttribute('fill', '#6b7280');
        svg.appendChild(dot);
      }
    });

    // x labels: sparse
    function xLabel(t) {
      if (view.mode === 'live') return t.slice(11, 16); // HH:MM from "YYYY-MM-DD HH:00:00.000"
      return t.slice(5); // MM-DD
    }
    var labelEvery = Math.max(1, Math.ceil(n / 8));
    rows.forEach(function (r, i) {
      if (i % labelEvery !== 0 && i !== n - 1) return;
      var cx = padL + band * i + band / 2;
      var anchor = i === n - 1 ? 'end' : (i === 0 ? 'start' : 'middle');
      svg.appendChild(textEl(cx, H - 10, xLabel(r.t), anchor));
    });

    if (startEl) startEl.textContent = rows[0].t.slice(0, 10);
    if (endEl) endEl.textContent = rows[n - 1].t.slice(0, 10) + (view.mode === 'live' ? ' · UTC' : '');
  }

  /* ================= console ticker ================= */

  function eventKey(a) {
    return (a.time || '') + '|' + (a.ip || '') + '|' + (a.event || '') + '|' + (a.detail || '');
  }

  function buildConsoleLine(a) {
    var line = document.createElement('div');
    line.className = 'c-line';

    var t = document.createElement('span');
    t.className = 't';
    var ts = String(a.time || '');
    t.textContent = '[' + (ts.length > 19 ? ts.slice(0, 19) : ts) + ']';
    line.appendChild(t);

    function kv(k, v, cls) {
      var ks = document.createElement('span');
      ks.className = 'k';
      ks.textContent = ' ' + k + '=';
      line.appendChild(ks);
      var vs = document.createElement('span');
      vs.className = cls || 'v';
      vs.textContent = String(v == null ? '' : v);
      line.appendChild(vs);
    }

    kv('src', a.ip || '?');
    kv('cc', a.country || '--');

    var isCmd = a.event === 'command' || a.event === 'command.input';
    kv('event', a.event || '?', 'ev' + (isCmd ? ' cmd' : ''));

    var detail = a.detail == null ? '' : String(a.detail);
    if (isCmd) {
      kv('cmd', '"' + detail + '"');
    } else if (detail.indexOf('/') !== -1) {
      var parts = detail.split('/');
      kv('u', parts[0]);
      if (parts.length > 1) kv('p', parts.slice(1).join('/'));
    } else if (detail) {
      kv('d', detail);
    }
    return line;
  }

  function renderTicker(recent) {
    var box = $('console');
    var note = $('tickerNote');
    if (!box) return;
    box.textContent = '';

    if (!recent) {
      if (note) note.textContent = 'available in the Last 24h view';
      var hint = document.createElement('div');
      hint.className = 'empty';
      hint.textContent = 'available in the Last 24h view';
      box.appendChild(hint);
      appendCursor(box);
      return;
    }

    if (note) note.textContent = 'raw event stream';

    // newest first, dedupe by key
    var items = recent.slice(0, TICKER_MAX);
    var keys = items.map(eventKey);

    if (!items.length) {
      var empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'awaiting first intercept';
      box.appendChild(empty);
      appendCursor(box);
      state.tickerSeen = [];
      return;
    }

    // reveal line-by-line only for rows that are new since last paint
    var stagger = 0;
    items.forEach(function (a, i) {
      var line = buildConsoleLine(a);
      var isNew = state.tickerSeen.indexOf(keys[i]) === -1;
      if (isNew && stagger < 14) {
        line.style.animationDelay = (stagger * 90) + 'ms';
        stagger++;
      } else {
        line.style.animation = 'none';
        line.style.opacity = '1';
      }
      box.appendChild(line);
    });
    state.tickerSeen = keys;
    appendCursor(box);
  }

  function appendCursor(box) {
    var c = document.createElement('div');
    c.className = 'c-cursor';
    var prompt = document.createElement('span');
    prompt.textContent = 'root@hp04:~#';
    c.appendChild(prompt);
    var block = document.createElement('span');
    block.className = 'block';
    block.setAttribute('aria-hidden', 'true');
    c.appendChild(block);
    box.appendChild(c);
    box.scrollTop = 0; // newest at top
  }

  /* ================= globe ================= */

  var world = null;
  var globeOK = false;
  var coordEl = null;

  function makeSolidTexture() {
    var cv = document.createElement('canvas');
    cv.width = 8; cv.height = 4;
    var ctx = cv.getContext('2d');
    ctx.fillStyle = '#111417';
    ctx.fillRect(0, 0, 8, 4);
    return cv.toDataURL('image/png');
  }

  function initGlobe() {
    var el = $('globe');
    coordEl = $('coordReadout');
    if (!el) return;
    if (typeof Globe === 'undefined') {
      globeFallback(el);
      return;
    }
    try {
      world = Globe()(el)
        .backgroundColor('#0b0d0f')
        .showAtmosphere(true)
        .atmosphereColor('#ff7a18')
        .atmosphereAltitude(0.12)
        .pointLat('lat')
        .pointLng('lon')
        .pointColor(function () { return '#ff7a18'; })
        .pointAltitude(function (d) { return Math.min(0.55, 0.05 + Math.sqrt(d.count || 1) * 0.025); })
        .pointRadius(function (d) { return 0.42 + Math.min(1.0, Math.sqrt(d.count || 1) * 0.11); })
        .pointLabel(function (d) {
          return '<div class="globe-tip"><span class="gt-label">' +
            escapeHTML(d.country || countryName(d.code || '') || 'ORIGIN') + '</span>' +
            escapeHTML(fmt(d.count)) + ' hits</div>';
        });

      // lat/lon graticule grid for definition (dim hairlines, solid color)
      try { world.showGraticules(true).graticuleColor('rgba(64,72,80,0.55)'); } catch (eg) { /* noop */ }

      // force a solid sphere (no earth texture), a touch lighter than the bg
      try {
        var mat = world.globeMaterial && world.globeMaterial();
        if (mat) {
          if (mat.color && mat.color.set) mat.color.set('#1a1f24');
          if ('map' in mat) mat.map = null;
          if (mat.shininess !== undefined) mat.shininess = 4;
          mat.needsUpdate = true;
        }
      } catch (e1) {
        try { world.globeImageUrl(makeSolidTexture()); } catch (e2) { /* solid enough */ }
      }

      try {
        var ctrl = world.controls();
        ctrl.autoRotate = true;
        ctrl.autoRotateSpeed = 0.55;
        if ('enableZoom' in ctrl) ctrl.enableZoom = false;
      } catch (e3) { /* controls unavailable */ }

      var wrap = $('globeWrap');
      var resize = function () {
        if (!wrap || !world) return;
        var r = wrap.getBoundingClientRect();
        var w = Math.max(220, Math.floor(r.width));
        var h = Math.max(220, Math.floor(r.height));
        try { world.width(w).height(h); } catch (e4) { /* noop */ }
      };
      if (window.ResizeObserver && wrap) {
        var ro = new ResizeObserver(resize);
        ro.observe(wrap);
      }
      window.addEventListener('resize', resize);
      resize();

      // coordinate readout under cursor
      if (wrap && coordEl) {
        wrap.addEventListener('pointermove', function (ev) {
          var txt = null;
          try {
            if (world && typeof world.toGeoCoords === 'function') {
              var rect = el.getBoundingClientRect();
              var pt = world.toGeoCoords(ev.clientX - rect.left, ev.clientY - rect.top);
              if (pt && isFinite(pt.lat) && isFinite(pt.lng)) {
                txt = 'LAT ' + (pt.lat >= 0 ? '+' : '') + pt.lat.toFixed(2) +
                      ' / LON ' + (pt.lng >= 0 ? '+' : '') + pt.lng.toFixed(2);
              }
            }
          } catch (e5) { txt = null; }
          coordEl.textContent = txt || 'SOL 33.95N 118.39W — USW2';
          coordEl.classList.toggle('on', !!txt);
        });
        wrap.addEventListener('pointerleave', function () {
          coordEl.textContent = 'HOVER SPHERE FOR COORDINATES';
          coordEl.classList.remove('on');
        });
      }

      globeOK = true;
    } catch (e6) {
      globeFallback(el);
    }
  }

  function globeFallback(el) {
    globeOK = false;
    el.textContent = '';
    var d = document.createElement('div');
    d.className = 'globe-fallback';
    d.textContent = 'globe offline';
    el.appendChild(d);
  }

  function updateGlobe(points) {
    if (!globeOK || !world) return;
    try {
      world.pointsData(points || []);
      if (points && points.length) {
        world.pointOfView({ lat: 22, lng: 12, altitude: 2.15 }, 900);
      }
    } catch (e) { /* keep last frame */ }
  }

  /* ================= render orchestration ================= */

  function renderAll() {
    var view = computeView();
    state.view = view;

    renderStats(view.stats);
    renderLeader($('chartCountries'), view.countries, { flags: true });
    renderLeader($('chartUsernames'), view.usernames);
    renderLeader($('chartCommands'), view.commands);
    renderLeader($('chartIps'), view.ips, { flags: true });
    renderLeader($('chartPasswords'), view.passwords);
    renderTimeline(view);
    renderTicker(view.recent);
    updateGlobe(view.points);
  }

  /* ================= range controls ================= */

  function setPreset(p) {
    state.preset = p;
    var btns = document.querySelectorAll('.r-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].getAttribute('data-preset') === p);
    }
    var bar = $('customBar');
    if (bar) bar.classList.toggle('open', p === 'custom');
    if (p === 'custom') {
      // only render once both dates are valid
      var s = $('customStart'), e = $('customEnd');
      if (s && e && s.value && e.value && s.value <= e.value) {
        state.customStart = s.value;
        state.customEnd = e.value;
        renderAll();
      }
    } else {
      renderAll();
    }
  }

  function clampCustomInputs() {
    var s = $('customStart'), e = $('customEnd');
    if (!s || !e) return;
    var min = state.firstDate || '2020-01-01';
    var max = todayStr();
    s.min = min; s.max = max;
    e.min = min; e.max = max;
    if (!s.value) s.value = min;
    if (!e.value) e.value = max;
    if (s.value < min) s.value = min;
    if (s.value > max) s.value = max;
    if (e.value < min) e.value = min;
    if (e.value > max) e.value = max;
  }

  function wireControls() {
    var btns = document.querySelectorAll('.r-btn');
    for (var i = 0; i < btns.length; i++) {
      (function (b) {
        b.addEventListener('click', function () {
          setPreset(b.getAttribute('data-preset'));
        });
      })(btns[i]);
    }
    var apply = $('customApply');
    if (apply) {
      apply.addEventListener('click', function () {
        var s = $('customStart'), e = $('customEnd');
        if (!s || !e) return;
        var ok = s.value && e.value && s.value <= e.value;
        s.classList.toggle('invalid', !s.value || (!!e.value && s.value > e.value));
        e.classList.toggle('invalid', !e.value || (!!s.value && s.value > e.value));
        if (!ok) return;
        state.customStart = s.value;
        state.customEnd = e.value;
        state.preset = 'custom';
        renderAll();
      });
    }
  }

  /* ================= reveal on scroll ================= */

  function wireReveal() {
    var els = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window)) {
      for (var i = 0; i < els.length; i++) els[i].classList.add('in-view');
      return;
    }
    for (var j = 0; j < els.length; j++) {
      els[j].style.setProperty('--d', (Math.min(j, 8) * 70) + 'ms');
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.classList.add('in-view');
          io.unobserve(en.target);
        }
      });
    }, { threshold: 0.12 });
    for (var k = 0; k < els.length; k++) io.observe(els[k]);
  }

  /* ================= boot ================= */

  function boot() {
    wireControls();
    wireReveal();
    initGlobe();
    clampCustomInputs();
    loadData().then(function () {
      hideError();
      renderAll();
    });
    setInterval(function () {
      loadData().then(function () {
        if (state.lastFetchOk) {
          hideError();
          renderAll();
        }
      });
    }, REFRESH_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

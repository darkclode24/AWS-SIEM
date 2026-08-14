/* SIGNAL / INTERCEPT — honeypot console
   Plain vanilla JS. No framework, no chart library.
   Network: relative fetch of meta.json, live.json, archive.json, countries-110m.json only. */
(function () {
  'use strict';

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
  function localDateStr(d) { return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
  function todayStr() { return localDateStr(new Date()); }
  function addDaysStr(dateStr, days) {
    var d = new Date(dateStr + 'T00:00:00');
    d.setDate(d.getDate() + days);
    return localDateStr(d);
  }

  /* ================= country flags (tiny inline SVGs) ================= */

  function flagURI(rows, horiz) {
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">';
    if (horiz) {
      svg += '<rect width="14" height="3.34" fill="' + rows[0] + '"/>' +
        '<rect y="3.33" width="14" height="3.34" fill="' + rows[1] + '"/>' +
        '<rect y="6.66" width="14" height="3.34" fill="' + rows[2] + '"/></svg>';
    } else {
      svg += '<rect width="4.67" height="10" fill="' + rows[0] + '"/>' +
        '<rect x="4.66" width="4.67" height="10" fill="' + rows[1] + '"/>' +
        '<rect x="9.33" width="4.67" height="10" fill="' + rows[2] + '"/></svg>';
    }
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
  }
  function flagPlain(color) {
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10"><rect width="14" height="10" fill="' + color + '"/></svg>');
  }
  function flagSvg(svg) {
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10">' + svg + '</svg>');
  }
  function usFlag() {
    var s = '<rect width="14" height="10" fill="#ffffff"/>', y;
    for (var i = 0; i < 7; i++) { y = (i * 20 / 13).toFixed(2); s += '<rect y="' + y + '" width="14" height="0.77" fill="#b22234"/>'; }
    s += '<rect width="5.6" height="5.38" fill="#3c3b6e"/>';
    for (var r = 0; r < 4; r++) for (var c = 0; c < 5; c++) {
      s += '<circle cx="' + (0.56 + c * 1.12).toFixed(2) + '" cy="' + (0.67 + r * 1.34).toFixed(2) + '" r="0.22" fill="#ffffff"/>';
    }
    return flagSvg(s);
  }
  function trig(x, y) {
    return '<rect x="' + x + '" y="' + y + '" width="2.6" height="0.5" fill="#000"/>' +
      '<rect x="' + x + '" y="' + (y + 0.9) + '" width="2.6" height="0.5" fill="#000"/>' +
      '<rect x="' + x + '" y="' + (y + 1.8) + '" width="2.6" height="0.5" fill="#000"/>';
  }
  function krFlag() {
    return flagSvg('<rect width="14" height="10" fill="#ffffff"/>' +
      '<path d="M4.6,5 A2.4,2.4 0 0 1 9.4,5 Z" fill="#cd2e3a"/>' +
      '<path d="M4.6,5 A2.4,2.4 0 0 0 9.4,5 Z" fill="#0047a0"/>' +
      trig(0.8, 0.9) + trig(10.6, 0.9) + trig(0.8, 6.0) + trig(10.6, 6.0));
  }
  function twFlag() {
    return flagSvg('<rect width="14" height="10" fill="#fe0000"/>' +
      '<rect width="7" height="5" fill="#000095"/>' +
      '<circle cx="3.5" cy="2.5" r="1.5" fill="#ffffff"/>' +
      '<path d="M3.5,0.8 L3.5,4.2 M1.8,2.5 L5.2,2.5" stroke="#000095" stroke-width="0.55"/>');
  }
  function hkFlag() {
    return flagSvg('<rect width="14" height="10" fill="#de2910"/>' +
      '<circle cx="7" cy="5" r="2.3" fill="#ffffff"/>');
  }
  function arFlag() {
    return flagSvg('<rect width="14" height="10" fill="#ffffff"/>' +
      '<rect width="14" height="3.33" fill="#74acdf"/>' +
      '<rect y="6.67" width="14" height="3.33" fill="#74acdf"/>' +
      '<circle cx="7" cy="5" r="1.1" fill="#f6b40e"/>');
  }

  var FLAGS = {
    CN: flagPlain('#de2910'), HK: hkFlag(), TW: twFlag(),
    JP: flagPlain('#bc002d'), KR: krFlag(),
    US: usFlag(), AR: arFlag(),
    RU: flagURI(['#ffffff', '#0039a6', '#d52b1e'], true),
    DE: flagURI(['#000000', '#dd0000', '#ffce00'], true),
    NL: flagURI(['#ae1c28', '#ffffff', '#21468b'], true),
    FR: flagURI(['#0055a4', '#ffffff', '#ef4135'], false),
    IT: flagURI(['#009246', '#ffffff', '#ce2b37'], false),
    IE: flagURI(['#169b62', '#ffffff', '#ff883e'], false),
    BE: flagURI(['#000000', '#fdda24', '#ef3340'], false),
    UA: flagURI(['#0057b7', '#ffd700', '#ffd700'], true),
    IN: flagURI(['#ff9933', '#ffffff', '#138808'], true),
    BG: flagURI(['#ffffff', '#00966e', '#d62612'], true),
    GB: flagPlain('#012169'), BR: flagPlain('#009c3b'), VN: flagPlain('#da251d'),
    SG: flagURI(['#ef3340', '#ffffff', '#ffffff'], true),
    ID: flagURI(['#e70011', '#ffffff', '#ffffff'], true),
    PL: flagURI(['#ffffff', '#dc143c', '#dc143c'], true)
  };
  var UNKNOWN_FLAG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 10"><rect width="14" height="10" fill="#1e2328"/><rect x="6.5" y="4.5" width="1" height="1" fill="#6b7280"/></svg>');
  var CC_NAMES = {
    CN: 'China', HK: 'Hong Kong', TW: 'Taiwan', JP: 'Japan', KR: 'South Korea',
    RU: 'Russia', DE: 'Germany', NL: 'Netherlands', FR: 'France', IT: 'Italy',
    IE: 'Ireland', BE: 'Belgium', UA: 'Ukraine', IN: 'India', BG: 'Bulgaria',
    GB: 'United Kingdom', BR: 'Brazil', VN: 'Vietnam', SG: 'Singapore', PL: 'Poland',
    US: 'United States', AR: 'Argentina', ID: 'Indonesia'
  };
  function countryName(code) { return CC_NAMES[code] || code || '??'; }

  function makeFlag(code) {
    var i = document.createElement('i');
    i.className = 'lflag';
    i.setAttribute('aria-hidden', 'true');
    var url = FLAGS[code] || UNKNOWN_FLAG;
    i.style.backgroundImage = 'url("' + url + '")';
    return i;
  }

  /* ================= state ================= */

  var REFRESH_MS = 60000;
  var TOP_N = 8;
  var TICKER_MAX = 60;

  var state = {
    preset: 'all', customStart: null, customEnd: null, firstDate: null,
    live: null, archive: null, view: null, tickerSeen: [], lastFetchOk: null,
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
    return Promise.all([fetchJSON('meta.json'), fetchJSON('live.json'), fetchJSON('archive.json')])
      .then(function (res) {
        state.firstDate = res[0].first_data_date || (res[2] && res[2].first_data_date) || null;
        state.live = res[1] || null;
        state.archive = res[2] || null;
        state.lastFetchOk = true; state.lastFetchAt = new Date();
        setLiveDot(true); setUpdated(state.lastFetchAt, false); clampCustomInputs();
      })
      .catch(function (err) {
        state.lastFetchOk = false; setLiveDot(false);
        showError((err && err.message ? err.message : 'network error') + '. Retrying every 60s.');
        setUpdated(state.lastFetchAt, true);
      });
  }

  function setLiveDot(ok) {
    var d = $('liveDot'); if (d) d.classList.toggle('err', !ok);
  }
  function setUpdated(when, stale) {
    var el = $('updated'); if (!el) return;
    if (!when) { el.textContent = '—'; return; }
    el.textContent = when.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    el.classList.toggle('stale', !!stale);
  }
  function showError(msg) { var b = $('errBanner'); if (!b) return; b.textContent = msg; b.classList.add('show'); }
  function hideError() { var b = $('errBanner'); if (b) b.classList.remove('show'); }

  /* ================= data shaping ================= */

  function liveView(live) {
    var t = live.totals || {};
    return {
      mode: 'live',
      stats: { connections: t.connections || 0, auth: t.auth_attempts || 0, ips: t.unique_ips || 0, commands: t.commands || 0 },
      countries: (live.top_countries || []).map(function (c) {
        return { label: c.country || countryName(c.code), code: c.code || '', count: c.count || 0 };
      }),
      ips: (live.top_ips || []).map(function (x) {
        return { label: x.ip, code: x.country || '', count: x.count || 0 };
      }),
      usernames: (live.top_usernames || []).map(function (x) { return { label: x.username, count: x.count || 0 }; }),
      commands: (live.top_commands || []).map(function (x) { return { label: x.command != null ? x.command : x.input, count: x.count || 0 }; }),
      downloads: (live.top_downloads || []).map(function (x) { return { label: x.url, count: x.count || 0 }; }),
      uploads: (live.top_uploads || []).map(function (x) { return { label: x.outfile, count: x.count || 0 }; }),
      recent: live.recent_attacks || [],
      points: live.geo_points || [],
      timeline: (live.timeline || []).map(function (b) { return { t: String(b.t || ''), connections: b.connections || 0, auth: b.auth || 0 }; })
    };
  }

  function sumMapInto(acc, obj) {
    if (!obj) return;
    for (var k in obj) if (Object.prototype.hasOwnProperty.call(obj, k)) acc[k] = (acc[k] || 0) + (Number(obj[k]) || 0);
  }
  function mapToSortedRows(map) {
    var rows = [];
    for (var k in map) if (Object.prototype.hasOwnProperty.call(map, k)) rows.push({ label: k, code: k, count: map[k] });
    rows.sort(function (a, b) { return b.count - a.count; });
    return rows.slice(0, TOP_N);
  }
  function mapToIpRows(map) {
    var rows = [];
    for (var k in map) if (Object.prototype.hasOwnProperty.call(map, k)) rows.push({ label: k, code: map[k].country || '', count: map[k].count });
    rows.sort(function (a, b) { return b.count - a.count; });
    return rows.slice(0, TOP_N);
  }

  function archiveView(days) {
    var stats = { connections: 0, auth: 0, ips: 0, commands: 0 };
    var countries = {}, usernames = {}, commands = {}, downloads = {}, uploads = {}, geo = {}, ips = {};
    var timeline = [];
    (days || []).forEach(function (d) {
      stats.connections += d.connections || 0;
      stats.auth += d.auth || 0;
      stats.ips += d.unique_ips || 0;
      stats.commands += d.commands || 0;
      sumMapInto(countries, d.countries);
      sumMapInto(usernames, d.usernames);
      sumMapInto(commands, d.top_commands);
      sumMapInto(downloads, d.downloads_top);
      sumMapInto(uploads, d.uploads_top);
      if (d.ips) for (var ip in d.ips) if (Object.prototype.hasOwnProperty.call(d.ips, ip)) {
        var i = d.ips[ip];
        if (!ips[ip]) ips[ip] = { count: 0, country: (i.country || '') };
        ips[ip].count += Number(i.count) || 0;
      }
      (d.geo || []).forEach(function (g) {
        var lat = Math.round(Number(g.lat) * 10) / 10;
        var lon = Math.round(Number(g.lon) * 10) / 10;
        if (!isFinite(lat) || !isFinite(lon)) return;
        var key = lat + ',' + lon;
        if (!geo[key]) geo[key] = { lat: lat, lon: lon, count: 0, country: g.country || '' };
        geo[key].count += g.count || 0;
      });
      timeline.push({ t: d.date, connections: d.connections || 0, auth: d.auth || 0 });
    });
    var points = [];
    for (var gk in geo) if (Object.prototype.hasOwnProperty.call(geo, gk)) points.push(geo[gk]);
    return {
      mode: 'archive', stats: stats,
      countries: mapToSortedRows(countries),
      usernames: mapToSortedRows(usernames),
      commands: mapToSortedRows(commands),
      downloads: mapToSortedRows(downloads),
      uploads: mapToSortedRows(uploads),
      ips: mapToIpRows(ips), recent: null, points: points, timeline: timeline
    };
  }

  function computeView() {
    if (state.preset === '24h') return state.live ? liveView(state.live) : liveView({});
    var days = state.archive && state.archive.days ? state.archive.days : [];
    var end = todayStr(), start = null;
    if (state.preset === '7d') start = addDaysStr(end, -6);
    else if (state.preset === '30d') start = addDaysStr(end, -29);
    else if (state.preset === 'custom') { start = state.customStart; end = state.customEnd || end; }
    var sel = days.filter(function (d) {
      if (!d || !d.date) return false;
      if (start && d.date < start) return false;
      if (end && d.date > end) return false;
      return true;
    });
    return archiveView(sel);
  }

  /* ================= stats (count-up) ================= */

  function animateValue(el, target) {
    if (!el) return;
    target = Math.max(0, Math.floor(Number(target) || 0));
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) { el.textContent = fmt(target); return; }
    if (el._raf) cancelAnimationFrame(el._raf);
    var start = performance.now(), FLICKER = 260, COUNT = 640;
    function frame(now) {
      var t = now - start;
      if (t < FLICKER) {
        var digits = Math.max(1, String(target).length), s = '';
        for (var i = 0; i < digits; i++) s += String((Math.random() * 10) | 0);
        el.textContent = s;
      } else if (t < FLICKER + COUNT) {
        var p = (t - FLICKER) / COUNT; p = 1 - Math.pow(1 - p, 3);
        el.textContent = fmt(Math.round(target * p));
      } else { el.textContent = fmt(target); el._raf = null; return; }
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

  function renderLeader(el, rows, flags) {
    if (!el) return;
    el.textContent = '';
    if (!rows) {
      var h = document.createElement('div'); h.className = 'hint';
      h.textContent = 'available in the 24h view'; el.appendChild(h); return;
    }
    if (!rows.length) {
      var e = document.createElement('div'); e.className = 'empty';
      e.textContent = 'awaiting first intercept'; el.appendChild(e); return;
    }
    var max = rows[0].count || 1;
    rows.slice(0, TOP_N).forEach(function (r, i) {
      var row = document.createElement('div');
      row.className = 'lrow' + (i === 0 ? ' lead' : '');
      var rank = document.createElement('span'); rank.className = 'lrank';
      rank.textContent = pad2(i + 1); row.appendChild(rank);
      if (flags) row.appendChild(makeFlag(r.code));
      var label = document.createElement('span'); label.className = 'llabel';
      label.textContent = r.label == null || r.label === '' ? '(blank)' : String(r.label);
      label.title = label.textContent; row.appendChild(label);
      var track = document.createElement('span'); track.className = 'ltrack';
      var fill = document.createElement('span'); fill.className = 'lfill';
      track.appendChild(fill); row.appendChild(track);
      var count = document.createElement('span'); count.className = 'lcount';
      count.textContent = fmt(r.count); row.appendChild(count);
      el.appendChild(row);
      var pct = Math.max(1, Math.round((r.count / max) * 100));
      requestAnimationFrame(function () { requestAnimationFrame(function () { fill.style.width = pct + '%'; }); });
    });
  }

  /* ================= timeline (hand-rolled SVG) ================= */

  var SVG_NS = 'http://www.w3.org/2000/svg';
  function tlHideTip() {
    var p = $('panelActivity'), t = p && p.querySelector('.tl-tip');
    if (t) t.classList.remove('on');
  }
  function refreshTlHint() {
    var p = $('panelActivity'), sc = $('tlScroll');
    if (!p || !sc) return;
    var scrollable = sc.scrollWidth > sc.clientWidth + 1;
    p.classList.toggle('scrollable', scrollable);
    p.classList.toggle('at-end', !scrollable || sc.scrollLeft + sc.clientWidth >= sc.scrollWidth - 1);
  }
  function renderTimeline(view) {
    var svg = $('tlChart'); if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    var modeEl = $('activityMode');
    if (modeEl) modeEl.textContent = view.mode === 'live' ? 'hourly \u00B7 connections + auth' : 'daily \u00B7 connections + auth';
    var rows = view.timeline || [];
    var H = 200, padL = 42, padR = 8, padT = 14, padB = 26;
    var MIN_BAND = (window.matchMedia && window.matchMedia('(max-width: 900px)').matches) ? 40 : 26;
    var scrollEl = $('tlScroll');
    var availW = scrollEl ? scrollEl.clientWidth : 960;
    var W = Math.max(availW, rows.length * MIN_BAND + padL + padR);
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.style.width = W + 'px';
    var panel = $('panelActivity');
    var tip = panel ? panel.querySelector('.tl-tip') : null;
    if (panel && !tip) { tip = document.createElement('div'); tip.className = 'tl-tip'; panel.appendChild(tip); }
    if (tip) tip.classList.remove('on');
    function textEl(x, y, str, anchor) {
      var t = document.createElementNS(SVG_NS, 'text');
      t.setAttribute('x', x); t.setAttribute('y', y); t.setAttribute('fill', '#6b7280');
      t.setAttribute('font-size', '9'); t.setAttribute('font-family', 'Plex Mono, ui-monospace, monospace');
      t.setAttribute('letter-spacing', '1'); if (anchor) t.setAttribute('text-anchor', anchor);
      t.textContent = str; return t;
    }
    var startEl = $('activityStart'), endEl = $('activityEnd');
    if (!rows.length) {
      var base = document.createElementNS(SVG_NS, 'line');
      base.setAttribute('x1', padL); base.setAttribute('x2', W - padR);
      base.setAttribute('y1', H - padB); base.setAttribute('y2', H - padB);
      base.setAttribute('stroke', '#1e2328'); base.setAttribute('stroke-width', '1'); svg.appendChild(base);
      svg.appendChild(textEl((W + padL) / 2, H / 2, 'AWAITING FIRST INTERCEPT', 'middle'));
      if (startEl) startEl.textContent = ''; if (endEl) endEl.textContent = '';
      refreshTlHint();
      return;
    }
    var maxV = 1;
    rows.forEach(function (r) { maxV = Math.max(maxV, r.connections, r.auth); });
    var innerW = W - padL - padR, innerH = H - padT - padB, baseY = H - padB;
    var n = rows.length, band = innerW / n, tickW = Math.max(1.5, Math.min(4, band * 0.38));
    [0, Math.round(maxV / 2), maxV].forEach(function (v) {
      var y = baseY - (v / maxV) * innerH;
      var ln = document.createElementNS(SVG_NS, 'line');
      ln.setAttribute('x1', padL); ln.setAttribute('x2', W - padR);
      ln.setAttribute('y1', y); ln.setAttribute('y2', y);
      ln.setAttribute('stroke', v === 0 ? '#1e2328' : '#161a1e'); ln.setAttribute('stroke-width', '1'); svg.appendChild(ln);
      svg.appendChild(textEl(padL - 6, y + 3, fmt(v), 'end'));
    });
    rows.forEach(function (r, i) {
      var cx = padL + band * i + band / 2, half = tickW / 2;
      var hC = (r.connections / maxV) * innerH, hA = (r.auth / maxV) * innerH;
      if (r.auth > 0) {
        var ra = document.createElementNS(SVG_NS, 'rect');
        ra.setAttribute('x', cx - half); ra.setAttribute('width', half);
        ra.setAttribute('y', baseY - hA); ra.setAttribute('height', Math.max(1, hA));
        ra.setAttribute('fill', '#6b7280'); svg.appendChild(ra);
      }
      if (r.connections > 0) {
        var rc = document.createElementNS(SVG_NS, 'rect');
        rc.setAttribute('x', cx); rc.setAttribute('width', half);
        rc.setAttribute('y', baseY - hC); rc.setAttribute('height', Math.max(1, hC));
        rc.setAttribute('fill', '#ff7a18'); svg.appendChild(rc);
      }
      if (r.connections === 0 && r.auth === 0) {
        var dot = document.createElementNS(SVG_NS, 'rect');
        dot.setAttribute('x', cx - 0.5); dot.setAttribute('width', 1);
        dot.setAttribute('y', baseY - 1); dot.setAttribute('height', 1); dot.setAttribute('fill', '#6b7280'); svg.appendChild(dot);
      }
      var hit = document.createElementNS(SVG_NS, 'rect');
      hit.setAttribute('x', padL + band * i); hit.setAttribute('y', padT);
      hit.setAttribute('width', band); hit.setAttribute('height', innerH);
      hit.setAttribute('fill', 'transparent'); hit.setAttribute('pointer-events', 'all');
      function showTip() {
        if (!tip) return;
        var sr = svg.getBoundingClientRect(), pr = panel.getBoundingClientRect(), s = sr.width / W;
        var topY = baseY - Math.max(hC, hA, 2);
        tip.textContent = xLabel(r.t) + ' \u00B7 conn ' + fmt(r.connections) + ' \u00B7 auth ' + fmt(r.auth);
        var hw = tip.offsetWidth / 2;
        var lx = sr.left - pr.left + cx * s;
        tip.style.left = Math.max(hw, Math.min(lx, pr.width - hw)) + 'px';
        tip.style.top = (sr.top - pr.top + topY * s - 6) + 'px';
        tip.classList.add('on');
      }
      hit.addEventListener('mouseenter', showTip);
      hit.addEventListener('mouseleave', tlHideTip);
      hit.addEventListener('click', function (e) { e.stopPropagation(); showTip(); });
      svg.appendChild(hit);
    });
    function xLabel(t) { return view.mode === 'live' ? t.slice(11, 16) : t.slice(5); }
    var labelEvery = Math.max(1, Math.ceil(n / 8));
    rows.forEach(function (r, i) {
      if (i % labelEvery !== 0) return;
      var cx = padL + band * i + band / 2;
      svg.appendChild(textEl(cx, H - 10, xLabel(r.t), 'middle'));
    });
    if (startEl) startEl.textContent = rows[0].t.slice(0, 10);
    if (endEl) endEl.textContent = rows[n - 1].t.slice(0, 10) + (view.mode === 'live' ? ' &middot; UTC' : '');
    refreshTlHint();
  }

  /* ================= console ticker ================= */

  function eventKey(a) { return (a.time || '') + '|' + (a.ip || '') + '|' + (a.event || '') + '|' + (a.detail || ''); }
  function buildConsoleLine(a) {
    var line = document.createElement('div'); line.className = 'c-line';
    var t = document.createElement('span'); t.className = 't';
    var ts = String(a.time || '');
    t.textContent = '[' + (ts.length > 19 ? ts.slice(0, 19) : ts) + ']'; line.appendChild(t);
    function kv(k, v, cls) {
      var ks = document.createElement('span'); ks.className = 'k'; ks.textContent = ' ' + k + '='; line.appendChild(ks);
      var vs = document.createElement('span'); vs.className = cls || 'v'; vs.textContent = String(v == null ? '' : v); line.appendChild(vs);
    }
    kv('src', a.ip || '?'); kv('cc', a.country || '--');
    var isCmd = a.event === 'command' || a.event === 'command.input';
    kv('event', a.event || '?', 'ev' + (isCmd ? ' cmd' : ''));
    var detail = a.detail == null ? '' : String(a.detail);
    if (isCmd) kv('cmd', '"' + detail + '"');
    else if (detail.indexOf('/') !== -1) {
      var parts = detail.split('/'); kv('u', parts[0]);
      if (parts.length > 1) kv('p', parts.slice(1).join('/'));
    } else if (detail) kv('d', detail);
    return line;
  }
  function renderTicker(recent) {
    var box = $('console'); if (!box) return;
    box.textContent = '';
    if (!recent) {
      var hint = document.createElement('div'); hint.className = 'empty';
      hint.textContent = 'available in the 24h view'; box.appendChild(hint); appendCursor(box); return;
    }
    var items = recent.slice(0, TICKER_MAX);
    var keys = items.map(eventKey);
    if (!items.length) {
      var e = document.createElement('div'); e.className = 'empty';
      e.textContent = 'awaiting first intercept'; box.appendChild(e); appendCursor(box); state.tickerSeen = []; return;
    }
    var staggered = 0;
    items.forEach(function (a, i) {
      var line = buildConsoleLine(a);
      var isNew = state.tickerSeen.indexOf(keys[i]) === -1;
      if (isNew && staggered < 14) { line.style.animationDelay = (staggered * 90) + 'ms'; staggered++; }
      else { line.style.animation = 'none'; line.style.opacity = '1'; }
      box.appendChild(line);
    });
    state.tickerSeen = keys;
    appendCursor(box);
  }
  function appendCursor(box) {
    var c = document.createElement('div'); c.className = 'c-cursor';
    var p = document.createElement('span'); p.textContent = 'root@hp04:~#'; c.appendChild(p);
    var b = document.createElement('span'); b.className = 'block'; b.setAttribute('aria-hidden', 'true'); c.appendChild(b);
    box.appendChild(c); box.scrollTop = 0;
  }

  /* ================= globe ================= */

  var world = null, globeOK = false, coordEl = null, hoverCountry = null, globeVisible = true;
  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }
  function applyGlobePlayState() {
    if (!globeOK || !world) return;
    try { (globeVisible && !document.hidden ? world.resumeAnimation : world.pauseAnimation)(); } catch (e) {}
  }
  var hoverLast = 0;
  function hoverThrottle() {
    var now = performance.now();
    if (now - hoverLast < 50) return false;
    hoverLast = now; return true;
  }
  function decodeTopo(topo) {
    var obj = topo && topo.objects && topo.objects.countries;
    if (!obj || !topo.transform || !topo.arcs) return [];
    var arcs = topo.arcs, tr = topo.transform, feats = [];
    function readArc(i) {
      var arc = arcs[i], pts = [], x = 0, y = 0;
      for (var j = 0; j < arc.length; j++) { x += arc[j][0]; y += arc[j][1]; pts.push([x, y]); }
      return pts;
    }
    function ring(seg) {
      var pts = [];
      for (var a = 0; a < seg.length; a++) {
        var arc = seg[a] >= 0 ? readArc(seg[a]) : readArc(~seg[a]).reverse();
        for (var p = 0; p < arc.length; p++) {
          pts.push([tr.translate[0] + arc[p][0] * tr.scale[0], tr.translate[1] + arc[p][1] * tr.scale[1]]);
        }
      }
      return pts;
    }
    obj.geometries.forEach(function (g) {
      if (g.type !== 'Polygon' && g.type !== 'MultiPolygon') return;
      var coords = g.type === 'Polygon' ? g.arcs.map(ring) : g.arcs.map(function (poly) { return poly.map(ring); });
      feats.push({ type: 'Feature', properties: { name: (g.properties && g.properties.name) || '' }, geometry: { type: g.type, coordinates: coords } });
    });
    return feats;
  }
  function loadCountries() {
    if (!globeOK || !world) return;
    fetchJSON('countries-110m.json').then(function (topo) {
      var fs = decodeTopo(topo);
      if (fs.length) world.polygonsData(fs);
    }).catch(function () {});
  }
  function makeSolidTexture() {
    var cv = document.createElement('canvas'); cv.width = 8; cv.height = 4;
    var ctx = cv.getContext('2d'); ctx.fillStyle = '#111417'; ctx.fillRect(0, 0, 8, 4);
    return cv.toDataURL('image/png');
  }
  function initGlobe() {
    var el = $('globe'); coordEl = $('coordReadout');
    if (!el) return;
    if (typeof Globe === 'undefined') { globeFallback(el); return; }
    try {
      world = Globe()(el)
        .backgroundColor('#0b0d0f').showAtmosphere(true).atmosphereColor('#ff7a18').atmosphereAltitude(0.12)
        .pointLat('lat').pointLng('lon').pointColor(function () { return '#ff7a18'; })
        .pointAltitude(function (d) { return Math.min(0.55, 0.05 + Math.sqrt(d.count || 1) * 0.025); })
        .pointRadius(function (d) { return 0.42 + Math.min(1.0, Math.sqrt(d.count || 1) * 0.11); })
        .polygonCapColor(function () { return 'rgba(0,0,0,0)'; })
        .polygonSideColor(function () { return 'rgba(0,0,0,0)'; })
        .polygonStrokeColor(function () { return 'rgba(255,122,24,0.3)'; })
        .polygonAltitude(0.004).polygonsTransitionDuration(0)
        .onPolygonHover(function (p) { hoverCountry = (p && p.properties && p.properties.name) || null; })
        .pointLabel(function (d) {
          return '<div class="globe-tip"><span class="gt-label">' + escapeHTML(d.country || countryName(d.code || '') || 'ORIGIN') + '</span> ' + escapeHTML(fmt(d.count)) + ' hits</div>';
        });
      try { world.showGraticules(false); } catch (e) {}
      try {
        var mat = world.globeMaterial && world.globeMaterial();
        if (mat) { if (mat.color && mat.color.set) mat.color.set('#1a1f24'); if ('map' in mat) mat.map = null; if (mat.shininess !== undefined) mat.shininess = 4; mat.needsUpdate = true; }
      } catch (e1) { try { world.globeImageUrl(makeSolidTexture()); } catch (e2) {} }
      try { world.renderer().setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5)); } catch (e3) {}
      try {
        var ctrl = world.controls();
        ctrl.autoRotate = !prefersReducedMotion(); ctrl.autoRotateSpeed = 0.55;
        if ('enableZoom' in ctrl) ctrl.enableZoom = false;
      } catch (e4) {}
      var wrap = $('globeWrap');
      var resize = function () {
        if (!wrap || !world) return;
        var r = wrap.getBoundingClientRect();
        try { world.width(Math.max(220, Math.floor(r.width))).height(Math.max(220, Math.floor(r.height))); } catch (e4) {}
      };
      if (window.ResizeObserver && wrap) { var ro = new ResizeObserver(resize); ro.observe(wrap); }
      window.addEventListener('resize', resize); resize();
      if (window.IntersectionObserver && wrap) {
        new IntersectionObserver(function (entries) {
          globeVisible = entries[0].isIntersecting; applyGlobePlayState();
        }, { threshold: 0.05 }).observe(wrap);
      }
      document.addEventListener('visibilitychange', applyGlobePlayState);
      if (wrap && coordEl) {
        var GLOBE_R = 100;
        function rotateQuat(v, q) {
          var w = 2 * (q.y * v.z - q.z * v.y), x = 2 * (q.z * v.x - q.x * v.z), y = 2 * (q.x * v.y - q.y * v.x);
          return { x: v.x + q.w * w + (q.y * y - q.z * x), y: v.y + q.w * x + (q.z * w - q.x * y), z: v.z + q.w * y + (q.x * x - q.y * w) };
        }
        wrap.addEventListener('pointermove', function (ev) {
          var txt = null;
          try {
            if (world) {
              var rect = el.getBoundingClientRect();
              var px = ev.clientX - rect.left, py = ev.clientY - rect.top;
              if (hoverThrottle()) {
              if (px >= 0 && py >= 0 && px <= rect.width && py <= rect.height) {
                var cam = world.camera(), halfH = Math.tan(cam.fov * Math.PI / 360);
                var ndcX = (px / rect.width) * 2 - 1, ndcY = -((py / rect.height) * 2 - 1);
                var d = rotateQuat({ x: ndcX * halfH * cam.aspect, y: ndcY * halfH, z: -1 }, cam.quaternion);
                var len = Math.sqrt(d.x * d.x + d.y * d.y + d.z * d.z); d.x /= len; d.y /= len; d.z /= len;
                var cx = cam.position.x, cy = cam.position.y, cz = cam.position.z;
                var b = cx * d.x + cy * d.y + cz * d.z, disc = b * b - (cx * cx + cy * cy + cz * cz - GLOBE_R * GLOBE_R);
                if (disc >= 0) {
                  var t = -b - Math.sqrt(disc);
                  if (t >= 0) {
                    var pt = world.toGeoCoords({ x: cx + t * d.x, y: cy + t * d.y, z: cz + t * d.z });
                    if (pt && isFinite(pt.lat) && isFinite(pt.lng)) {
                      txt = 'LAT ' + (pt.lat >= 0 ? '+' : '') + pt.lat.toFixed(2) + ' / LON ' + (pt.lng >= 0 ? '+' : '') + pt.lng.toFixed(2);
                      if (hoverCountry) txt += ' \u00b7 ' + hoverCountry;
                    }
                  }
                }
              }
              }
            }
          } catch (e5) { txt = null; }
          coordEl.textContent = txt || 'HOVER SPHERE FOR COORDINATES';
          coordEl.classList.toggle('on', !!txt);
        });
        wrap.addEventListener('pointerleave', function () { coordEl.textContent = 'HOVER SPHERE FOR COORDINATES'; coordEl.classList.remove('on'); });
      }
      globeOK = true;
    } catch (e6) { globeFallback(el); }
  }
  function globeFallback(el) {
    globeOK = false; el.textContent = '';
    var d = document.createElement('div'); d.className = 'globe-fallback'; d.textContent = 'globe offline'; el.appendChild(d);
  }
  var globeSig = '';
  function updateGlobe(points) {
    if (!globeOK || !world) return;
    try {
      world.pointsData(points || []);
      var sig = (points || []).length + ':' + (points || []).reduce(function (s, p) { return s + (p.count || 0); }, 0);
      if (sig !== globeSig && points && points.length) { globeSig = sig; world.pointOfView({ lat: 22, lng: 12, altitude: 2.15 }, 900); }
      else globeSig = sig;
    } catch (e) {}
  }

  /* ================= sources (globe | list) ================= */

  function renderSources(view) {
    renderLeader($('chartCountries'), view.countries, true);
  }

  /* ================= render orchestration ================= */

  function renderAll() {
    var view = computeView(); state.view = view;
    renderStats(view.stats);
    renderTimeline(view);
    renderSources(view);
    updateGlobe(view.points);
    renderLeader($('chartIps'), view.ips, true);
    renderLeader($('chartUsernames'), view.usernames, false);
    renderLeader($('chartCommands'), view.commands, false);
    renderLeader($('chartDownloads'), view.downloads, false);
    renderLeader($('chartUploads'), view.uploads, false);
    renderTicker(view.recent);
  }

  /* ================= range controls ================= */

  function setPreset(p) {
    state.preset = p;
    var btns = document.querySelectorAll('.r-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', btns[i].getAttribute('data-preset') === p);
    }
    var bar = $('customBar');
    if (bar) bar.style.display = p === 'custom' ? 'flex' : 'none';
    if (p === 'custom') {
      var s = $('customStart'), e = $('customEnd');
      if (s && e && s.value && e.value && s.value <= e.value) { state.customStart = s.value; state.customEnd = e.value; renderAll(); }
    } else renderAll();
  }
  function clampCustomInputs() {
    var s = $('customStart'), e = $('customEnd');
    if (!s || !e) return;
    var min = state.firstDate || '2020-01-01', max = todayStr();
    s.min = min; s.max = max; e.min = min; e.max = max;
    if (!s.value) s.value = min; if (!e.value) e.value = max;
    if (s.value < min) s.value = min; if (s.value > max) s.value = max;
    if (e.value < min) e.value = min; if (e.value > max) e.value = max;
  }
  function wireControls() {
    var btns = document.querySelectorAll('.r-btn');
    for (var i = 0; i < btns.length; i++) {
      (function (b) { b.addEventListener('click', function () { setPreset(b.getAttribute('data-preset')); }); })(btns[i]);
    }
    var apply = $('customApply');
    if (apply) apply.addEventListener('click', function () {
      var s = $('customStart'), e = $('customEnd');
      if (!s || !e) return;
      var ok = s.value && e.value && s.value <= e.value;
      s.classList.toggle('invalid', !s.value || (!!e.value && s.value > e.value));
      e.classList.toggle('invalid', !e.value || (!!s.value && s.value > e.value));
      if (!ok) return;
      state.customStart = s.value; state.customEnd = e.value; state.preset = 'custom'; renderAll();
    });
  }

  /* ================= reveal on scroll ================= */

  function wireReveal() {
    var els = document.querySelectorAll('.reveal');
    if (!('IntersectionObserver' in window)) {
      for (var i = 0; i < els.length; i++) els[i].classList.add('in-view'); return;
    }
    for (var j = 0; j < els.length; j++) els[j].style.setProperty('--d', (Math.min(j, 8) * 70) + 'ms');
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in-view'); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    for (var k = 0; k < els.length; k++) io.observe(els[k]);
  }

  /* ================= boot ================= */

  function wireTimeline() {
    var sc = $('tlScroll');
    if (sc) sc.addEventListener('scroll', function () { tlHideTip(); refreshTlHint(); });
    var svgEl = $('tlChart');
    if (svgEl) svgEl.addEventListener('click', tlHideTip);
    window.addEventListener('resize', function () { if (state.view) renderTimeline(state.view); });
  }

  function boot() {
    wireControls(); wireReveal(); wireTimeline(); initGlobe(); loadCountries(); clampCustomInputs();
    setPreset('all');
    loadData().then(function () { hideError(); renderAll(); });
    setInterval(function () {
      loadData().then(function () { if (state.lastFetchOk) { hideError(); renderAll(); } });
    }, REFRESH_MS);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
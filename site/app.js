/* Honeypot Attack Map - dashboard logic.
   Plain vanilla JS. Data: meta.json, live.json, archive.json (same origin). */
(function () {
  'use strict';

  var REFRESH_MS = 60000;
  var MAX_BARS = 10;
  var TICKER_ROWS = 60;
  var COLOR_ACCENT = '#ff7a18';
  var COLOR_BG = '#0f1113';
  var COLOR_GLOBE = '#16191d';

  var state = {
    meta: null,
    live: null,
    archive: null,
    preset: 'all',            // 'all' | '7d' | '30d' | '24h' | 'custom'
    customStart: null,        // 'YYYY-MM-DD'
    customEnd: null,          // 'YYYY-MM-DD'
    liveOk: false,
    archiveOk: false,
    metaAt: 0,
    dataAt: 0,
    tickerKeys: [],
    tickerInit: false
  };

  var $ = function (id) { return document.getElementById(id); };
  var reduceMotion = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------------- helpers ---------------- */

  function pad2(n) { return (n < 10 ? '0' : '') + n; }

  function localISODate(d) {
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  }

  function todayISO() { return localISODate(new Date()); }

  function shiftISODate(iso, deltaDays) {
    var p = String(iso).split('-');
    var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]));
    if (isNaN(d.getTime())) return iso;
    d.setUTCDate(d.getUTCDate() + deltaDays);
    return d.getUTCFullYear() + '-' + pad2(d.getUTCMonth() + 1) + '-' + pad2(d.getUTCDate());
  }

  function clampISO(iso, min, max) {
    if (!iso) return iso;
    if (min && iso < min) return min;
    if (max && iso > max) return max;
    return iso;
  }

  function formatInt(n) {
    n = Number(n);
    if (!isFinite(n)) n = 0;
    try { return Math.round(n).toLocaleString('en-US'); }
    catch (e) { return String(Math.round(n)); }
  }

  function parseTime(t) {
    var d = new Date(t);
    return isNaN(d.getTime()) ? null : d;
  }

  function formatTime(t) {
    var d = parseTime(t);
    if (!d) return String(t == null ? '' : t);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
      ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  function timeAgo(ms) {
    var s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (s < 10) return 'just now';
    if (s < 60) return s + ' sec ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' min ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' hr ago';
    return Math.floor(h / 24) + ' d ago';
  }

  function truncate(s, n) {
    s = String(s == null ? '' : s);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  /* ---------------- fetching ---------------- */

  function fetchJSON(url) {
    return fetch(url + (url.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now(), { cache: 'no-store' })
      .then(function (res) {
        if (!res.ok) throw new Error(url + ' -> HTTP ' + res.status);
        return res.json();
      });
  }

  /* ---------------- count-up animation ---------------- */

  function animateValue(el, to) {
    to = Math.max(0, Math.round(Number(to) || 0));
    if (reduceMotion) { el.textContent = formatInt(to); return; }
    var from = parseInt(String(el.textContent).replace(/[^0-9-]/g, ''), 10);
    if (!isFinite(from)) from = 0;
    if (from === to) { el.textContent = formatInt(to); return; }
    if (el._raf) cancelAnimationFrame(el._raf);
    var dur = 700;
    var start = performance.now();
    function frame(now) {
      var k = Math.min(1, (now - start) / dur);
      var e = 1 - Math.pow(1 - k, 3); // ease-out cubic
      el.textContent = formatInt(from + (to - from) * e);
      if (k < 1) el._raf = requestAnimationFrame(frame);
      else { el.textContent = formatInt(to); el._raf = null; }
    }
    el._raf = requestAnimationFrame(frame);
  }

  function setStats(totals) {
    totals = totals || {};
    animateValue($('statConnections'), totals.connections || 0);
    animateValue($('statAuth'), totals.auth_attempts || 0);
    animateValue($('statIps'), totals.unique_ips || 0);
    animateValue($('statCommands'), totals.commands || 0);
  }

  /* ---------------- horizontal bar lists ---------------- */

  function renderBars(container, items, opts) {
    opts = opts || {};
    var limit = opts.limit || MAX_BARS;
    if (!container) return;
    container.textContent = '';
    items = (items || []).slice(0, limit);
    if (!items.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No data for this range yet.';
      container.appendChild(empty);
      return;
    }
    var max = 0;
    for (var i = 0; i < items.length; i++) {
      var c = Number(items[i].count) || 0;
      if (c > max) max = c;
    }
    if (max <= 0) max = 1; // divide-by-zero guard
    items.forEach(function (it) {
      var count = Number(it.count) || 0;
      var pct = Math.max(count > 0 ? 2 : 0, Math.round((count / max) * 100));
      var label = String(it.label);

      var row = document.createElement('div');
      row.className = 'bar-row';

      var name = document.createElement('div');
      name.className = 'bar-name' + (opts.mono ? ' mono' : '');
      name.textContent = label;
      name.title = label;

      var val = document.createElement('div');
      val.className = 'bar-value';
      val.textContent = formatInt(count);

      var track = document.createElement('div');
      track.className = 'bar-track';
      var fill = document.createElement('div');
      fill.className = 'bar-fill';
      track.appendChild(fill);

      row.appendChild(name);
      row.appendChild(val);
      row.appendChild(track);
      container.appendChild(row);

      requestAnimationFrame(function () {
        requestAnimationFrame(function () { fill.style.width = pct + '%'; });
      });
    });
  }

  function renderHint(el, text) {
    if (!el) return;
    el.textContent = '';
    var d = document.createElement('div');
    d.className = 'hint';
    d.textContent = text;
    el.appendChild(d);
  }

  /* ---------------- SVG timeline chart ---------------- */

  function renderTimeline(el, items, opts) {
    opts = opts || {};
    if (!el) return;
    el.textContent = '';
    var W = 640, H = 180, padB = 4, padT = 12;
    var svgNS = 'http://www.w3.org/2000/svg';
    var svg = document.createElementNS(svgNS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Activity over time');

    items = items || [];
    var n = items.length;

    if (!n) {
      var t = document.createElementNS(svgNS, 'text');
      t.setAttribute('x', W / 2);
      t.setAttribute('y', H / 2);
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('class', 'chart-empty');
      t.textContent = 'No data for this range yet.';
      svg.appendChild(t);
      el.appendChild(svg);
      return;
    }

    var maxV = 0;
    for (var i = 0; i < n; i++) {
      var v = Math.max(0, Number(items[i].value) || 0);
      if (v > maxV) maxV = v;
    }
    if (maxV <= 0) maxV = 1; // divide-by-zero guard

    var group = document.createElementNS(svgNS, 'g');
    group.setAttribute('class', 'chart-bars');

    var gap = 2;
    var bw = (W - gap * (n - 1)) / n;
    if (bw < 0.6) { gap = 0; bw = W / n; }

    for (var j = 0; j < n; j++) {
      var val = Math.max(0, Number(items[j].value) || 0);
      var h = val <= 0 ? 0 : Math.max(2, (val / maxV) * (H - padT - padB));
      var rect = document.createElementNS(svgNS, 'rect');
      rect.setAttribute('x', (j * (bw + gap)).toFixed(2));
      rect.setAttribute('y', (H - padB - h).toFixed(2));
      rect.setAttribute('width', Math.max(0.6, bw).toFixed(2));
      rect.setAttribute('height', h.toFixed(2));
      if (bw >= 4) rect.setAttribute('rx', '1');
      var title = document.createElementNS(svgNS, 'title');
      title.textContent = items[j].label + ' · ' + formatInt(val);
      rect.appendChild(title);
      group.appendChild(rect);
    }

    svg.appendChild(group);
    el.appendChild(svg);
  }

  function setTimelineFoot(startText, endText, modeText) {
    var s = $('activityStart'), e = $('activityEnd'), m = $('activityMode');
    if (s) s.textContent = startText || '';
    if (e) e.textContent = endText || '';
    if (m) m.textContent = modeText || '';
  }

  /* ---------------- globe ---------------- */

  var G = {
    world: null,
    failed: false,
    solidURL: null,
    resizeHandler: null
  };

  function makeSolidImageURL() {
    // Tiny solid-color canvas used as the globe texture -> solid dark sphere.
    try {
      var c = document.createElement('canvas');
      c.width = 2; c.height = 2;
      var ctx = c.getContext('2d');
      ctx.fillStyle = COLOR_GLOBE;
      ctx.fillRect(0, 0, 2, 2);
      return c.toDataURL('image/png');
    } catch (e) {
      return null;
    }
  }

  function globeUnavailable(msg) {
    var el = $('globe');
    if (!el) return;
    el.textContent = '';
    var d = document.createElement('div');
    d.className = 'globe-placeholder';
    d.textContent = msg || 'Globe unavailable.';
    el.appendChild(d);
  }

  function initGlobe() {
    var el = $('globe');
    if (!el) return;
    if (typeof Globe !== 'function') {
      G.failed = true;
      globeUnavailable('Globe unavailable — the WebGL globe library failed to load.');
      return;
    }
    try {
      var world = Globe()(el);
      G.solidURL = makeSolidImageURL();

      world
        .backgroundColor(COLOR_BG)
        .showAtmosphere(false)
        .showGraticules(false)
        .pointLat('lat')
        .pointLng('lon')
        .pointColor(function () { return COLOR_ACCENT; })
        .pointAltitude(function (d) { return Math.min(0.6, (Number(d.count) || 0) * 0.02 + 0.01); })
        .pointRadius(function (d) { return Math.min(1.5, 0.35 + Math.sqrt(Number(d.count) || 0) * 0.12); })
        .pointLabel(function () { return ''; });

      // Solid dark sphere. Primary path: tint the globe material directly and
      // drop any texture map (no async texture -> no race, no gradient/earth img).
      // Fallback: a tiny solid-color data-URI texture via globeImageUrl.
      var solidDone = false;
      try {
        if (typeof world.globeMaterial === 'function') {
          var mat = world.globeMaterial();
          if (mat) {
            if ('map' in mat && mat.map) mat.map = null;
            if (mat.color && typeof mat.color.set === 'function') mat.color.set(COLOR_GLOBE);
            mat.needsUpdate = true;
            solidDone = true;
          }
        }
      } catch (e) { solidDone = false; }
      if (!solidDone) {
        G.solidURL = makeSolidImageURL();
        if (G.solidURL) {
          try { world.globeImageUrl(G.solidURL); solidDone = true; } catch (e) { /* noop */ }
        }
      }

      try {
        var controls = world.controls();
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.6;
        controls.enableZoom = false;
      } catch (e) { /* controls optional */ }

      function size() {
        var w = el.clientWidth || 600;
        var h = el.clientHeight || 400;
        try { world.width(w).height(h); } catch (e) { /* noop */ }
      }
      size();
      G.resizeHandler = function () { size(); };
      window.addEventListener('resize', G.resizeHandler);

      G.world = world;
    } catch (e) {
      G.failed = true;
      globeUnavailable('Globe unavailable on this browser.');
    }
  }

  // HTML-escapes a string for safe use inside globe.gl's HTML tooltip label.
  function escHTML(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function renderGlobe(points) {
    if (G.failed) return;
    if (!G.world) return;
    points = points || [];
    try {
      G.world.pointsData(points.map(function (p) {
        return {
          lat: Number(p.lat),
          lon: Number(p.lon),
          count: Number(p.count) || 0,
          country: String(p.country || '')
        };
      }).filter(function (p) {
        return isFinite(p.lat) && isFinite(p.lon);
      }));
      G.world.pointLabel(function (d) {
        var where = d.country ? escHTML(d.country) + ' · ' : '';
        return '<div class="globe-tip"><b>' + escHTML(formatInt(d.count)) + '</b> ' +
          '<span>attacks &middot; ' + where + escHTML(d.lat.toFixed(1)) + ', ' + escHTML(d.lon.toFixed(1)) + '</span></div>';
      });
    } catch (e) { /* keep old points on error */ }
  }

  /* ---------------- archive aggregation ---------------- */

  function mergeCountMap(into, from) {
    if (!from) return;
    for (var k in from) {
      if (!Object.prototype.hasOwnProperty.call(from, k)) continue;
      var v = Number(from[k]) || 0;
      into[k] = (into[k] || 0) + v;
    }
  }

  function mapToSortedArray(map, limit) {
    var arr = [];
    for (var k in map) {
      if (Object.prototype.hasOwnProperty.call(map, k)) arr.push({ label: k, count: map[k] });
    }
    arr.sort(function (a, b) { return b.count - a.count || (a.label < b.label ? -1 : 1); });
    return limit ? arr.slice(0, limit) : arr;
  }

  function geoKey(lat, lon) {
    return lat.toFixed(2) + ',' + lon.toFixed(2);
  }

  // Aggregate archive day-buckets between startISO..endISO (inclusive).
  function aggregateArchive(startISO, endISO) {
    var days = (state.archive && Array.isArray(state.archive.days)) ? state.archive.days : [];
    var totals = { connections: 0, auth_attempts: 0, unique_ips: 0, commands: 0, downloads: 0, uploads: 0 };
    var countries = {}, usernames = {}, commands = {}, geo = {};
    var timeline = [];

    days.forEach(function (day) {
      if (!day || !day.date) return;
      if (startISO && day.date < startISO) return;
      if (endISO && day.date > endISO) return;

      totals.connections += Number(day.connections) || 0;
      totals.auth_attempts += Number(day.auth) || 0;
      totals.unique_ips += Number(day.unique_ips) || 0;
      totals.commands += Number(day.commands) || 0;
      totals.downloads += Number(day.downloads) || 0;
      totals.uploads += Number(day.uploads) || 0;

      mergeCountMap(countries, day.countries);
      mergeCountMap(usernames, day.usernames);
      mergeCountMap(commands, day.top_commands);

      if (Array.isArray(day.geo)) {
        day.geo.forEach(function (g) {
          if (!g) return;
          var lat = Number(g.lat), lon = Number(g.lon);
          if (!isFinite(lat) || !isFinite(lon)) return;
          var key = geoKey(lat, lon);
          if (!geo[key]) geo[key] = { lat: lat, lon: lon, count: 0 };
          geo[key].count += Number(g.count) || 0;
        });
      }

      timeline.push({ date: day.date, connections: Number(day.connections) || 0 });
    });

    timeline.sort(function (a, b) { return a.date < b.date ? -1 : (a.date > b.date ? 1 : 0); });

    var geoArr = [];
    for (var k in geo) {
      if (Object.prototype.hasOwnProperty.call(geo, k)) geoArr.push(geo[k]);
    }

    return {
      totals: totals,
      countries: mapToSortedArray(countries, MAX_BARS),
      usernames: mapToSortedArray(usernames, MAX_BARS),
      commands: mapToSortedArray(commands, MAX_BARS),
      geo: geoArr,
      timeline: timeline
    };
  }

  /* ---------------- range resolution ---------------- */

  function metaMinDate() {
    var m = state.meta && state.meta.first_data_date;
    if (!m && state.archive && state.archive.first_data_date) m = state.archive.first_data_date;
    return m || null;
  }

  function currentRange() {
    var min = metaMinDate();
    var max = todayISO();
    switch (state.preset) {
      case '7d':
        return { preset: '7d', start: clampISO(shiftISODate(max, -6), min, max), end: max };
      case '30d':
        return { preset: '30d', start: clampISO(shiftISODate(max, -29), min, max), end: max };
      case 'custom':
        if (state.customStart && state.customEnd) {
          var s = clampISO(state.customStart, min, max);
          var e = clampISO(state.customEnd, min, max);
          if (s > e) { var tmp = s; s = e; e = tmp; }
          return { preset: 'custom', start: s, end: e };
        }
        return { preset: 'all', start: min, end: max };
      case 'all':
      default:
        return { preset: 'all', start: min, end: max };
    }
  }

  /* ---------------- view models ---------------- */

  function viewFromLive(live) {
    live = live || {};
    var t = live.totals || {};
    var timeline = (Array.isArray(live.timeline) ? live.timeline : []).map(function (d) {
      var lbl = d && d.t != null ? String(d.t) : '';
      var dt = parseTime(lbl);
      if (dt) lbl = dt.getFullYear() + '-' + pad2(dt.getMonth() + 1) + '-' + pad2(dt.getDate()) +
        ' ' + pad2(dt.getHours()) + ':00';
      return {
        label: lbl,
        value: Number(d && d.connections) || 0,
        auth: Number(d && d.auth) || 0
      };
    });
    return {
      mode: 'live',
      totals: {
        connections: Number(t.connections) || 0,
        auth_attempts: Number(t.auth_attempts) || 0,
        unique_ips: Number(t.unique_ips) || 0,
        commands: Number(t.commands) || 0,
        downloads: Number(t.downloads) || 0,
        uploads: Number(t.uploads) || 0
      },
      countries: (Array.isArray(live.top_countries) ? live.top_countries : [])
        .slice(0, MAX_BARS)
        .map(function (d) {
          return { label: String(d.country || d.code || '?'), count: Number(d.count) || 0 };
        }),
      usernames: (Array.isArray(live.top_usernames) ? live.top_usernames : [])
        .slice(0, MAX_BARS)
        .map(function (d) { return { label: String(d.username), count: Number(d.count) || 0 }; }),
      commands: (Array.isArray(live.top_commands) ? live.top_commands : [])
        .slice(0, MAX_BARS)
        .map(function (d) { return { label: String(d.command), count: Number(d.count) || 0 }; }),
      ips: (Array.isArray(live.top_ips) ? live.top_ips : [])
        .slice(0, MAX_BARS)
        .map(function (d) { return { label: String(d.ip), count: Number(d.count) || 0 }; }),
      passwords: (Array.isArray(live.top_passwords) ? live.top_passwords : [])
        .slice(0, MAX_BARS)
        .map(function (d) { return { label: String(d.password), count: Number(d.count) || 0 }; }),
      geo: Array.isArray(live.geo_points) ? live.geo_points : [],
      timeline: timeline,
      recent: Array.isArray(live.recent_attacks) ? live.recent_attacks : []
    };
  }

  function viewFromArchive(range) {
    var agg = aggregateArchive(range.start, range.end);
    return {
      mode: 'archive',
      totals: agg.totals,
      countries: agg.countries,
      usernames: agg.usernames,
      commands: agg.commands,
      ips: null,        // not available from the compact archive
      passwords: null,  // not available from the compact archive
      geo: agg.geo,
      timeline: agg.timeline.map(function (d) {
        return { label: d.date, value: d.connections };
      }),
      recent: null,
      rangeLabel: (range.start || '…') + ' → ' + (range.end || '…')
    };
  }

  /* ---------------- recent attacks ticker ---------------- */

  function tickerRowKey(r) {
    return [r.time, r.ip, r.country, r.event, r.detail].join('|');
  }

  function buildTickerRow(r, isNew) {
    var row = document.createElement('div');
    row.className = 'ticker-row' + (isNew ? ' new-row' : '');

    function cell(text, cls) {
      var d = document.createElement('span');
      d.className = 'c ' + cls;
      d.textContent = text;
      return d;
    }

    row.appendChild(cell(formatTime(r.time), 't-time'));
    row.appendChild(cell(String(r.ip == null ? '' : r.ip), 't-ip'));
    row.appendChild(cell(String(r.country == null ? '' : r.country), 't-country'));
    row.appendChild(cell(String(r.event == null ? '' : r.event), 't-event'));
    row.appendChild(cell(truncate(r.detail == null ? '' : r.detail, 160), 't-detail'));
    return row;
  }

  function renderTicker(recent) {
    var wrap = $('ticker');
    if (!wrap) return;
    var list = (recent || []).slice().sort(function (a, b) {
      var ta = parseTime(a && a.time), tb = parseTime(b && b.time);
      var va = ta ? ta.getTime() : 0, vb = tb ? tb.getTime() : 0;
      return vb - va;
    }).slice(0, TICKER_ROWS);

    var newKeys = list.map(tickerRowKey);
    var newSet = {};
    newKeys.forEach(function (k) { newSet[k] = true; });

    var isNewData = state.tickerInit &&
      list.length > 0 &&
      (!state.tickerKeys.length || newKeys[0] !== state.tickerKeys[0]);

    wrap.textContent = '';
    if (!list.length) {
      var empty = document.createElement('div');
      empty.className = 'empty-state';
      empty.textContent = 'No recent attacks in the last 24h.';
      wrap.appendChild(empty);
    } else {
      list.forEach(function (r) {
        wrap.appendChild(buildTickerRow(r, isNewData));
      });
    }

    state.tickerKeys = newKeys;
    state.tickerInit = true;
    void newSet;
  }

  /* ---------------- main render ---------------- */

  function renderAll() {
    var isLive = state.preset === '24h';
    var vm;
    if (isLive) {
      if (!state.live) { showEmptyState('live'); return; }
      vm = viewFromLive(state.live);
    } else {
      if (!state.archive) { showEmptyState('archive'); return; }
      vm = viewFromArchive(currentRange());
    }

    setStats(vm.totals);
    renderGlobe(vm.geo);

    var tl = vm.timeline || [];
    var firstLbl = tl.length ? tl[0].label : '';
    var lastLbl = tl.length ? tl[tl.length - 1].label : '';
    if (isLive) {
      setTimelineFoot(firstLbl, lastLbl, 'hourly · connections');
    } else {
      setTimelineFoot(firstLbl, lastLbl, 'daily · connections');
    }
    renderTimeline($('activityChart'), tl);

    renderBars($('chartCountries'), vm.countries, { mono: false });
    renderBars($('chartUsernames'), vm.usernames, { mono: true });
    renderBars($('chartCommands'), vm.commands, { mono: true });

    if (isLive) {
      renderBars($('chartIps'), vm.ips, { mono: true });
      renderBars($('chartPasswords'), vm.passwords, { mono: true });
      renderTicker(vm.recent);
    } else {
      renderHint($('chartIps'), 'available in the Last 24h view');
      renderHint($('chartPasswords'), 'available in the Last 24h view');
      renderHint($('ticker'), 'available in the Last 24h view');
    }
  }

  function showEmptyState(which) {
    setStats({ connections: 0, auth_attempts: 0, unique_ips: 0, commands: 0 });
    renderTimeline($('activityChart'), []);
    setTimelineFoot('', '', '');
    renderGlobe([]);
    renderBars($('chartCountries'), []);
    renderBars($('chartUsernames'), []);
    renderBars($('chartCommands'), []);
    renderHint($('chartIps'), which === 'live' ? 'No data yet.' : 'available in the Last 24h view');
    renderHint($('chartPasswords'), which === 'live' ? 'No data yet.' : 'available in the Last 24h view');
    renderHint($('ticker'), which === 'live' ? 'No data yet.' : 'available in the Last 24h view');
  }

  /* ---------------- error banner / updated indicator ---------------- */

  function updateBanner() {
    var el = $('errorBanner');
    if (!el) return;
    var needLive = state.preset === '24h';
    var activeOk = needLive ? state.liveOk : state.archiveOk;
    if (activeOk) {
      el.classList.remove('show');
      el.textContent = '';
    } else {
      el.classList.add('show');
      el.textContent = 'No data yet — could not load ' +
        (needLive ? 'live.json' : 'archive.json') + '. Retrying every 60 seconds.';
    }
  }

  function updateUpdatedText() {
    var el = $('updated');
    if (!el) return;
    if (!state.dataAt) {
      el.textContent = 'awaiting data';
      return;
    }
    el.textContent = 'updated ' + timeAgo(state.dataAt);
  }

  /* ---------------- refresh loop ---------------- */

  function refreshMeta() {
    fetchJSON('meta.json').then(function (m) {
      state.meta = m || null;
      state.metaAt = Date.now();
      applyDateBounds();
    }).catch(function () { /* keep previous meta */ });
  }

  function refreshActive() {
    var needLive = state.preset === '24h';
    var url = needLive ? 'live.json' : 'archive.json';
    fetchJSON(url).then(function (data) {
      if (needLive) { state.live = data; state.liveOk = true; }
      else { state.archive = data; state.archiveOk = true; }
      state.dataAt = Date.now();
      updateBanner();
      updateUpdatedText();
      renderAll();
    }).catch(function () {
      if (needLive) state.liveOk = false;
      else state.archiveOk = false;
      updateBanner();
      updateUpdatedText();
      if (needLive && !state.live) showEmptyState('live');
      if (!needLive && !state.archive) showEmptyState('archive');
    });
  }

  function refreshAll() {
    refreshMeta();
    refreshActive();
  }

  /* ---------------- range picker ---------------- */

  function applyDateBounds() {
    var min = metaMinDate();
    var max = todayISO();
    var s = $('customStart'), e = $('customEnd');
    if (!s || !e) return;
    if (min) { s.min = min; e.min = min; }
    s.max = max; e.max = max;
    if (!s.value) s.value = min || max;
    if (!e.value) e.value = max;
  }

  function setPreset(p) {
    state.preset = p;
    var btns = document.querySelectorAll('.preset-btn');
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      if (b.getAttribute('data-preset') === p) b.classList.add('active');
      else b.classList.remove('active');
    }
    var custom = $('customRange');
    if (custom) {
      if (p === 'custom') custom.classList.add('open');
      else custom.classList.remove('open');
    }
    if (p === 'custom') {
      // Re-render instantly with whatever dates are currently set.
      var s = $('customStart'), e = $('customEnd');
      if (s && e && s.value && e.value) {
        state.customStart = s.value;
        state.customEnd = e.value;
      }
    }
    updateBanner();
    updateUpdatedText();
    renderAll();
    refreshActive(); // pull the dataset this mode needs right away
  }

  function initRangePicker() {
    var btns = document.querySelectorAll('.preset-btn');
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
        if (!s || !e || !s.value || !e.value) return;
        state.customStart = s.value;
        state.customEnd = e.value;
        state.preset = 'custom';
        renderAll();
      });
    }
    var s = $('customStart'), e = $('customEnd');
    [s, e].forEach(function (inp) {
      if (!inp) return;
      inp.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter' && apply) apply.click();
      });
    });
  }

  /* ---------------- reveal on scroll ---------------- */

  function initReveal() {
    var panels = document.querySelectorAll('.panel.reveal');
    if (!('IntersectionObserver' in window) || reduceMotion) {
      for (var i = 0; i < panels.length; i++) panels[i].classList.add('in-view');
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.classList.add('in-view');
          io.unobserve(en.target);
        }
      });
    }, { threshold: 0.08 });
    for (var j = 0; j < panels.length; j++) io.observe(panels[j]);
  }

  /* ---------------- init ---------------- */

  function init() {
    initRangePicker();
    applyDateBounds();
    initReveal();
    initGlobe();
    updateBanner();
    updateUpdatedText();
    refreshAll();
    setInterval(refreshAll, REFRESH_MS);
    setInterval(updateUpdatedText, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();





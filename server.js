require('dotenv').config();
const express   = require('express');
const axios     = require('axios');
const NodeCache = require('node-cache');
const cors      = require('cors');
const crypto    = require('crypto');
const fs        = require('fs');
const path      = require('path');
const FormData  = require('form-data');

const app      = express();
const PORT     = process.env.PORT || 3000;
const apiCache = new NodeCache();

const ADMIN_PASS = process.env.ADMIN_PASS       || 'CodeVortex$777';
const OWNER      = process.env.OWNER            || '@CodeVortex';
const SITE_NAME  = process.env.SITE_NAME        || 'DARKXOSINT';
const TG_TOKEN   = process.env.TG_BOT_TOKEN     || '';
const TG_USER    = process.env.TG_ALERT_USER_ID || '';
const INIT_IP    = process.env.ADMIN_IP         || '152.59.8.197';
const BASE_URL   = process.env.BASE_URL         || '';

// ── DATA ─────────────────────────────────────────────────────────────────────
const DATA_DIR   = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
[DATA_DIR, BACKUP_DIR, path.join(__dirname, 'public')].forEach(function(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const DB = {
  apis:    path.join(DATA_DIR, 'apis.json'),
  keys:    path.join(DATA_DIR, 'keys.json'),
  ips:     path.join(DATA_DIR, 'ips.json'),
  stats:   path.join(DATA_DIR, 'stats.json'),
  logs:    path.join(DATA_DIR, 'logs.json'),
  settings:path.join(DATA_DIR, 'settings.json'),
  banned:  path.join(DATA_DIR, 'banned.json'),
  monitor: path.join(DATA_DIR, 'monitor.json'),
};

const mem = {};
const MEM_TTL = 3000;

function read(f) {
  var now = Date.now();
  if (mem[f] && now - mem[f].t < MEM_TTL) return mem[f].d;
  try {
    var d = JSON.parse(fs.readFileSync(f, 'utf8'));
    mem[f] = { d: d, t: now };
    return d;
  } catch(e) { return {}; }
}

function write(f, d) {
  fs.writeFileSync(f, JSON.stringify(d, null, 2));
  mem[f] = { d: d, t: Date.now() };
}

Object.values(DB).forEach(function(f) { if (!fs.existsSync(f)) write(f, {}); });

// Init defaults
var ii = read(DB.ips);
if (!ii.whitelist) { ii.whitelist = [{ ip: INIT_IP, label: 'Owner', addedAt: new Date().toISOString() }]; write(DB.ips, ii); }
var si = read(DB.settings);
if (!si.initialized) { si.developer = OWNER; si.initialized = true; si.lastBackupTime = 0; write(DB.settings, si); }
var sti = read(DB.stats);
if (!sti.total) { sti.total = { requests: 0, success: 0, failed: 0 }; sti.byType = {}; sti.daily = {}; write(DB.stats, sti); }
var bi = read(DB.banned);
if (!bi.ips) { bi.ips = []; write(DB.banned, bi); }
var mi = read(DB.monitor);
if (!mi.sessions) { mi.sessions = {}; write(DB.monitor, mi); }

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.headers['x-real-ip']
    || req.socket.remoteAddress
    || '0.0.0.0';
}
function cleanIP(ip) { return ip.replace(/^::ffff:/, '').trim(); }
function isIPAllowed(ip) {
  var r = ip, c = cleanIP(ip);
  var d = read(DB.ips);
  return (d.whitelist || []).some(function(e) { return e.ip === r || e.ip === c || e.ip === '::ffff:' + c; });
}
function isBanned(ip) {
  var c = cleanIP(ip);
  var d = read(DB.banned);
  return (d.ips || []).some(function(e) { return e.ip === c || e.ip === ip; });
}

var ccache = new Map();
async function getCountry(ip) {
  var c = cleanIP(ip);
  if (['127.0.0.1', '::1'].includes(c) || c.startsWith('192.168') || c.startsWith('10.')) return 'LOCAL';
  if (ccache.has(c)) return ccache.get(c);
  try {
    var r = await axios.get('http://ip-api.com/json/' + c + '?fields=countryCode', { timeout: 1500 });
    var co = (r.data && r.data.countryCode) ? r.data.countryCode : 'XX';
    ccache.set(c, co);
    setTimeout(function() { ccache.delete(c); }, 3600000);
    return co;
  } catch(e) { return 'XX'; }
}

function isVercel(req) {
  var ua = req.headers['user-agent'] || '';
  return !!(req.headers['x-vercel-id'] || req.headers['x-vercel-deployment-url'] || ua.toLowerCase().includes('vercel'));
}

var BOTS = ['python-requests','python-urllib','scrapy','wget','httpx','go-http-client','java/','libwww-perl','masscan','zgrab','nuclei','nikto','sqlmap','nmap','aiohttp','mechanize'];
function isBot(req) {
  var ua = (req.headers['user-agent'] || '').toLowerCase();
  if (!ua) return true;
  return BOTS.some(function(p) { return ua.includes(p); });
}

function hideF(obj, fields) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(function(i) { return hideF(i, fields); });
  var r = Object.assign({}, obj);
  fields.forEach(function(f) { if (f) delete r[f.trim()]; });
  Object.keys(r).forEach(function(k) { if (r[k] && typeof r[k] === 'object') r[k] = hideF(r[k], fields); });
  return r;
}

var CK = ['credit','credits','owner','made_by','author','powered_by','created_by','dev','source','api_by','developer'];
function repC(obj, val) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(function(i) { return repC(i, val); });
  var r = Object.assign({}, obj);
  CK.forEach(function(k) { if (r.hasOwnProperty(k)) r[k] = val; });
  Object.keys(r).forEach(function(k) { if (r[k] && typeof r[k] === 'object') r[k] = repC(r[k], val); });
  return r;
}

function setF(obj, field, val) {
  if (!obj || typeof obj !== 'object') return;
  if (obj.hasOwnProperty(field)) { obj[field] = val; return; }
  Object.values(obj).forEach(function(v) { if (v && typeof v === 'object') setF(v, field, val); });
}

// ── STATS ─────────────────────────────────────────────────────────────────────
function updateStats(type, success) {
  setImmediate(function() {
    var s = read(DB.stats);
    var today = new Date().toISOString().split('T')[0];
    if (!s.total) s.total = { requests: 0, success: 0, failed: 0 };
    if (!s.byType) s.byType = {};
    if (!s.byType[type]) s.byType[type] = { requests: 0, success: 0, failed: 0 };
    if (!s.daily) s.daily = {};
    if (!s.daily[today]) s.daily[today] = { requests: 0, success: 0, failed: 0 };
    [s.total, s.byType[type], s.daily[today]].forEach(function(t) {
      t.requests++;
      if (success) t.success++; else t.failed++;
    });
    write(DB.stats, s);
  });
}

function updateHits(keyStr, type) {
  setImmediate(function() {
    var keys = read(DB.keys);
    var ki = keys[keyStr];
    if (!ki) return;
    var today = new Date().toDateString();
    if (ki.lastResetDate !== today) { ki.dailyHits = 0; ki.lastResetDate = today; }
    ki.usedHits = (ki.usedHits || 0) + 1;
    ki.dailyHits = (ki.dailyHits || 0) + 1;
    ki.lastUsed = new Date().toISOString();
    if (ki.typeConfig && ki.typeConfig[type]) {
      var tc = ki.typeConfig[type];
      if (tc.lastResetDate !== today) { tc.dailyHits = 0; tc.lastResetDate = today; }
      tc.totalHits = (tc.totalHits || 0) + 1;
      tc.dailyHits = (tc.dailyHits || 0) + 1;
    }
    write(DB.keys, keys);
  });
}

// ── MONITORING ────────────────────────────────────────────────────────────────
function logMonitorRequest(keyStr, type, query, ip, fullURL) {
  var monitor = read(DB.monitor);
  var sessions = monitor.sessions || {};
  var now = Date.now();
  var changed = false;

  Object.keys(sessions).forEach(function(sid) {
    var session = sessions[sid];
    if (session.keyId !== keyStr || session.status !== 'active') return;

    if (now > new Date(session.endTime).getTime()) {
      session.status = 'completed';
      session.completedAt = new Date().toISOString();
      session.report = generateMonitorReport(session);
      changed = true;
      sendMonitorReport(session);
      return;
    }
    if (!session.requests) session.requests = [];
    session.requests.push({
      time: new Date().toISOString(),
      type: type,
      query: query,
      ip: cleanIP(ip),
      url: fullURL
    });
    changed = true;
  });

  if (changed) write(DB.monitor, monitor);
}

function generateMonitorReport(session) {
  var reqs = session.requests || [];
  var uniqueIPs = Array.from(new Set(reqs.map(function(r) { return r.ip; })));
  var uniqueQueries = Array.from(new Set(reqs.map(function(r) { return r.query; })));
  var uniqueTypes = Array.from(new Set(reqs.map(function(r) { return r.type; })));

  var ipCount = {};
  reqs.forEach(function(r) { ipCount[r.ip] = (ipCount[r.ip] || 0) + 1; });
  var topIPs = Object.entries(ipCount).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 10);

  var queryCount = {};
  reqs.forEach(function(r) { queryCount[r.query] = (queryCount[r.query] || 0) + 1; });
  var topQueries = Object.entries(queryCount).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 10);

  var hourly = {};
  reqs.forEach(function(r) {
    var h = new Date(r.time).getHours() + ':00';
    hourly[h] = (hourly[h] || 0) + 1;
  });

  var peakEntry = Object.entries(hourly).sort(function(a, b) { return b[1] - a[1]; })[0];
  var peakHour = peakEntry ? (peakEntry[0] + ' (' + peakEntry[1] + ' requests)') : 'N/A';

  // Detect possible API resellers (high volume from single IP)
  var suspiciousIPs = topIPs.filter(function(e) { return e[1] > reqs.length * 0.3; });

  return {
    totalRequests: reqs.length,
    uniqueIPCount: uniqueIPs.length,
    uniqueIPs: uniqueIPs,
    uniqueQueryCount: uniqueQueries.length,
    uniqueTypes: uniqueTypes,
    topIPs: topIPs,
    topQueries: topQueries,
    hourly: hourly,
    peakHour: peakHour,
    suspiciousIPs: suspiciousIPs,
    generatedAt: new Date().toISOString()
  };
}

async function sendMonitorReport(session) {
  if (!TG_TOKEN || !TG_USER) return;
  var r = session.report;
  if (!r) return;

  var msg = '📊 *Monitoring Report — ' + SITE_NAME + '*\n\n' +
    'Key: `' + session.keyId + '` (' + session.keyLabel + ')\n' +
    'Duration: ' + session.durationLabel + '\n' +
    'Period: ' + new Date(session.startTime).toLocaleString('en-IN') + ' → ' + new Date(session.endTime).toLocaleString('en-IN') + '\n\n' +
    '📈 *Summary*\n' +
    '• Total Requests: ' + r.totalRequests + '\n' +
    '• Unique IPs: ' + r.uniqueIPCount + '\n' +
    '• Unique Queries: ' + r.uniqueQueryCount + '\n' +
    '• API Types: ' + r.uniqueTypes.join(', ') + '\n' +
    '• Peak Hour: ' + r.peakHour + '\n\n';

  if (r.topIPs.length) {
    msg += '🌐 *Top IPs*\n';
    r.topIPs.slice(0, 5).forEach(function(e) { msg += '• `' + e[0] + '` — ' + e[1] + ' requests\n'; });
    msg += '\n';
  }

  if (r.topQueries.length) {
    msg += '🔍 *Top Queries*\n';
    r.topQueries.slice(0, 5).forEach(function(e) { msg += '• `' + e[0] + '` — ' + e[1] + ' times\n'; });
    msg += '\n';
  }

  if (r.suspiciousIPs.length) {
    msg += '⚠️ *Possible API Resellers*\n';
    r.suspiciousIPs.forEach(function(e) { msg += '• `' + e[0] + '` — ' + e[1] + ' requests (' + Math.round(e[1]/r.totalRequests*100) + '%)\n'; });
  }

  try { await tg(msg); } catch(e) {}
}

// Check expired sessions
function checkExpiredSessions() {
  var monitor = read(DB.monitor);
  var sessions = monitor.sessions || {};
  var now = Date.now();
  var changed = false;

  Object.keys(sessions).forEach(function(sid) {
    var session = sessions[sid];
    if (session.status === 'active' && now > new Date(session.endTime).getTime()) {
      session.status = 'completed';
      session.completedAt = new Date().toISOString();
      session.report = generateMonitorReport(session);
      changed = true;
      sendMonitorReport(session);
    }
  });

  if (changed) write(DB.monitor, monitor);
}

setInterval(checkExpiredSessions, 60000);

// ── SCRAPING DETECTION ────────────────────────────────────────────────────────
var scrapingTracker = new Map();
async function detectScraping(keyStr, type, ip, query) {
  var mapKey = cleanIP(ip) + ':' + type;
  var now = Date.now();
  var entry = scrapingTracker.get(mapKey);

  if (!entry || now - entry.start > 300000) {
    scrapingTracker.set(mapKey, { queries: new Set([query]), start: now, alerted: false, key: keyStr });
    return;
  }
  entry.queries.add(query);

  if (entry.queries.size >= 25 && !entry.alerted) {
    entry.alerted = true;
    var banURL = BASE_URL ? (BASE_URL + '/admin-action/ban?ip=' + cleanIP(ip) + '&token=' + ADMIN_PASS) : null;
    var kb = banURL ? [[{ text: '🚫 Ban IP ' + cleanIP(ip), url: banURL }]] : null;
    await tg(
      '🕵️ *Scraping Alert — ' + SITE_NAME + '*\n\n' +
      'API Type: `' + type + '`\n' +
      'Key: `' + keyStr + '`\n' +
      'IP: `' + cleanIP(ip) + '`\n' +
      'Unique Queries: ' + entry.queries.size + ' in 5 min\n' +
      'Time: ' + new Date().toLocaleString('en-IN') + '\n\n' +
      '⚠️ This IP is systematically querying — possible scraping!',
      kb
    );
  }
}

// ── KEY DETAILS ───────────────────────────────────────────────────────────────
function appendDetails(data, ki, cfg, type) {
  if (typeof data !== 'object' || Array.isArray(data)) return data;
  var r = Object.assign({}, data);
  var showKD = ki.showKeyDetails || (cfg && cfg.showKeyDetails);
  var showDev = ki.showDeveloper || (cfg && cfg.showDeveloper);

  if (showKD) {
    var tc = ki.typeConfig && ki.typeConfig[type] ? ki.typeConfig[type] : {};
    var du = tc.dailyHits || ki.dailyHits || 0;
    var dl = tc.dailyLimit || ki.dailyLimit || null;
    var tu = tc.totalHits || ki.usedHits || 0;
    var q  = tc.quota || ki.quota || null;
    var exp = tc.expiresAt || ki.expiresAt;
    var isExp = exp && new Date() > new Date(exp);
    r.key_details = {
      status: isExp ? 'Expired' : 'Active',
      api_type: type,
      daily_usage: dl ? (du + ' / ' + dl.toLocaleString()) : 'Unlimited',
      remaining_today: dl ? Math.max(0, dl - du) : 'Unlimited',
      total_used: q ? (tu + ' / ' + q.toLocaleString()) : tu,
      expires_on: exp ? new Date(exp).toISOString().split('T')[0] : 'Never'
    };
  }
  if (showDev) r.developer = ki.developerText || (cfg && cfg.developerText) || OWNER;
  return r;
}

// ── TELEGRAM ──────────────────────────────────────────────────────────────────
async function tg(msg, kb) {
  if (!TG_TOKEN || !TG_USER) return;
  try {
    var b = { chat_id: TG_USER, text: msg, parse_mode: 'Markdown' };
    if (kb) b.reply_markup = { inline_keyboard: kb };
    await axios.post('https://api.telegram.org/bot' + TG_TOKEN + '/sendMessage', b, { timeout: 5000 });
  } catch(e) { console.error('TG:', e.message); }
}

async function tgSendFile(content, filename, caption) {
  if (!TG_TOKEN || !TG_USER) return;
  try {
    var form = new FormData();
    form.append('chat_id', TG_USER);
    form.append('caption', caption || 'Backup');
    form.append('document', Buffer.from(content), { filename: filename, contentType: 'application/json' });
    await axios.post('https://api.telegram.org/bot' + TG_TOKEN + '/sendDocument', form, { headers: form.getHeaders(), timeout: 30000 });
  } catch(e) { console.error('TG File:', e.message); }
}

// ── BACKUP (weekly + on changes) ──────────────────────────────────────────────
var BACKUP_WEEK = 7 * 24 * 60 * 60 * 1000;

async function createBackup(reason) {
  var backup = {
    version: '5.0',
    createdAt: new Date().toISOString(),
    reason: reason || 'Manual',
    data: {
      apis: read(DB.apis),
      keys: read(DB.keys),
      settings: read(DB.settings),
      ips: read(DB.ips),
      banned: read(DB.banned)
    }
  };
  var ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  var fname = 'backup-' + ts + '.json';
  var fpath = path.join(BACKUP_DIR, fname);
  fs.writeFileSync(fpath, JSON.stringify(backup, null, 2));

  var files = fs.readdirSync(BACKUP_DIR).filter(function(f) { return f.endsWith('.json'); }).sort().reverse();
  files.slice(15).forEach(function(f) { try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch(e) {} });

  var summary = '📦 *DARKXOSINT Backup*\n\nReason: ' + reason + '\nAPIs: ' + Object.keys(backup.data.apis).length + '\nKeys: ' + Object.keys(backup.data.keys).length + '\nTime: ' + new Date().toLocaleString('en-IN');
  await tgSendFile(JSON.stringify(backup, null, 2), fname, summary);
  return { path: fpath, name: fname };
}

function autoBackup(reason) {
  var settings = read(DB.settings);
  var lastBackup = settings.lastBackupTime || 0;
  var now = Date.now();
  if (now - lastBackup < BACKUP_WEEK) return;
  settings.lastBackupTime = now;
  write(DB.settings, settings);
  setImmediate(function() { createBackup(reason).catch(function(e) { console.error('Backup:', e.message); }); });
}

// ── WRONG KEY ALERT ───────────────────────────────────────────────────────────
var wkTrack = new Map();
async function alertWrongKey(key, type, ip, query) {
  var mk = key + ':' + cleanIP(ip);
  var now = Date.now();
  var e = wkTrack.get(mk);
  if (e && now - e.t < 60000) { e.c++; return; }
  wkTrack.set(mk, { c: 1, t: now });
  var banURL = BASE_URL ? (BASE_URL + '/admin-action/ban?ip=' + cleanIP(ip) + '&token=' + ADMIN_PASS) : null;
  await tg(
    '🔑 *Invalid Key Alert — ' + SITE_NAME + '*\n\nKey: `' + key + '`\nType: `' + type + '`\nQuery: `' + query + '`\nIP: `' + cleanIP(ip) + '`\nTime: `' + new Date().toLocaleString('en-IN') + '`',
    banURL ? [[{ text: '🚫 Ban IP ' + cleanIP(ip), url: banURL }]] : null
  );
}

// ── DDOS ─────────────────────────────────────────────────────────────────────
var ddosMap = new Map();
async function chkDDoS(cfg, key, query, ip, url) {
  var th = cfg.ddosThreshold || 60;
  var mk = cfg.id + ':' + key + ':' + query;
  var now = Date.now();
  var e = ddosMap.get(mk);

  if (!e || now - e.s > 60000) { ddosMap.set(mk, { c: 1, s: now, alerted: false }); return false; }
  e.c++;

  if (e.c >= th && !e.alerted) {
    e.alerted = true;
    if (cfg.autoPauseOnDdos) {
      var apis = read(DB.apis);
      if (apis[cfg.id]) { apis[cfg.id].ddosPaused = true; apis[cfg.id].pausedAt = new Date().toISOString(); write(DB.apis, apis); }
    }
    var uURL = BASE_URL ? (BASE_URL + '/unpause?api=' + cfg.id + '&token=' + ADMIN_PASS) : null;
    var bURL = BASE_URL ? (BASE_URL + '/admin-action/ban?ip=' + cleanIP(ip) + '&token=' + ADMIN_PASS) : null;
    var kb = [];
    if (uURL && cfg.autoPauseOnDdos) kb.push([{ text: '▶ Unpause API', url: uURL }]);
    if (bURL) kb.push([{ text: '🚫 Ban IP', url: bURL }]);
    await tg(
      '🚨 *DDoS Alert — ' + SITE_NAME + '*\n\nAPI: ' + cfg.name + ' (`' + cfg.type + '`)\nKey: `' + key + '`\nQuery: `' + query + '`\nIP: `' + cleanIP(ip) + '`\nHits: ' + e.c + '/min\nURL: `' + url + '`\nTime: ' + new Date().toLocaleString('en-IN') + '\n\n' + (cfg.autoPauseOnDdos ? '⏸ API auto-paused' : '⚠️ Still active'),
      kb.length ? kb : null
    );
  }
  return e.c > th * 2;
}

// ── BOT COMMANDS ──────────────────────────────────────────────────────────────
async function handleBotCmd(msg) {
  if (String(msg.chat.id) !== String(TG_USER)) return;
  var text = msg.text || '';
  var p = text.split(' ');
  var cmd = p[0].toLowerCase().replace('/', '').split('@')[0];

  if (cmd === 'start' || cmd === 'help') {
    await tg('⚡ *DARKXOSINT Bot*\n\n/keys — List keys\n/key <key> — Key info\n/expiring — Expiring soon\n/ban <ip> — Ban IP\n/unban <ip> — Unban IP\n/banned — Banned IPs\n/stats — Stats\n/apis — API list\n/pause <type> — Pause API\n/resume <type> — Resume API\n/backup — Send backup');
  }
  else if (cmd === 'keys') {
    var keys = read(DB.keys);
    var list = Object.values(keys);
    if (!list.length) { await tg('No keys'); return; }
    var out = list.slice(0, 15).map(function(k) {
      var types = Object.keys(k.typeConfig || {}).join(',') || 'All';
      var exp = k.expiresAt ? Math.ceil((new Date(k.expiresAt) - new Date()) / 86400000) + 'd' : '∞';
      return '• `' + k.key + '` — ' + k.label + '\n  Types: ' + types + ' | Hits: ' + (k.usedHits || 0) + ' | Exp: ' + exp;
    }).join('\n\n');
    await tg('🔑 *Keys (' + list.length + ')*\n\n' + out);
  }
  else if (cmd === 'key' && p[1]) {
    var keys2 = read(DB.keys);
    var k = keys2[p[1]];
    if (!k) { await tg('❌ Key not found'); return; }
    var exp2 = k.expiresAt ? new Date(k.expiresAt).toLocaleDateString('en-IN') : 'Never';
    var dl2 = k.expiresAt ? Math.ceil((new Date(k.expiresAt) - new Date()) / 86400000) : null;
    var types2 = Object.keys(k.typeConfig || {});
    var typeInfo = types2.length ? '\n\n*Per-Type:*\n' + types2.map(function(t) {
      var tc = k.typeConfig[t];
      var texp = tc.expiresAt ? Math.ceil((new Date(tc.expiresAt) - new Date()) / 86400000) + 'd left' : 'No expiry';
      return '• `' + t + '`: ' + (tc.totalHits || 0) + ' hits | ' + texp;
    }).join('\n') : '';
    await tg('🔑 *' + k.key + '*\nLabel: ' + k.label + '\nHits: ' + (k.usedHits || 0) + '\nExpiry: ' + exp2 + (dl2 !== null ? ' (' + dl2 + ' days)' : '') + '\nLast Used: ' + (k.lastUsed ? new Date(k.lastUsed).toLocaleString('en-IN') : 'Never') + typeInfo);
  }
  else if (cmd === 'expiring') {
    var keys3 = read(DB.keys);
    var soon = Object.values(keys3).filter(function(k) {
      if (!k.expiresAt) return false;
      var d = Math.ceil((new Date(k.expiresAt) - new Date()) / 86400000);
      return d <= 7 && d > 0;
    });
    if (!soon.length) { await tg('✅ No keys expiring in 7 days'); return; }
    var out2 = soon.map(function(k) {
      var d = Math.ceil((new Date(k.expiresAt) - new Date()) / 86400000);
      return '• `' + k.key + '` — ' + k.label + ' — *' + d + ' days left*';
    }).join('\n');
    await tg('⚠️ *Expiring Soon (' + soon.length + ')*\n\n' + out2);
  }
  else if (cmd === 'ban' && p[1]) {
    var d2 = read(DB.banned);
    if (!d2.ips) d2.ips = [];
    if (d2.ips.some(function(e) { return e.ip === p[1]; })) { await tg('Already banned'); return; }
    var reason = p.slice(2).join(' ') || 'Bot ban';
    d2.ips.push({ ip: p[1], reason: reason, bannedAt: new Date().toISOString() });
    write(DB.banned, d2);
    await tg('🚫 `' + p[1] + '` banned');
  }
  else if (cmd === 'unban' && p[1]) {
    var d3 = read(DB.banned);
    d3.ips = (d3.ips || []).filter(function(e) { return e.ip !== p[1]; });
    write(DB.banned, d3);
    await tg('✅ `' + p[1] + '` unbanned');
  }
  else if (cmd === 'banned') {
    var d4 = read(DB.banned);
    var ips = d4.ips || [];
    if (!ips.length) { await tg('No banned IPs'); return; }
    await tg('🚫 *Banned (' + ips.length + ')*\n\n' + ips.map(function(e) { return '• `' + e.ip + '` — ' + (e.reason || '—'); }).join('\n'));
  }
  else if (cmd === 'stats') {
    var s = read(DB.stats);
    var t = s.total || {};
    var rate = t.requests ? Math.round(t.success / t.requests * 100) : 0;
    var keys4 = read(DB.keys);
    var apis = read(DB.apis);
    await tg('📊 *Stats*\n\nRequests: ' + (t.requests || 0) + '\nSuccess: ' + (t.success || 0) + '\nFailed: ' + (t.failed || 0) + '\nRate: ' + rate + '%\nAPIs: ' + Object.keys(apis).length + '\nKeys: ' + Object.keys(keys4).length);
  }
  else if (cmd === 'apis') {
    var apis2 = read(DB.apis);
    var list2 = Object.values(apis2);
    if (!list2.length) { await tg('No APIs'); return; }
    await tg('🔌 *APIs (' + list2.length + ')*\n\n' + list2.map(function(a) { return '• `' + a.type + '` — ' + a.name + '\n  ' + (a.enabled ? (a.ddosPaused ? '⏸ Paused' : '🟢 Active') : '🔴 Disabled'); }).join('\n\n'));
  }
  else if (cmd === 'pause' && p[1]) {
    var apis3 = read(DB.apis);
    var a = Object.values(apis3).find(function(x) { return x.type === p[1]; });
    if (!a) { await tg('❌ Type not found'); return; }
    apis3[a.id].enabled = false; write(DB.apis, apis3);
    await tg('⏸ `' + p[1] + '` paused');
  }
  else if (cmd === 'resume' && p[1]) {
    var apis4 = read(DB.apis);
    var a2 = Object.values(apis4).find(function(x) { return x.type === p[1]; });
    if (!a2) { await tg('❌ Type not found'); return; }
    apis4[a2.id].enabled = true; apis4[a2.id].ddosPaused = false; write(DB.apis, apis4);
    await tg('✅ `' + p[1] + '` resumed');
  }
  else if (cmd === 'backup') {
    await tg('📦 Generating...');
    createBackup('Manual via bot').catch(function(e) { tg('❌ ' + e.message); });
  }
  else {
    await tg('❓ Unknown. Send /help');
  }
}

var lastUpdateId = 0;
async function pollBot() {
  if (!TG_TOKEN || !TG_USER) return;
  try {
    var r = await axios.get('https://api.telegram.org/bot' + TG_TOKEN + '/getUpdates?offset=' + (lastUpdateId + 1) + '&timeout=10&limit=10', { timeout: 15000 });
    var updates = r.data.result || [];
    for (var i = 0; i < updates.length; i++) {
      var u = updates[i];
      lastUpdateId = u.update_id;
      if (u.message) { try { await handleBotCmd(u.message); } catch(e) {} }
    }
  } catch(e) {}
  setTimeout(pollBot, 2000);
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));

function ipGuard(req, res, next) {
  var ip = getIP(req);
  if (isIPAllowed(ip)) return next();
  var l = read(DB.logs);
  if (!l.unauthorized) l.unauthorized = [];
  l.unauthorized.unshift({ ip: cleanIP(ip), time: new Date().toISOString(), path: req.path });
  if (l.unauthorized.length > 200) l.unauthorized = l.unauthorized.slice(0, 200);
  write(DB.logs, l);
  return res.status(403).json({ success: false, message: 'Sorry, you are not Hacker.' });
}

function tokGuard(req, res, next) {
  var t = req.headers['x-admin-token'] || (req.body && req.body.token);
  if (t !== ADMIN_PASS) return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

// ── URL ACTIONS (Telegram buttons) ───────────────────────────────────────────
app.get('/unpause', function(req, res) {
  var id = req.query.api, token = req.query.token;
  if (token !== ADMIN_PASS) return res.status(401).json({ success: false });
  var a = read(DB.apis);
  if (!a[id]) return res.status(404).json({ success: false });
  a[id].ddosPaused = false; write(DB.apis, a);
  tg('✅ API Resumed: ' + a[id].name);
  res.json({ success: true });
});

app.get('/admin-action/ban', function(req, res) {
  var ip = req.query.ip, token = req.query.token;
  if (token !== ADMIN_PASS) return res.status(401).json({ success: false });
  var d = read(DB.banned);
  if (!d.ips) d.ips = [];
  if (!d.ips.some(function(e) { return e.ip === ip; })) {
    d.ips.push({ ip: ip, reason: 'Telegram ban', bannedAt: new Date().toISOString() });
    write(DB.banned, d);
    tg('🚫 IP Banned: `' + ip + '`');
  }
  res.json({ success: true });
});

// ── PUBLIC API ────────────────────────────────────────────────────────────────
app.get('/', async function(req, res) {
  var type = req.query.type, apiKey = req.query.key, query = req.query.query;
  var clientIP = getIP(req);

  if (!type && !apiKey && !query) {
    return res.json({ success: true, name: SITE_NAME, owner: OWNER, usage: '/?type=API_TYPE&key=YOUR_KEY&query=VALUE', status: 'operational' });
  }
  if (!type || !apiKey || !query) {
    return res.status(400).json({ success: false, message: 'type, key and query are required' });
  }

  if (isBanned(clientIP)) return res.status(403).json({ success: false, message: 'Your IP has been banned.' });

  var apisData = read(DB.apis);
  var cfg = Object.values(apisData).find(function(a) { return a.type === type; });

  if (!cfg) return res.status(404).json({ success: false, message: "API type '" + type + "' not found" });
  if (!cfg.enabled) return res.status(503).json({ success: false, message: cfg.disabledMessage || 'Service unavailable.', info: 'Your key remains valid.', developer: cfg.developerText || OWNER });
  if (cfg.ddosPaused) return res.status(503).json({ success: false, message: 'Service paused.', developer: cfg.developerText || OWNER });

  if (cfg.blockVercel && isVercel(req)) return res.status(403).json({ success: false, message: 'Access denied.' });
  if (cfg.blockBots && isBot(req)) return res.status(403).json({ success: false, message: 'Automated requests not allowed.' });
  if (cfg.indiaOnly) {
    var co = await getCountry(clientIP);
    if (co !== 'IN' && co !== 'LOCAL') return res.status(403).json({ success: false, message: 'Only available in India.' });
  }

  var fullURL = req.protocol + '://' + req.get('host') + req.originalUrl;
  var blocked = await chkDDoS(cfg, apiKey, query, clientIP, fullURL);
  if (blocked) return res.status(429).json({ success: false, message: 'Too many requests.' });

  var keysData = read(DB.keys);
  var ki = keysData[apiKey];
  if (!ki) { await alertWrongKey(apiKey, type, clientIP, query); return res.status(401).json({ success: false, message: 'Invalid API key.' }); }

  if (ki.blockVercel && isVercel(req)) return res.status(403).json({ success: false, message: 'Access denied.' });
  if (ki.blockBots && isBot(req)) return res.status(403).json({ success: false, message: 'Automated requests not allowed.' });
  if (ki.indiaOnly) {
    var co2 = await getCountry(clientIP);
    if (co2 !== 'IN' && co2 !== 'LOCAL') return res.status(403).json({ success: false, message: 'Your key is India-only.' });
  }

  var hasTC = ki.typeConfig && Object.keys(ki.typeConfig).length > 0;
  var tc = ki.typeConfig && ki.typeConfig[type] ? ki.typeConfig[type] : null;

  if (hasTC) {
    if (!tc) return res.status(403).json({ success: false, message: "Your key doesn't include '" + type + "' API.", developer: cfg.developerText || OWNER });
    if (tc.enabled === false) return res.status(403).json({ success: false, message: "'" + type + "' is disabled for your key." });
  } else if (ki.allowedTypes && ki.allowedTypes.length > 0) {
    if (!ki.allowedTypes.includes(type)) return res.status(403).json({ success: false, message: "No access to '" + type + "'.", developer: cfg.developerText || OWNER });
  }

  var typeExp = tc && tc.expiresAt ? tc.expiresAt : null;
  if (typeExp && new Date() > new Date(typeExp)) {
    var expD = new Date(typeExp).toLocaleDateString('en-IN');
    return res.status(403).json({ success: false, message: "'" + type + "' access expired on " + expD + '.', developer: cfg.developerText || OWNER });
  }
  if (!typeExp && ki.expiresAt && new Date() > new Date(ki.expiresAt)) {
    var expD2 = new Date(ki.expiresAt).toLocaleDateString('en-IN');
    return res.status(403).json({ success: false, message: 'API key expired on ' + expD2 + '.', developer: cfg.developerText || OWNER });
  }

  var typeQuota = tc ? tc.quota : null;
  var typeTotal = tc ? (tc.totalHits || 0) : 0;
  if (typeQuota && typeTotal >= typeQuota) return res.status(403).json({ success: false, message: "'" + type + "' quota exceeded.", developer: cfg.developerText || OWNER });
  if (!typeQuota && ki.quota && (ki.usedHits || 0) >= ki.quota) return res.status(403).json({ success: false, message: 'Quota exceeded.', developer: cfg.developerText || OWNER });

  var today = new Date().toDateString();
  var typeDL = tc ? tc.dailyLimit : null;
  if (typeDL) {
    if (!tc.lastResetDate || tc.lastResetDate !== today) { tc.dailyHits = 0; tc.lastResetDate = today; }
    if ((tc.dailyHits || 0) >= typeDL) return res.status(429).json({ success: false, message: "Daily limit for '" + type + "' reached." });
  } else if (ki.dailyLimit) {
    if (ki.lastResetDate !== today) { ki.dailyHits = 0; ki.lastResetDate = today; }
    if ((ki.dailyHits || 0) >= ki.dailyLimit) return res.status(429).json({ success: false, message: 'Daily limit reached.' });
  }

  var ck = type + ':' + query;
  var ttl = cfg.cacheTTL || 300;
  var cached = apiCache.get(ck);

  if (cached) {
    updateHits(apiKey, type);
    updateStats(type, true);
    logMonitorRequest(apiKey, type, query, clientIP, fullURL);
    detectScraping(apiKey, type, clientIP, query);
    return res.json(appendDetails(cached, read(DB.keys)[apiKey] || ki, cfg, type));
  }

  try {
    var url = cfg.baseURL.replace('{query}', encodeURIComponent(query));
    var up = await axios.get(url, { timeout: (cfg.timeout || 10) * 1000, headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } });
    var data = up.data;
    if (cfg.hideFields && cfg.hideFields.length) data = hideF(data, cfg.hideFields);
    if (cfg.replaceCredit) data = repC(data, OWNER);
    if (cfg.creditField && typeof data === 'object') setF(data, cfg.creditField, cfg.creditValue || OWNER);
    apiCache.set(ck, data, ttl);
    updateHits(apiKey, type);
    updateStats(type, true);
    logMonitorRequest(apiKey, type, query, clientIP, fullURL);
    detectScraping(apiKey, type, clientIP, query);
    return res.json(appendDetails(data, read(DB.keys)[apiKey] || ki, cfg, type));
  } catch(err) {
    updateHits(apiKey, type);
    updateStats(type, false);
    return res.status(502).json({ success: false, message: 'Upstream service error.' });
  }
});

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/auth/login', ipGuard, function(req, res) {
  var passkey = req.body.passkey;
  var ip = cleanIP(getIP(req));
  var l = read(DB.logs);
  if (!l.logins) l.logins = [];
  if (passkey === ADMIN_PASS) {
    l.logins.unshift({ ip: ip, time: new Date().toISOString(), success: true });
    write(DB.logs, l);
    tg('✅ *Admin Login*\nIP: `' + ip + '`\nTime: `' + new Date().toLocaleString('en-IN') + '`');
    return res.json({ success: true, token: ADMIN_PASS });
  }
  l.logins.unshift({ ip: ip, time: new Date().toISOString(), success: false });
  if (l.logins.length > 100) l.logins = l.logins.slice(0, 100);
  write(DB.logs, l);
  tg('⚠️ *Failed Login*\nIP: `' + ip + '`');
  return res.status(401).json({ success: false, message: 'Invalid passkey' });
});

app.get('/panel', ipGuard, function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'panel.html'));
});

// ── ADMIN ROUTES ──────────────────────────────────────────────────────────────
var adm = express.Router();
adm.use(ipGuard);
adm.use(tokGuard);

adm.get('/stats', function(req, res) {
  var s = read(DB.stats), a = read(DB.apis), k = read(DB.keys), i = read(DB.ips), b = read(DB.banned);
  res.json({
    success: true,
    total: s.total || { requests: 0, success: 0, failed: 0 },
    byType: s.byType || {},
    daily: s.daily || {},
    totalApis: Object.keys(a).length,
    activeApis: Object.values(a).filter(function(x) { return x.enabled && !x.ddosPaused; }).length,
    pausedApis: Object.values(a).filter(function(x) { return x.ddosPaused; }).length,
    disabledApis: Object.values(a).filter(function(x) { return !x.enabled; }).length,
    totalKeys: Object.keys(k).length,
    activeKeys: Object.values(k).filter(function(x) { return !x.expiresAt || new Date() < new Date(x.expiresAt); }).length,
    whitelistedIPs: (i.whitelist || []).length,
    bannedIPs: (b.ips || []).length
  });
});

adm.get('/settings', function(req, res) { res.json({ success: true, settings: read(DB.settings) }); });
adm.put('/settings', function(req, res) { var s = Object.assign(read(DB.settings), req.body); write(DB.settings, s); res.json({ success: true, settings: s }); });

adm.get('/apis', function(req, res) { res.json({ success: true, apis: read(DB.apis) }); });

adm.post('/apis', function(req, res) {
  var body = req.body;
  if (!body.name || !body.type || !body.baseURL) return res.status(400).json({ success: false, message: 'name, type, baseURL required' });
  var apis = read(DB.apis);
  var existId = Object.keys(apis).find(function(id) { return apis[id].type === body.type; });
  var id = existId || ('API_' + crypto.randomBytes(4).toString('hex').toUpperCase());
  var ex = existId ? apis[existId] : {};
  apis[id] = Object.assign(ex, {
    id: id, name: body.name, type: body.type,
    baseURL: body.baseURL.includes('{query}') ? body.baseURL : body.baseURL + '{query}',
    hideFields: body.hideFields ? body.hideFields.split(',').map(function(f) { return f.trim(); }).filter(Boolean) : [],
    replaceCredit: !!body.replaceCredit, creditField: body.creditField || '', creditValue: body.creditValue || OWNER,
    disabledMessage: body.disabledMessage || 'Service temporarily unavailable.',
    cacheTTL: parseInt(body.cacheTTL) || 300, timeout: parseInt(body.timeout) || 10, rateLimit: parseInt(body.rateLimit) || 1000,
    blockVercel: !!body.blockVercel, blockBots: !!body.blockBots, indiaOnly: !!body.indiaOnly,
    ddosThreshold: parseInt(body.ddosThreshold) || 60, autoPauseOnDdos: !!body.autoPauseOnDdos,
    showKeyDetails: !!body.showKeyDetails, showDeveloper: !!body.showDeveloper, developerText: body.developerText || OWNER,
    enabled: ex.enabled !== undefined ? ex.enabled : true, ddosPaused: ex.ddosPaused || false,
    createdAt: ex.createdAt || new Date().toISOString(), updatedAt: new Date().toISOString()
  });
  write(DB.apis, apis);
  autoBackup('API ' + (existId ? 'updated' : 'created') + ': ' + body.type);
  res.json({ success: true, api: apis[id], updated: !!existId });
});

adm.put('/apis/:id', function(req, res) {
  var apis = read(DB.apis);
  if (!apis[req.params.id]) return res.status(404).json({ success: false });
  var b = Object.assign({}, req.body);
  if (b.hideFields && typeof b.hideFields === 'string') b.hideFields = b.hideFields.split(',').map(function(f) { return f.trim(); }).filter(Boolean);
  apis[req.params.id] = Object.assign(apis[req.params.id], b, { updatedAt: new Date().toISOString() });
  write(DB.apis, apis);
  res.json({ success: true, api: apis[req.params.id] });
});

adm.patch('/apis/:id/toggle', function(req, res) {
  var a = read(DB.apis);
  if (!a[req.params.id]) return res.status(404).json({ success: false });
  a[req.params.id].enabled = !a[req.params.id].enabled;
  write(DB.apis, a);
  res.json({ success: true, enabled: a[req.params.id].enabled });
});

adm.patch('/apis/:id/unpause', function(req, res) {
  var a = read(DB.apis);
  if (!a[req.params.id]) return res.status(404).json({ success: false });
  a[req.params.id].ddosPaused = false;
  write(DB.apis, a);
  tg('✅ API Resumed: ' + a[req.params.id].name);
  res.json({ success: true });
});

adm.delete('/apis/:id', function(req, res) {
  var a = read(DB.apis);
  delete a[req.params.id];
  write(DB.apis, a);
  autoBackup('API deleted');
  res.json({ success: true });
});

adm.get('/keys', function(req, res) { res.json({ success: true, keys: read(DB.keys) }); });

adm.post('/keys', function(req, res) {
  var body = req.body;
  var keys = read(DB.keys);
  var apiKey = (body.keyType === 'custom' && body.customKey) ? body.customKey : crypto.randomBytes(8).toString('hex').toUpperCase();
  if (keys[apiKey]) return res.status(400).json({ success: false, message: 'Key already exists' });
  keys[apiKey] = {
    key: apiKey, label: body.label || 'User',
    typeConfig: body.typeConfig || {},
    allowedTypes: Array.isArray(body.allowedTypes) ? body.allowedTypes : (body.allowedTypes ? [body.allowedTypes] : []),
    indiaOnly: !!body.indiaOnly, blockVercel: !!body.blockVercel, blockBots: !!body.blockBots,
    showKeyDetails: !!body.showKeyDetails, showDeveloper: !!body.showDeveloper, developerText: body.developerText || OWNER,
    usedHits: 0, dailyHits: 0, lastResetDate: new Date().toDateString(),
    createdAt: new Date().toISOString(), lastUsed: null
  };
  write(DB.keys, keys);
  autoBackup('Key created: ' + (body.label || 'User'));
  res.json({ success: true, key: keys[apiKey] });
});

adm.put('/keys/:key', function(req, res) {
  var keys = read(DB.keys);
  var k = decodeURIComponent(req.params.key);
  if (!keys[k]) return res.status(404).json({ success: false, message: 'Key not found' });
  keys[k] = Object.assign(keys[k], req.body, { updatedAt: new Date().toISOString() });
  write(DB.keys, keys);
  autoBackup('Key updated: ' + keys[k].label);
  res.json({ success: true, key: keys[k] });
});

adm.post('/keys/:key/regenerate', function(req, res) {
  var keys = read(DB.keys);
  var old = decodeURIComponent(req.params.key);
  if (!keys[old]) return res.status(404).json({ success: false, message: 'Not found' });
  var newKey = (req.body && req.body.newKey) ? req.body.newKey : crypto.randomBytes(8).toString('hex').toUpperCase();
  if (keys[newKey]) return res.status(400).json({ success: false, message: 'New key exists' });
  keys[newKey] = Object.assign({}, keys[old], { key: newKey, updatedAt: new Date().toISOString() });
  delete keys[old];
  write(DB.keys, keys);
  autoBackup('Key regenerated');
  res.json({ success: true, oldKey: old, newKey: newKey, key: keys[newKey] });
});

adm.delete('/keys/:key', function(req, res) {
  var k = read(DB.keys);
  var label = k[decodeURIComponent(req.params.key)] && k[decodeURIComponent(req.params.key)].label;
  delete k[decodeURIComponent(req.params.key)];
  write(DB.keys, k);
  autoBackup('Key deleted: ' + label);
  res.json({ success: true });
});

adm.get('/ips', function(req, res) { res.json({ success: true, ips: (read(DB.ips).whitelist || []) }); });
adm.post('/ips', function(req, res) {
  var ip = req.body.ip, label = req.body.label;
  if (!ip) return res.status(400).json({ success: false });
  var d = read(DB.ips);
  if (!d.whitelist) d.whitelist = [];
  if (d.whitelist.some(function(e) { return e.ip === ip; })) return res.status(400).json({ success: false, message: 'Already exists' });
  d.whitelist.push({ ip: ip, label: label || 'User', addedAt: new Date().toISOString() });
  write(DB.ips, d);
  res.json({ success: true });
});
adm.delete('/ips/:ip', function(req, res) {
  var d = read(DB.ips);
  d.whitelist = (d.whitelist || []).filter(function(e) { return e.ip !== decodeURIComponent(req.params.ip); });
  write(DB.ips, d);
  res.json({ success: true });
});

adm.get('/banned', function(req, res) { res.json({ success: true, banned: (read(DB.banned).ips || []) }); });
adm.post('/banned', function(req, res) {
  var ip = req.body.ip, reason = req.body.reason;
  if (!ip) return res.status(400).json({ success: false });
  var d = read(DB.banned);
  if (!d.ips) d.ips = [];
  if (d.ips.some(function(e) { return e.ip === ip; })) return res.status(400).json({ success: false, message: 'Already banned' });
  d.ips.push({ ip: ip, reason: reason || 'Manual ban', bannedAt: new Date().toISOString() });
  write(DB.banned, d);
  tg('🚫 IP Banned: `' + ip + '`\nReason: ' + (reason || 'Manual'));
  res.json({ success: true });
});
adm.delete('/banned/:ip', function(req, res) {
  var d = read(DB.banned);
  var ip = decodeURIComponent(req.params.ip);
  d.ips = (d.ips || []).filter(function(e) { return e.ip !== ip; });
  write(DB.banned, d);
  tg('✅ IP Unbanned: `' + ip + '`');
  res.json({ success: true });
});

adm.get('/logs', function(req, res) { res.json({ success: true, logs: read(DB.logs) }); });
adm.delete('/logs', function(req, res) { write(DB.logs, {}); res.json({ success: true }); });

// MONITORING ROUTES
adm.get('/monitor', function(req, res) { res.json({ success: true, sessions: read(DB.monitor).sessions || {} }); });

adm.post('/monitor/start', function(req, res) {
  var keyId = req.body.keyId, duration = parseInt(req.body.duration) || 3600, label = req.body.label || '';
  var keys = read(DB.keys);
  if (!keys[keyId]) return res.status(404).json({ success: false, message: 'Key not found' });

  var monitor = read(DB.monitor);
  if (!monitor.sessions) monitor.sessions = {};

  // Check if already monitoring this key
  var existing = Object.values(monitor.sessions).find(function(s) { return s.keyId === keyId && s.status === 'active'; });
  if (existing) return res.status(400).json({ success: false, message: 'Already monitoring this key' });

  var sid = 'MON_' + crypto.randomBytes(4).toString('hex').toUpperCase();
  var startTime = new Date();
  var endTime = new Date(startTime.getTime() + duration * 1000);

  var labels = { 3600: '1 Hour', 21600: '6 Hours', 43200: '12 Hours', 86400: '24 Hours', 259200: '3 Days', 604800: '7 Days' };
  var durationLabel = labels[duration] || (Math.round(duration / 3600) + ' Hours');

  monitor.sessions[sid] = {
    id: sid, keyId: keyId, keyLabel: keys[keyId].label,
    startTime: startTime.toISOString(), endTime: endTime.toISOString(),
    duration: duration, durationLabel: durationLabel,
    status: 'active', requests: [], report: null
  };
  write(DB.monitor, monitor);
  tg('📡 *Monitoring Started*\nKey: `' + keyId + '` (' + keys[keyId].label + ')\nDuration: ' + durationLabel + '\nEnds: ' + endTime.toLocaleString('en-IN'));
  res.json({ success: true, session: monitor.sessions[sid] });
});

adm.delete('/monitor/:sid', function(req, res) {
  var monitor = read(DB.monitor);
  var session = monitor.sessions && monitor.sessions[req.params.sid];
  if (!session) return res.status(404).json({ success: false });
  session.status = 'stopped';
  session.completedAt = new Date().toISOString();
  session.report = generateMonitorReport(session);
  write(DB.monitor, monitor);
  res.json({ success: true, report: session.report });
});

adm.post('/monitor/:sid/send', async function(req, res) {
  var monitor = read(DB.monitor);
  var session = monitor.sessions && monitor.sessions[req.params.sid];
  if (!session) return res.status(404).json({ success: false });
  if (!session.report) session.report = generateMonitorReport(session);
  await sendMonitorReport(session);
  res.json({ success: true });
});

adm.delete('/monitor/:sid/delete', function(req, res) {
  var monitor = read(DB.monitor);
  if (monitor.sessions) delete monitor.sessions[req.params.sid];
  write(DB.monitor, monitor);
  res.json({ success: true });
});

// BACKUP ROUTES
adm.get('/backup', function(req, res) {
  var backup = { version: '5.0', createdAt: new Date().toISOString(), reason: 'Manual download', data: { apis: read(DB.apis), keys: read(DB.keys), settings: read(DB.settings), ips: read(DB.ips), banned: read(DB.banned) } };
  res.setHeader('Content-Disposition', 'attachment; filename="darkxosint-backup-' + Date.now() + '.json"');
  res.setHeader('Content-Type', 'application/json');
  res.json(backup);
});

adm.post('/backup/send', function(req, res) {
  createBackup('Manual from panel').then(function() { res.json({ success: true, message: 'Sent to Telegram' }); }).catch(function(e) { res.status(500).json({ success: false, message: e.message }); });
});

adm.post('/restore', function(req, res) {
  try {
    var backup = req.body.backup, preview = req.body.preview;
    if (!backup || !backup.version || !backup.data) return res.status(400).json({ success: false, message: 'Invalid backup' });
    if (preview) {
      return res.json({ success: true, preview: { version: backup.version, createdAt: backup.createdAt, reason: backup.reason, apis: Object.keys(backup.data.apis || {}).length, keys: Object.keys(backup.data.keys || {}).length, ips: ((backup.data.ips && backup.data.ips.whitelist) || []).length, banned: ((backup.data.banned && backup.data.banned.ips) || []).length } });
    }
    if (backup.data.apis) write(DB.apis, backup.data.apis);
    if (backup.data.keys) write(DB.keys, backup.data.keys);
    if (backup.data.settings) write(DB.settings, backup.data.settings);
    if (backup.data.ips) write(DB.ips, backup.data.ips);
    if (backup.data.banned) write(DB.banned, backup.data.banned);
    tg('🔄 *Backup Restored*\nTime: ' + new Date().toLocaleString('en-IN'));
    res.json({ success: true, message: 'Restored successfully' });
  } catch(e) { res.status(400).json({ success: false, message: 'Restore failed: ' + e.message }); }
});

app.use('/admin', adm);

app.listen(PORT, function() {
  console.log('DARKXOSINT v5 running on port ' + PORT);
  if (TG_TOKEN) pollBot();
});

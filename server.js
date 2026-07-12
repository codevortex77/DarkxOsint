require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const cache = new NodeCache({ stdTTL: 300 });

// ── CONFIG ────────────────────────────────────────────────────────────────────
const ADMIN_PASS   = process.env.ADMIN_PASS   || 'CodeVortex$777';
const OWNER        = process.env.OWNER        || '@RichAllOver';
const SITE_NAME    = process.env.SITE_NAME    || 'DARKXOSINT';
const TG_TOKEN     = process.env.TG_BOT_TOKEN || '';
const TG_USER      = process.env.TG_ALERT_USER_ID || '';
const INIT_ADMIN_IP = process.env.ADMIN_IP    || '152.59.8.197';

// ── DATA LAYER ────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public')))
  fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const DB = {
  apis:   path.join(DATA_DIR, 'apis.json'),
  keys:   path.join(DATA_DIR, 'keys.json'),
  ips:    path.join(DATA_DIR, 'ips.json'),
  stats:  path.join(DATA_DIR, 'stats.json'),
  logs:   path.join(DATA_DIR, 'logs.json'),
};

function read(file)       { try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { return {}; } }
function write(file, data){ fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

// Bootstrap data files
Object.values(DB).forEach(f => { if (!fs.existsSync(f)) write(f, {}); });

// Bootstrap IP whitelist
const ipsInit = read(DB.ips);
if (!ipsInit.whitelist) {
  ipsInit.whitelist = [{ ip: INIT_ADMIN_IP, label: 'Owner', addedAt: new Date().toISOString() }];
  write(DB.ips, ipsInit);
}

// Bootstrap stats
const statsInit = read(DB.stats);
if (!statsInit.total) {
  statsInit.total = { requests: 0, success: 0, failed: 0 };
  statsInit.byType = {};
  statsInit.daily = {};
  write(DB.stats, statsInit);
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.headers['x-real-ip']
    || req.socket.remoteAddress
    || '0.0.0.0';
}

function isIPAllowed(ip) {
  const data = read(DB.ips);
  return (data.whitelist || []).some(e => e.ip === ip);
}

function genKey(len = 16) {
  return crypto.randomBytes(len).toString('hex').toUpperCase();
}

// Deep delete fields from object/array
function hideFields(obj, fields) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(i => hideFields(i, fields));
  const result = { ...obj };
  fields.forEach(f => { delete result[f]; });
  Object.keys(result).forEach(k => {
    if (result[k] && typeof result[k] === 'object')
      result[k] = hideFields(result[k], fields);
  });
  return result;
}

// Replace credit-like fields
const CREDIT_KEYS = ['credit','credits','owner','made_by','author','powered_by','created_by','dev','source'];
function replaceCredits(obj, replacement) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(i => replaceCredits(i, replacement));
  const result = { ...obj };
  CREDIT_KEYS.forEach(k => { if (result.hasOwnProperty(k)) result[k] = replacement; });
  Object.keys(result).forEach(k => {
    if (result[k] && typeof result[k] === 'object')
      result[k] = replaceCredits(result[k], replacement);
  });
  return result;
}

function updateStats(type, success) {
  const s = read(DB.stats);
  const today = new Date().toISOString().split('T')[0];
  if (!s.total)          s.total = { requests:0, success:0, failed:0 };
  if (!s.byType)         s.byType = {};
  if (!s.byType[type])   s.byType[type] = { requests:0, success:0, failed:0 };
  if (!s.daily)          s.daily = {};
  if (!s.daily[today])   s.daily[today] = { requests:0, success:0, failed:0 };

  s.total.requests++;
  s.byType[type].requests++;
  s.daily[today].requests++;
  if (success) { s.total.success++;  s.byType[type].success++;  s.daily[today].success++; }
  else         { s.total.failed++;   s.byType[type].failed++;   s.daily[today].failed++;  }
  write(DB.stats, s);
}

function updateKeyHits(keyStr, keysData) {
  const k = keysData[keyStr];
  if (!k) return;
  const today = new Date().toDateString();
  if (k.lastResetDate !== today) { k.dailyHits = 0; k.lastResetDate = today; }
  k.usedHits  = (k.usedHits  || 0) + 1;
  k.dailyHits = (k.dailyHits || 0) + 1;
  k.lastUsed  = new Date().toISOString();
  write(DB.keys, keysData);
}

// ── DDOS PROTECTION ───────────────────────────────────────────────────────────
const ddosMap = new Map();
const DDOS_LIMIT  = 60;   // hits per window
const DDOS_WINDOW = 60000; // 1 minute ms

async function checkDDoS(key, query, ip) {
  const mapKey = `${key}:${query}`;
  const now    = Date.now();
  let entry    = ddosMap.get(mapKey);

  if (!entry || now - entry.start > DDOS_WINDOW) {
    ddosMap.set(mapKey, { count: 1, start: now, alerted: false });
    return false;
  }

  entry.count++;
  if (entry.count >= DDOS_LIMIT && !entry.alerted) {
    entry.alerted = true;
    if (TG_TOKEN && TG_USER) {
      try {
        await axios.post(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
          chat_id: TG_USER,
          parse_mode: 'Markdown',
          text: `🚨 *DDoS Alert — ${SITE_NAME}*\n\n` +
                `🔑 Key: \`${key}\`\n` +
                `🔍 Query: \`${query}\`\n` +
                `🌐 IP: \`${ip}\`\n` +
                `📊 Hits: *${entry.count}* in 1 min\n` +
                `⏰ Time: \`${new Date().toLocaleString('en-IN')}\`\n\n` +
                `🛡️ Request auto-blocked.`
        });
      } catch (_) {}
    }
  }
  return entry.count > DDOS_LIMIT * 2;
}

// ── TELEGRAM NOTIFY ───────────────────────────────────────────────────────────
async function tgNotify(msg) {
  if (!TG_TOKEN || !TG_USER) return;
  try {
    await axios.post(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      chat_id: TG_USER, text: msg, parse_mode: 'Markdown'
    });
  } catch (_) {}
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// IP whitelist guard
function ipGuard(req, res, next) {
  const ip = getIP(req);
  if (isIPAllowed(ip)) return next();

  // Log unauthorized attempt
  const l = read(DB.logs);
  if (!l.unauthorized) l.unauthorized = [];
  l.unauthorized.unshift({ ip, time: new Date().toISOString(), path: req.path, ua: req.headers['user-agent'] || '' });
  if (l.unauthorized.length > 200) l.unauthorized = l.unauthorized.slice(0, 200);
  write(DB.logs, l);

  return res.status(403).json({ success: false, message: 'Sorry, you are not Hacker.' });
}

// Admin token guard
function tokenGuard(req, res, next) {
  const token = req.headers['x-admin-token'] || req.body?.token;
  if (token !== ADMIN_PASS) return res.status(401).json({ success: false, message: 'Invalid passkey' });
  next();
}

// ── PUBLIC API ENDPOINT ───────────────────────────────────────────────────────
// Format: GET /?type=tg_num&key=swayam&query=1797079166
app.get('/', async (req, res) => {
  const { type, key: apiKey, query } = req.query;
  const clientIP = getIP(req);

  // No params → show info
  if (!type && !apiKey && !query) {
    return res.json({
      success: true,
      name: SITE_NAME,
      owner: OWNER,
      usage: `/?type=API_TYPE&key=YOUR_KEY&query=VALUE`,
      status: 'operational'
    });
  }

  if (!type || !apiKey || !query) {
    return res.status(400).json({ success: false, message: 'type, key, query are required' });
  }

  // DDoS check
  const blocked = await checkDDoS(apiKey, query, clientIP);
  if (blocked) {
    return res.status(429).json({ success: false, message: 'Rate limit exceeded. Try again later.' });
  }

  // Validate key
  const keysData = read(DB.keys);
  const keyInfo  = keysData[apiKey];

  if (!keyInfo) {
    return res.status(401).json({ success: false, message: 'Invalid API key' });
  }

  // Check expiry
  if (keyInfo.expiresAt && new Date() > new Date(keyInfo.expiresAt)) {
    return res.status(403).json({ success: false, message: 'API key expired' });
  }

  // Check quota
  if (keyInfo.quota && (keyInfo.usedHits || 0) >= keyInfo.quota) {
    return res.status(403).json({ success: false, message: `Quota of ${keyInfo.quota} requests exceeded` });
  }

  // Check daily limit
  if (keyInfo.dailyLimit) {
    const today = new Date().toDateString();
    if (keyInfo.lastResetDate !== today) { keyInfo.dailyHits = 0; keyInfo.lastResetDate = today; }
    if ((keyInfo.dailyHits || 0) >= keyInfo.dailyLimit) {
      return res.status(429).json({ success: false, message: `Daily limit of ${keyInfo.dailyLimit} reached` });
    }
  }

  // Find API config by type
  const apisData = read(DB.apis);
  const apiCfg   = Object.values(apisData).find(a => a.type === type);

  if (!apiCfg) {
    return res.status(404).json({ success: false, message: `API type '${type}' not found` });
  }

  if (!apiCfg.enabled) {
    return res.status(503).json({
      success: false,
      message: apiCfg.disabledMessage || 'This API is currently disabled'
    });
  }

  // Cache check
  const cacheKey = `${type}:${query}`;
  const ttl      = apiCfg.cacheTTL || 300;
  const cached   = cache.get(cacheKey);
  if (cached) {
    updateKeyHits(apiKey, keysData);
    updateStats(type, true);
    return res.json(cached);
  }

  try {
    const url = apiCfg.baseURL.replace('{query}', encodeURIComponent(query));
    const upstream = await axios.get(url, {
      timeout: (apiCfg.timeout || 10) * 1000,
      headers: { 'User-Agent': 'DARKXOSINT/2.0' }
    });
    let data = upstream.data;

    // Hide fields
    if (apiCfg.hideFields && apiCfg.hideFields.length) {
      data = hideFields(data, apiCfg.hideFields);
    }

    // Replace credit fields
    if (apiCfg.replaceCredit) {
      data = replaceCredits(data, OWNER);
    }

    // Add powered by tag
    if (apiCfg.showPoweredBy && typeof data === 'object' && !Array.isArray(data)) {
      data.powered_by = `API Powered BY: ${OWNER}`;
    }

    // Custom credit replacement (specific field→value)
    if (apiCfg.creditField && apiCfg.creditValue && typeof data === 'object') {
      setNestedField(data, apiCfg.creditField, apiCfg.creditValue);
    }

    cache.set(cacheKey, data, ttl);
    updateKeyHits(apiKey, keysData);
    updateStats(type, true);

    res.json(data);
  } catch (err) {
    updateKeyHits(apiKey, keysData);
    updateStats(type, false);
    res.status(502).json({ success: false, message: 'Upstream API error', detail: err.message });
  }
});

function setNestedField(obj, field, value) {
  if (typeof obj !== 'object') return;
  if (obj.hasOwnProperty(field)) { obj[field] = value; return; }
  Object.values(obj).forEach(v => { if (v && typeof v === 'object') setNestedField(v, field, value); });
}

// ── ADMIN LOGIN (IP guarded, no token yet) ────────────────────────────────────
app.post('/auth/login', ipGuard, (req, res) => {
  const { passkey } = req.body;
  const ip = getIP(req);
  if (passkey === ADMIN_PASS) {
    tgNotify(`✅ *Admin Login*\nIP: \`${ip}\`\nTime: \`${new Date().toLocaleString('en-IN')}\``);
    const l = read(DB.logs);
    if (!l.logins) l.logins = [];
    l.logins.unshift({ ip, time: new Date().toISOString(), success: true });
    if (l.logins.length > 100) l.logins = l.logins.slice(0, 100);
    write(DB.logs, l);
    return res.json({ success: true, token: ADMIN_PASS });
  }
  const l = read(DB.logs);
  if (!l.logins) l.logins = [];
  l.logins.unshift({ ip, time: new Date().toISOString(), success: false });
  write(DB.logs, l);
  res.status(401).json({ success: false, message: 'Wrong passkey' });
});

// ── ADMIN PANEL (serve HTML, IP guarded) ──────────────────────────────────────
app.get('/panel', ipGuard, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'panel.html'));
});

// ── ADMIN API ROUTES ──────────────────────────────────────────────────────────
const admin = express.Router();
admin.use(ipGuard);
admin.use(tokenGuard);

// Dashboard stats
admin.get('/stats', (req, res) => {
  const stats  = read(DB.stats);
  const apis   = read(DB.apis);
  const keys   = read(DB.keys);
  const ips    = read(DB.ips);
  res.json({
    success: true,
    total: stats.total || {},
    byType: stats.byType || {},
    daily: stats.daily || {},
    totalApis:    Object.keys(apis).length,
    activeApis:   Object.values(apis).filter(a => a.enabled).length,
    disabledApis: Object.values(apis).filter(a => !a.enabled).length,
    totalKeys:    Object.keys(keys).length,
    activeKeys:   Object.values(keys).filter(k => !k.expiresAt || new Date() < new Date(k.expiresAt)).length,
    whitelistedIPs: (ips.whitelist || []).length
  });
});

// ── API CRUD ──────────────────────────────────────────────────────────────────
admin.get('/apis', (req, res) => {
  res.json({ success: true, apis: read(DB.apis) });
});

admin.post('/apis', (req, res) => {
  const { name, type, baseURL, hideFields: hf, replaceCredit, showPoweredBy,
          creditField, creditValue, disabledMessage, cacheTTL, timeout, rateLimit } = req.body;
  if (!name || !type || !baseURL)
    return res.status(400).json({ success: false, message: 'name, type, baseURL required' });

  const apis = read(DB.apis);
  if (Object.values(apis).some(a => a.type === type))
    return res.status(400).json({ success: false, message: `Type '${type}' already exists` });

  const id = 'API_' + crypto.randomBytes(4).toString('hex').toUpperCase();
  apis[id] = {
    id, name, type,
    baseURL: baseURL.includes('{query}') ? baseURL : baseURL + '{query}',
    hideFields:      hf ? hf.split(',').map(f => f.trim()).filter(Boolean) : [],
    replaceCredit:   !!replaceCredit,
    showPoweredBy:   !!showPoweredBy,
    creditField:     creditField  || '',
    creditValue:     creditValue  || OWNER,
    disabledMessage: disabledMessage || 'This API is currently disabled',
    cacheTTL:  parseInt(cacheTTL)  || 300,
    timeout:   parseInt(timeout)   || 10,
    rateLimit: parseInt(rateLimit) || 1000,
    enabled:   true,
    createdAt: new Date().toISOString()
  };
  write(DB.apis, apis);
  res.json({ success: true, api: apis[id] });
});

admin.put('/apis/:id', (req, res) => {
  const apis = read(DB.apis);
  if (!apis[req.params.id])
    return res.status(404).json({ success: false, message: 'API not found' });
  const body = req.body;
  if (body.hideFields && typeof body.hideFields === 'string')
    body.hideFields = body.hideFields.split(',').map(f => f.trim()).filter(Boolean);
  apis[req.params.id] = { ...apis[req.params.id], ...body };
  write(DB.apis, apis);
  res.json({ success: true, api: apis[req.params.id] });
});

admin.patch('/apis/:id/toggle', (req, res) => {
  const apis = read(DB.apis);
  if (!apis[req.params.id])
    return res.status(404).json({ success: false, message: 'API not found' });
  apis[req.params.id].enabled = !apis[req.params.id].enabled;
  write(DB.apis, apis);
  res.json({ success: true, enabled: apis[req.params.id].enabled });
});

admin.delete('/apis/:id', (req, res) => {
  const apis = read(DB.apis);
  if (!apis[req.params.id])
    return res.status(404).json({ success: false, message: 'API not found' });
  delete apis[req.params.id];
  write(DB.apis, apis);
  res.json({ success: true });
});

// ── KEY CRUD ──────────────────────────────────────────────────────────────────
admin.get('/keys', (req, res) => {
  res.json({ success: true, keys: read(DB.keys) });
});

admin.post('/keys', (req, res) => {
  const { label, keyType, customKey, validityType, validityValue,
          quota, dailyLimit, allowedTypes } = req.body;
  const keys = read(DB.keys);

  const apiKey = (keyType === 'custom' && customKey) ? customKey : genKey();
  if (keys[apiKey])
    return res.status(400).json({ success: false, message: 'Key already exists' });

  let expiresAt = null;
  if (validityType && validityValue) {
    const d = new Date();
    if      (validityType === 'days')   d.setDate(d.getDate() + parseInt(validityValue));
    else if (validityType === 'months') d.setMonth(d.getMonth() + parseInt(validityValue));
    expiresAt = d.toISOString();
  }

  keys[apiKey] = {
    key: apiKey,
    label: label || 'User',
    expiresAt,
    quota:      quota      ? parseInt(quota)      : null,
    dailyLimit: dailyLimit ? parseInt(dailyLimit) : null,
    usedHits:   0, dailyHits: 0,
    lastResetDate: new Date().toDateString(),
    allowedTypes:  allowedTypes || [],
    createdAt: new Date().toISOString(),
    lastUsed: null
  };
  write(DB.keys, keys);
  res.json({ success: true, key: keys[apiKey] });
});

admin.put('/keys/:key', (req, res) => {
  const keys = read(DB.keys);
  if (!keys[req.params.key])
    return res.status(404).json({ success: false, message: 'Key not found' });
  keys[req.params.key] = { ...keys[req.params.key], ...req.body };
  write(DB.keys, keys);
  res.json({ success: true });
});

admin.delete('/keys/:key', (req, res) => {
  const keys = read(DB.keys);
  delete keys[req.params.key];
  write(DB.keys, keys);
  res.json({ success: true });
});

// ── IP MANAGEMENT ─────────────────────────────────────────────────────────────
admin.get('/ips', (req, res) => {
  res.json({ success: true, ips: (read(DB.ips).whitelist || []) });
});

admin.post('/ips', (req, res) => {
  const { ip, label } = req.body;
  if (!ip) return res.status(400).json({ success: false, message: 'ip required' });
  const data = read(DB.ips);
  if (!data.whitelist) data.whitelist = [];
  if (data.whitelist.some(e => e.ip === ip))
    return res.status(400).json({ success: false, message: 'IP already whitelisted' });
  data.whitelist.push({ ip, label: label || 'User', addedAt: new Date().toISOString() });
  write(DB.ips, data);
  res.json({ success: true });
});

admin.delete('/ips/:ip', (req, res) => {
  const data = read(DB.ips);
  const decodedIP = decodeURIComponent(req.params.ip);
  data.whitelist = (data.whitelist || []).filter(e => e.ip !== decodedIP);
  write(DB.ips, data);
  res.json({ success: true });
});

// ── LOGS ──────────────────────────────────────────────────────────────────────
admin.get('/logs', (req, res) => {
  res.json({ success: true, logs: read(DB.logs) });
});

admin.delete('/logs', (req, res) => {
  write(DB.logs, {});
  res.json({ success: true });
});

// Mount admin router
app.use('/admin', admin);

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ██████╗  █████╗ ██████╗ ██╗  ██╗██╗  ██╗`);
  console.log(`  ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝╚██╗██╔╝`);
  console.log(`  ██║  ██║███████║██████╔╝█████╔╝  ╚███╔╝ `);
  console.log(`  ██║  ██║██╔══██║██╔══██╗██╔═██╗  ██╔██╗ `);
  console.log(`  ██████╔╝██║  ██║██║  ██║██║  ██╗██╔╝ ██╗`);
  console.log(`  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝`);
  console.log(`\n  DARKXOSINT API Panel — port ${PORT}\n`);
});

require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const NodeCache = require('node-cache');
const cors    = require('cors');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app   = express();
const PORT  = process.env.PORT || 3000;
const cache = new NodeCache();

const ADMIN_PASS = process.env.ADMIN_PASS  || 'CodeVortex$777';
const OWNER      = process.env.OWNER       || '@RichAllOver';
const SITE_NAME  = process.env.SITE_NAME   || 'DARKXOSINT';
const TG_TOKEN   = process.env.TG_BOT_TOKEN || '';
const TG_USER    = process.env.TG_ALERT_USER_ID || '';
const INIT_IP    = process.env.ADMIN_IP    || '152.59.8.197';
const BASE_URL   = process.env.BASE_URL    || '';

// ── DATA ──────────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public')))
  fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const DB = {
  apis:     path.join(DATA_DIR, 'apis.json'),
  keys:     path.join(DATA_DIR, 'keys.json'),
  ips:      path.join(DATA_DIR, 'ips.json'),
  stats:    path.join(DATA_DIR, 'stats.json'),
  logs:     path.join(DATA_DIR, 'logs.json'),
  settings: path.join(DATA_DIR, 'settings.json'),
};

function read(f)   { try { return JSON.parse(fs.readFileSync(f,'utf8')); } catch { return {}; } }
function write(f,d){ fs.writeFileSync(f, JSON.stringify(d, null, 2)); }

Object.values(DB).forEach(f => { if (!fs.existsSync(f)) write(f, {}); });

const ipsInit = read(DB.ips);
if (!ipsInit.whitelist) {
  ipsInit.whitelist = [{ ip: INIT_IP, label: 'Owner', addedAt: new Date().toISOString() }];
  write(DB.ips, ipsInit);
}

const settingsInit = read(DB.settings);
if (!settingsInit.initialized) {
  settingsInit.developer     = OWNER;
  settingsInit.showKeyDetails = true;
  settingsInit.showDeveloper  = true;
  settingsInit.initialized    = true;
  write(DB.settings, settingsInit);
}

const statsInit = read(DB.stats);
if (!statsInit.total) {
  statsInit.total = { requests:0, success:0, failed:0 };
  statsInit.byType = {};  statsInit.daily = {};
  write(DB.stats, statsInit);
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getIP(req) {
  return (req.headers['x-forwarded-for']||'').split(',')[0].trim()
    || req.headers['x-real-ip']
    || req.socket.remoteAddress || '0.0.0.0';
}
function cleanIP(ip) { return ip.replace(/^::ffff:/,'').trim(); }

function isIPAllowed(ip) {
  const raw = ip, clean = cleanIP(ip);
  const data = read(DB.ips);
  return (data.whitelist||[]).some(e =>
    e.ip===raw || e.ip===clean || e.ip==='::ffff:'+clean
  );
}

// Country cache
const ipCountryCache = new Map();
async function getIPCountry(ip) {
  const c = cleanIP(ip);
  if (['127.0.0.1','::1'].includes(c)||c.startsWith('192.168')||c.startsWith('10.')) return 'LOCAL';
  if (ipCountryCache.has(c)) return ipCountryCache.get(c);
  try {
    const r = await axios.get(`http://ip-api.com/json/${c}?fields=countryCode`,{timeout:2000});
    const country = r.data?.countryCode||'XX';
    ipCountryCache.set(c, country);
    setTimeout(()=>ipCountryCache.delete(c), 3600000);
    return country;
  } catch { return 'XX'; }
}

function isVercelRequest(req) {
  const ua = req.headers['user-agent']||'';
  return !!(req.headers['x-vercel-id']||req.headers['x-vercel-deployment-url']
    ||ua.toLowerCase().includes('vercel'));
}

const BOT_PATTERNS = ['python-requests','python-urllib','scrapy','wget','httpx',
  'go-http-client','java/','libwww-perl','masscan','zgrab','nuclei','nikto',
  'sqlmap','nmap','dirbuster','gobuster','aiohttp','mechanize','phantomjs'];

function isBotRequest(req) {
  const ua = (req.headers['user-agent']||'').toLowerCase();
  if (!ua) return true;
  return BOT_PATTERNS.some(p=>ua.includes(p));
}

// Field helpers
function hideFields(obj, fields) {
  if (!obj||typeof obj!=='object') return obj;
  if (Array.isArray(obj)) return obj.map(i=>hideFields(i,fields));
  const r={...obj};
  fields.forEach(f=>{if(f)delete r[f.trim()];});
  Object.keys(r).forEach(k=>{if(r[k]&&typeof r[k]==='object')r[k]=hideFields(r[k],fields);});
  return r;
}

const CREDIT_KEYS=['credit','credits','owner','made_by','author','powered_by','created_by','dev','source','api_by'];
function replaceCredits(obj,val) {
  if (!obj||typeof obj!=='object') return obj;
  if (Array.isArray(obj)) return obj.map(i=>replaceCredits(i,val));
  const r={...obj};
  CREDIT_KEYS.forEach(k=>{if(r.hasOwnProperty(k))r[k]=val;});
  Object.keys(r).forEach(k=>{if(r[k]&&typeof r[k]==='object')r[k]=replaceCredits(r[k],val);});
  return r;
}

function setField(obj,field,value) {
  if (!obj||typeof obj!=='object') return;
  if (obj.hasOwnProperty(field)){obj[field]=value;return;}
  Object.values(obj).forEach(v=>{if(v&&typeof v==='object')setField(v,field,value);});
}

// Stats
function updateStats(type,success) {
  const s=read(DB.stats);
  const today=new Date().toISOString().split('T')[0];
  if (!s.total)        s.total={requests:0,success:0,failed:0};
  if (!s.byType)       s.byType={};
  if (!s.byType[type]) s.byType[type]={requests:0,success:0,failed:0};
  if (!s.daily)        s.daily={};
  if (!s.daily[today]) s.daily[today]={requests:0,success:0,failed:0};
  [s.total,s.byType[type],s.daily[today]].forEach(t=>{
    t.requests++;
    if(success)t.success++;else t.failed++;
  });
  write(DB.stats,s);
}

function updateKeyHits(keyStr) {
  const keys=read(DB.keys);
  const k=keys[keyStr]; if(!k)return;
  const today=new Date().toDateString();
  if(k.lastResetDate!==today){k.dailyHits=0;k.lastResetDate=today;}
  k.usedHits=(k.usedHits||0)+1;
  k.dailyHits=(k.dailyHits||0)+1;
  k.lastUsed=new Date().toISOString();
  write(DB.keys,keys);
}

// Telegram
async function tgSend(msg,keyboard=null) {
  if(!TG_TOKEN||!TG_USER) return;
  try {
    const body={chat_id:TG_USER,text:msg,parse_mode:'Markdown'};
    if(keyboard)body.reply_markup={inline_keyboard:keyboard};
    await axios.post(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`,body);
  } catch(e){console.error('TG:',e.message);}
}

// DDoS
const ddosMap=new Map();
async function checkDDoS(apiCfg,key,query,ip,fullURL) {
  const threshold=apiCfg.ddosThreshold||60;
  const mapKey=`${apiCfg.id}:${key}:${query}`;
  const now=Date.now();
  let entry=ddosMap.get(mapKey);
  if(!entry||now-entry.start>60000){
    ddosMap.set(mapKey,{count:1,start:now,alerted:false});
    return false;
  }
  entry.count++;
  if(entry.count>=threshold&&!entry.alerted){
    entry.alerted=true;
    if(apiCfg.autoPauseOnDdos){
      const apis=read(DB.apis);
      if(apis[apiCfg.id]){apis[apiCfg.id].ddosPaused=true;apis[apiCfg.id].pausedAt=new Date().toISOString();write(DB.apis,apis);}
    }
    const unpauseURL=BASE_URL?`${BASE_URL}/unpause?api=${apiCfg.id}&token=${ADMIN_PASS}`:null;
    const msg=`🚨 *DDoS Alert — ${SITE_NAME}*\n\n`+
      `*API:* ${apiCfg.name} (\`${apiCfg.type}\`)\n`+
      `*Key:* \`${key}\`\n`+
      `*Query:* \`${query}\`\n`+
      `*IP:* \`${cleanIP(ip)}\`\n`+
      `*Hits:* ${entry.count}/min (limit: ${threshold})\n`+
      `*URL:* \`${fullURL}\`\n`+
      `*Time:* ${new Date().toLocaleString('en-IN')}\n\n`+
      (apiCfg.autoPauseOnDdos?'⏸ API auto-paused':'⚠️ API still active');
    const kb=unpauseURL&&apiCfg.autoPauseOnDdos?[[{text:'▶ Unpause API',url:unpauseURL}]]:null;
    await tgSend(msg,kb);
  }
  return entry.count>threshold*2;
}

// Key details appender
function appendKeyDetails(data,keyInfo,settings) {
  if(!settings.showKeyDetails||typeof data!=='object'||Array.isArray(data)) return data;
  const dailyUsed=keyInfo.dailyHits||0;
  const dailyLimit=keyInfo.dailyLimit||null;
  const totalUsed=keyInfo.usedHits||0;
  const quota=keyInfo.quota||null;
  const isExpired=keyInfo.expiresAt&&new Date()>new Date(keyInfo.expiresAt);
  return {
    ...data,
    key_details:{
      status: isExpired?'Expired':'Active',
      daily_usage: dailyLimit?`${dailyUsed} / ${dailyLimit.toLocaleString()}`:'Unlimited',
      remaining_requests: dailyLimit?Math.max(0,dailyLimit-dailyUsed):'Unlimited',
      total_used: quota?`${totalUsed} / ${quota.toLocaleString()}`:totalUsed,
      expires_on: keyInfo.expiresAt?new Date(keyInfo.expiresAt).toISOString().split('T')[0]:'Never'
    },
    developer: settings.showDeveloper?(settings.developer||OWNER):undefined
  };
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors()); app.use(express.json());

function ipGuard(req,res,next) {
  const ip=getIP(req);
  if(isIPAllowed(ip)) return next();
  const l=read(DB.logs);
  if(!l.unauthorized)l.unauthorized=[];
  l.unauthorized.unshift({ip:cleanIP(ip),raw:ip,time:new Date().toISOString(),path:req.path});
  if(l.unauthorized.length>200)l.unauthorized=l.unauthorized.slice(0,200);
  write(DB.logs,l);
  return res.status(403).json({success:false,message:'Sorry, you are not Hacker.'});
}

function tokenGuard(req,res,next) {
  const token=req.headers['x-admin-token']||req.body?.token;
  if(token!==ADMIN_PASS) return res.status(401).json({success:false,message:'Unauthorized'});
  next();
}

// ── UNPAUSE via URL ───────────────────────────────────────────────────────────
app.get('/unpause',(req,res)=>{
  const{api:apiId,token}=req.query;
  if(token!==ADMIN_PASS) return res.status(401).json({success:false,message:'Invalid token'});
  const apis=read(DB.apis);
  if(!apis[apiId]) return res.status(404).json({success:false,message:'Not found'});
  apis[apiId].ddosPaused=false; apis[apiId].pausedAt=null;
  write(DB.apis,apis);
  tgSend(`✅ *API Resumed*\n${apis[apiId].name} is now active.`);
  res.json({success:true,message:`API ${apis[apiId].name} resumed`});
});

// ── PUBLIC API ────────────────────────────────────────────────────────────────
app.get('/',async(req,res)=>{
  const{type,key:apiKey,query}=req.query;
  const clientIP=getIP(req);

  if(!type&&!apiKey&&!query) return res.json({
    success:true,name:SITE_NAME,owner:OWNER,
    usage:'/?type=API_TYPE&key=YOUR_KEY&query=VALUE',status:'operational'
  });

  if(!type||!apiKey||!query)
    return res.status(400).json({success:false,message:'type, key and query are required'});

  const apisData=read(DB.apis);
  const apiCfg=Object.values(apisData).find(a=>a.type===type);
  const settings=read(DB.settings);

  if(!apiCfg)
    return res.status(404).json({success:false,message:`API type '${type}' not found`});

  if(!apiCfg.enabled)
    return res.status(503).json({
      success:false,
      message:apiCfg.disabledMessage||'Service temporarily unavailable.',
      info:'Your API key remains valid and will work once service resumes.',
      developer:settings.developer||OWNER
    });

  if(apiCfg.ddosPaused)
    return res.status(503).json({
      success:false,
      message:'Service paused due to unusual traffic. Please try again later.',
      developer:settings.developer||OWNER
    });

  if(apiCfg.blockVercel&&isVercelRequest(req))
    return res.status(403).json({success:false,message:'Access denied.'});

  if(apiCfg.blockBots&&isBotRequest(req))
    return res.status(403).json({success:false,message:'Automated requests are not allowed.'});

  if(apiCfg.indiaOnly){
    const country=await getIPCountry(clientIP);
    if(country!=='IN'&&country!=='LOCAL')
      return res.status(403).json({success:false,message:'This API is only available in India.'});
  }

  const fullURL=`${req.protocol}://${req.get('host')}${req.originalUrl}`;
  const isBlocked=await checkDDoS(apiCfg,apiKey,query,clientIP,fullURL);
  if(isBlocked)
    return res.status(429).json({success:false,message:'Too many requests. Temporarily blocked.'});

  const keysData=read(DB.keys);
  const keyInfo=keysData[apiKey];

  if(!keyInfo)
    return res.status(401).json({success:false,message:'Invalid API key.'});

  if(keyInfo.allowedTypes&&keyInfo.allowedTypes.length>0&&!keyInfo.allowedTypes.includes(type))
    return res.status(403).json({
      success:false,
      message:`Your API key does not have access to '${type}'. Contact the developer.`,
      developer:settings.developer||OWNER
    });

  if(keyInfo.expiresAt&&new Date()>new Date(keyInfo.expiresAt)){
    const d=new Date(keyInfo.expiresAt).toLocaleDateString('en-IN');
    return res.status(403).json({
      success:false,
      message:`API key expired on ${d}. Please contact the developer to renew.`,
      developer:settings.developer||OWNER
    });
  }

  if(keyInfo.quota&&(keyInfo.usedHits||0)>=keyInfo.quota)
    return res.status(403).json({
      success:false,
      message:`Request quota of ${keyInfo.quota.toLocaleString()} exceeded.`,
      developer:settings.developer||OWNER
    });

  const today=new Date().toDateString();
  if(keyInfo.dailyLimit){
    if(keyInfo.lastResetDate!==today){keyInfo.dailyHits=0;keyInfo.lastResetDate=today;}
    if((keyInfo.dailyHits||0)>=keyInfo.dailyLimit)
      return res.status(429).json({
        success:false,
        message:`Daily limit of ${keyInfo.dailyLimit.toLocaleString()} requests reached. Resets at midnight.`,
        developer:settings.developer||OWNER
      });
  }

  const cacheKey=`${type}:${query}`;
  const ttl=apiCfg.cacheTTL||300;
  const cached=cache.get(cacheKey);
  if(cached){
    updateKeyHits(apiKey);
    updateStats(type,true);
    return res.json(appendKeyDetails(cached,read(DB.keys)[apiKey]||keyInfo,settings));
  }

  try {
    const url=apiCfg.baseURL.replace('{query}',encodeURIComponent(query));
    const up=await axios.get(url,{
      timeout:(apiCfg.timeout||10)*1000,
      headers:{'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    });
    let data=up.data;
    if(apiCfg.hideFields?.length) data=hideFields(data,apiCfg.hideFields);
    if(apiCfg.replaceCredit)      data=replaceCredits(data,OWNER);
    if(apiCfg.creditField&&typeof data==='object') setField(data,apiCfg.creditField,apiCfg.creditValue||OWNER);
    cache.set(cacheKey,data,ttl);
    updateKeyHits(apiKey);
    updateStats(type,true);
    res.json(appendKeyDetails(data,read(DB.keys)[apiKey]||keyInfo,settings));
  } catch(err) {
    updateKeyHits(apiKey);
    updateStats(type,false);
    res.status(502).json({success:false,message:'Upstream service error.'});
  }
});

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/auth/login',ipGuard,(req,res)=>{
  const{passkey}=req.body;
  const ip=cleanIP(getIP(req));
  const l=read(DB.logs);
  if(!l.logins)l.logins=[];
  if(passkey===ADMIN_PASS){
    l.logins.unshift({ip,time:new Date().toISOString(),success:true});
    write(DB.logs,l);
    tgSend(`✅ *Admin Login*\nIP: \`${ip}\`\nTime: \`${new Date().toLocaleString('en-IN')}\``);
    return res.json({success:true,token:ADMIN_PASS});
  }
  l.logins.unshift({ip,time:new Date().toISOString(),success:false});
  if(l.logins.length>100)l.logins=l.logins.slice(0,100);
  write(DB.logs,l);
  tgSend(`⚠️ *Failed Login*\nIP: \`${ip}\`\nTime: \`${new Date().toLocaleString('en-IN')}\``);
  res.status(401).json({success:false,message:'Invalid passkey'});
});

app.get('/panel',ipGuard,(req,res)=>{
  res.sendFile(path.join(__dirname,'public','panel.html'));
});

// ── ADMIN ─────────────────────────────────────────────────────────────────────
const admin=express.Router();
admin.use(ipGuard); admin.use(tokenGuard);

admin.get('/stats',(req,res)=>{
  const stats=read(DB.stats);
  const apis=read(DB.apis);
  const keys=read(DB.keys);
  const ips=read(DB.ips);
  res.json({
    success:true,...stats,
    totalApis:Object.keys(apis).length,
    activeApis:Object.values(apis).filter(a=>a.enabled&&!a.ddosPaused).length,
    pausedApis:Object.values(apis).filter(a=>a.ddosPaused).length,
    disabledApis:Object.values(apis).filter(a=>!a.enabled).length,
    totalKeys:Object.keys(keys).length,
    activeKeys:Object.values(keys).filter(k=>!k.expiresAt||new Date()<new Date(k.expiresAt)).length,
    whitelistedIPs:(ips.whitelist||[]).length
  });
});

admin.get('/settings',(req,res)=>res.json({success:true,settings:read(DB.settings)}));
admin.put('/settings',(req,res)=>{
  const s={...read(DB.settings),...req.body};
  write(DB.settings,s);
  res.json({success:true,settings:s});
});

admin.get('/apis',(req,res)=>res.json({success:true,apis:read(DB.apis)}));

admin.post('/apis',(req,res)=>{
  const{name,type,baseURL,hideFields:hf,replaceCredit,creditField,creditValue,
    disabledMessage,cacheTTL,timeout,rateLimit,
    blockVercel,blockBots,indiaOnly,ddosThreshold,autoPauseOnDdos}=req.body;
  if(!name||!type||!baseURL)
    return res.status(400).json({success:false,message:'name, type, baseURL required'});
  const apis=read(DB.apis);
  if(Object.values(apis).some(a=>a.type===type))
    return res.status(400).json({success:false,message:`Type '${type}' already exists`});
  const id='API_'+crypto.randomBytes(4).toString('hex').toUpperCase();
  apis[id]={
    id,name,type,
    baseURL:baseURL.includes('{query}')?baseURL:baseURL+'{query}',
    hideFields:hf?hf.split(',').map(f=>f.trim()).filter(Boolean):[],
    replaceCredit:!!replaceCredit,creditField:creditField||'',creditValue:creditValue||OWNER,
    disabledMessage:disabledMessage||'Service temporarily unavailable.',
    cacheTTL:parseInt(cacheTTL)||300,timeout:parseInt(timeout)||10,rateLimit:parseInt(rateLimit)||1000,
    blockVercel:!!blockVercel,blockBots:!!blockBots,indiaOnly:!!indiaOnly,
    ddosThreshold:parseInt(ddosThreshold)||60,autoPauseOnDdos:!!autoPauseOnDdos,
    enabled:true,ddosPaused:false,createdAt:new Date().toISOString()
  };
  write(DB.apis,apis);
  res.json({success:true,api:apis[id]});
});

admin.put('/apis/:id',(req,res)=>{
  const apis=read(DB.apis);
  if(!apis[req.params.id]) return res.status(404).json({success:false,message:'Not found'});
  const body={...req.body};
  if(body.hideFields&&typeof body.hideFields==='string')
    body.hideFields=body.hideFields.split(',').map(f=>f.trim()).filter(Boolean);
  apis[req.params.id]={...apis[req.params.id],...body};
  write(DB.apis,apis);
  res.json({success:true,api:apis[req.params.id]});
});

admin.patch('/apis/:id/toggle',(req,res)=>{
  const apis=read(DB.apis);
  if(!apis[req.params.id]) return res.status(404).json({success:false,message:'Not found'});
  apis[req.params.id].enabled=!apis[req.params.id].enabled;
  write(DB.apis,apis);
  res.json({success:true,enabled:apis[req.params.id].enabled});
});

admin.patch('/apis/:id/unpause',(req,res)=>{
  const apis=read(DB.apis);
  if(!apis[req.params.id]) return res.status(404).json({success:false,message:'Not found'});
  apis[req.params.id].ddosPaused=false;
  write(DB.apis,apis);
  tgSend(`✅ *API Resumed*\n${apis[req.params.id].name} is now active.`);
  res.json({success:true});
});

admin.delete('/apis/:id',(req,res)=>{
  const apis=read(DB.apis);
  delete apis[req.params.id];
  write(DB.apis,apis);
  res.json({success:true});
});

admin.get('/keys',(req,res)=>res.json({success:true,keys:read(DB.keys)}));

admin.post('/keys',(req,res)=>{
  const{label,keyType,customKey,validityType,validityValue,expiryDate,quota,dailyLimit,allowedTypes}=req.body;
  const keys=read(DB.keys);
  const apiKey=(keyType==='custom'&&customKey)?customKey:crypto.randomBytes(8).toString('hex').toUpperCase();
  if(keys[apiKey]) return res.status(400).json({success:false,message:'Key already exists'});
  let expiresAt=null;
  if(expiryDate){ expiresAt=new Date(expiryDate).toISOString(); }
  else if(validityType&&validityValue){
    const d=new Date();
    if(validityType==='days') d.setDate(d.getDate()+parseInt(validityValue));
    else if(validityType==='months') d.setMonth(d.getMonth()+parseInt(validityValue));
    expiresAt=d.toISOString();
  }
  const types=Array.isArray(allowedTypes)?allowedTypes:(allowedTypes?[allowedTypes]:[]);
  keys[apiKey]={
    key:apiKey,label:label||'User',expiresAt,
    quota:quota?parseInt(quota):null,dailyLimit:dailyLimit?parseInt(dailyLimit):null,
    allowedTypes:types,usedHits:0,dailyHits:0,
    lastResetDate:new Date().toDateString(),createdAt:new Date().toISOString(),lastUsed:null
  };
  write(DB.keys,keys);
  res.json({success:true,key:keys[apiKey]});
});

admin.delete('/keys/:key',(req,res)=>{
  const keys=read(DB.keys);
  delete keys[decodeURIComponent(req.params.key)];
  write(DB.keys,keys);
  res.json({success:true});
});

admin.get('/ips',(req,res)=>res.json({success:true,ips:(read(DB.ips).whitelist||[])}));

admin.post('/ips',(req,res)=>{
  const{ip,label}=req.body;
  if(!ip) return res.status(400).json({success:false,message:'IP required'});
  const data=read(DB.ips);
  if(!data.whitelist)data.whitelist=[];
  if(data.whitelist.some(e=>e.ip===ip))
    return res.status(400).json({success:false,message:'Already whitelisted'});
  data.whitelist.push({ip,label:label||'User',addedAt:new Date().toISOString()});
  write(DB.ips,data);
  res.json({success:true});
});

admin.delete('/ips/:ip',(req,res)=>{
  const data=read(DB.ips);
  data.whitelist=(data.whitelist||[]).filter(e=>e.ip!==decodeURIComponent(req.params.ip));
  write(DB.ips,data);
  res.json({success:true});
});

admin.get('/logs',(req,res)=>res.json({success:true,logs:read(DB.logs)}));
admin.delete('/logs',(req,res)=>{write(DB.logs,{});res.json({success:true});});

app.use('/admin',admin);

app.listen(PORT,()=>{
  console.log(`DARKXOSINT v2 running on port ${PORT}`);
});

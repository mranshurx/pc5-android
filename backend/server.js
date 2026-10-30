const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '1mb' }));
app.use(cors());

/* ================= STORAGE ================= */
const HARD = {
  owner:  'mranshurx',
  repo:   'pc5-android',
  branch: 'main',
  file:   'data/keys.json',
  token:  ''
};

const LOCAL_CFG = path.join(__dirname, 'github.json');
const REPO_CFG_PATH = 'data/config.json';

function envOverrides() {
  const o = {};
  if (process.env.GITHUB_OWNER) o.owner = process.env.GITHUB_OWNER;
  if (process.env.GITHUB_REPO) o.repo = process.env.GITHUB_REPO;
  if (process.env.GITHUB_BRANCH) o.branch = process.env.GITHUB_BRANCH;
  if (process.env.GITHUB_KEYS_PATH) o.file = process.env.GITHUB_KEYS_PATH;
  if (process.env.GITHUB_TOKEN) o.token = process.env.GITHUB_TOKEN.trim();
  return o;
}

let cfg = { ...HARD, ...envOverrides() };

function loadCfg() {
  try {
    if (fs.existsSync(LOCAL_CFG)) {
      const saved = JSON.parse(fs.readFileSync(LOCAL_CFG, 'utf8'));
      for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
        if (saved[k]) cfg[k] = String(saved[k]).trim();
      }
      console.log('[cfg] loaded from local github.json');
    }
  } catch (e) { console.warn('[cfg] could not read github.json:', e.message); }
}
function saveCfg() {
  try { fs.writeFileSync(LOCAL_CFG, JSON.stringify(cfg, null, 2)); }
  catch (e) { console.warn('[cfg] could not persist github.json:', e.message); }
}

/* Persist the storage config into the repo so it survives Render restarts. */
async function pushCfgToRepo(creds, snapshot) {
  const c = creds || cfg;
  const body = snapshot || cfg;
  if (!c.token) return;
  try {
    const url = `https://api.github.com/repos/${c.owner}/${c.repo}/contents/${REPO_CFG_PATH}`;
    const cur = await fetch(url, { headers: apiHeaders(c, false) });
    let sha = null;
    if (cur.ok) {
      const j = await cur.json().catch(() => ({}));
      sha = j.sha || null;
    }
    const put = {
      message: 'chore(cfg): update storage config',
      content: Buffer.from(JSON.stringify(body, null, 2), 'utf8').toString('base64'),
      branch: c.branch
    };
    if (sha) put.sha = sha;
    const r = await fetch(url, { method: 'PUT', headers: apiHeaders(c, true), body: JSON.stringify(put) });
    if (!r.ok) console.warn('[cfg] repo persist failed:', r.status);
    else console.log('[cfg] storage config mirrored to repo');
  } catch (e) { console.warn('[cfg] repo persist failed:', e.message); }
}

/* Restore the storage config from the repo when the disk copy is gone. */
let lastPull = 0;
async function pullCfgFromRepo() {
  if (cfg.token) return;
  if (Date.now() - lastPull < 20000) return;
  lastPull = Date.now();
  try {
    const raw = `https://raw.githubusercontent.com/${HARD.owner}/${HARD.repo}/${HARD.branch}/${REPO_CFG_PATH}?t=${Date.now()}`;
    const r = await fetch(raw, { headers: { 'User-Agent': 'pc5-android' } });
    if (!r.ok) return;
    const j = await r.json();
    for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
      if (j[k]) cfg[k] = String(j[k]).trim();
    }
    saveCfg();
    console.log('[cfg] storage config restored from repo');
  } catch (e) { console.warn('[cfg] repo restore failed:', e.message); }
}

/* Adopt a token supplied by the panel so client requests can write too. */
function adoptToken(req) {
  const t = req.body && req.body.gh && req.body.gh.token;
  if (!t || !String(t).trim()) return;
  const v = String(t).trim();
  if (v === cfg.token) return;
  cfg.token = v;
  saveCfg();
  pushCfgToRepo(cfg, cfg).catch(() => {});
}

function credsFrom(req) {
  const out = { ...cfg };
  const gh = (req.body && req.body.gh) || {};
  for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
    if (gh[k] && String(gh[k]).trim()) out[k] = String(gh[k]).trim();
  }
  if (!out.branch) out.branch = 'main';
  if (!out.file) out.file = 'data/keys.json';
  if (!out.owner) out.owner = HARD.owner;
  if (!out.repo) out.repo = HARD.repo;
  if (!out.token) out.token = HARD.token || process.env.GITHUB_TOKEN || '';
  out.token = out.token.trim();
  return out;
}
/* Token is deliberately NOT part of the signature: client and admin must share one cache. */
function sigOf(c) { return `${c.owner}/${c.repo}@${c.branch}:${c.file}`; }
function ready(c) { return !!(c.owner && c.repo); }

function tokenShape(t) {
  if (!t) return 'missing';
  if (t.startsWith('ghp_')) return t.length === 40 ? 'classic (looks valid)' : `classic but ${t.length} chars, expected 40`;
  if (t.startsWith('github_pat_')) return 'fine-grained';
  if (t.startsWith('gho_')) return 'oauth';
  return 'unknown prefix';
}

/* ================= ADMIN KEY (remote — no hardcoded secret) ================= */
const ADMIN_KEY_URL = process.env.ADMIN_KEY_URL ||
  'https://raw.githubusercontent.com/mranshurx/pc5-android/refs/heads/main/adminkey.txt';
const ADMIN_KEY_TTL = 30000;

let adminKeyState = { value: '', ver: '', at: 0 };

function parseAdminKey(raw) {
  const first = (raw || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean)[0] || '';
  let v = first.replace(/^[A-Za-z _-]{0,24}\s*[:=]\s*/, '');
  v = v.replace(/^["'`]+|["'`]+$/g, '').trim();
  return v;
}

function verOf(v) {
  return crypto.createHash('sha256').update(v).digest('hex').slice(0, 16);
}

async function getAdminKey(force) {
  const fresh = adminKeyState.value && Date.now() - adminKeyState.at < ADMIN_KEY_TTL;
  if (!force && fresh) return adminKeyState;

  try {
    const url = `${ADMIN_KEY_URL}${ADMIN_KEY_URL.includes('?') ? '&' : '?'}t=${Date.now()}`;
    const r = await fetch(url, {
      headers: { 'User-Agent': 'pc5-android', 'Cache-Control': 'no-cache' },
      cache: 'no-store'
    });
    if (!r.ok) throw new Error(`GET ${r.status}`);
    const value = parseAdminKey(await r.text());
    if (!value) throw new Error('empty key file');
    if (value !== adminKeyState.value) console.log(`[admin] key rotated -> ${verOf(value)}`);
    adminKeyState = { value, ver: verOf(value), at: Date.now() };
  } catch (e) {
    console.warn('[admin] key source unreachable:', e.message, '— using last known key');
  }
  return adminKeyState;
}

async function requireAdmin(req, res) {
  const state = await getAdminKey(false);
  if (!state.value) {
    res.status(503).json({ error: 'Admin key source unreachable. Try again shortly.' });
    return null;
  }
  const supplied = String((req.body && req.body.adminPass) || '').trim();
  if (supplied !== state.value) {
    res.status(401).json({ error: 'Invalid Admin Password.' });
    return null;
  }
  adoptToken(req);
  return state;
}

const HAPP_PROVIDER_ID = "";

const FRONTEND_DIR = fs.existsSync(path.join(__dirname, '..', 'frontend'))
  ? path.join(__dirname, '..', 'frontend')
  : path.join(__dirname, 'frontend');

const DEFAULT_MAINT = { enabled: false, message: 'System under maintenance.' };
const EMPTY_DB = () => ({ keys: [], maintenance: { ...DEFAULT_MAINT } });

/* ================= GITHUB API ================= */
function apiHeaders(c, json) {
  const h = {
    'User-Agent': 'pc5-android',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
  if (c.token) h.Authorization = `Bearer ${c.token}`;
  if (json) h['Content-Type'] = 'application/json';
  return h;
}

function ghPath(c) {
  return c.file.split('/').map(encodeURIComponent).join('/');
}

async function ghRead(c) {
  if (!ready(c)) return null;
  const encoded = ghPath(c);

  if (!c.token) {
    const raw = `https://raw.githubusercontent.com/${c.owner}/${c.repo}/${encodeURIComponent(c.branch)}/${encoded}?t=${Date.now()}`;
    const r = await fetch(raw, { headers: { 'User-Agent': 'pc5-android' } });
    if (r.status === 404) return { text: null, sha: null };
    if (!r.ok) throw new Error(`raw GET ${r.status}`);
    return { text: await r.text(), sha: null };
  }

  const url = `https://api.github.com/repos/${c.owner}/${c.repo}/contents/${encoded}?ref=${encodeURIComponent(c.branch)}`;
  const r = await fetch(url, { headers: apiHeaders(c, false) });
  if (r.status === 404) return { text: null, sha: null };
  if (r.status === 401) throw new Error('401 bad credentials — token revoked, expired, or mistyped. Classic tokens are auto-revoked when committed to a public repo.');
  if (r.status === 403) throw new Error('403 forbidden — token lacks Contents permission, or rate limit hit');
  if (!r.ok) throw new Error(`Storage GET ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json();
  return { text: Buffer.from(j.content || '', 'base64').toString('utf8'), sha: j.sha || null };
}

async function ghWriteOnce(c, text, sha, useBranch) {
  const encoded = ghPath(c);
  const body = {
    message: 'chore(keys): update license database',
    content: Buffer.from(text, 'utf8').toString('base64')
  };
  if (useBranch) body.branch = c.branch;
  if (sha) body.sha = sha;

  const r = await fetch(`https://api.github.com/repos/${c.owner}/${c.repo}/contents/${encoded}`, {
    method: 'PUT',
    headers: apiHeaders(c, true),
    body: JSON.stringify(body)
  });
  if (r.status === 409 || r.status === 422) {
    return { conflict: true, status: r.status, detail: (await r.text()).slice(0, 300) };
  }
  if (r.status === 401) throw new Error('401 bad credentials — token revoked, expired, or mistyped');
  if (r.status === 403) throw new Error('403 forbidden — token needs Contents: Read and write');
  if (!r.ok) throw new Error(`Storage PUT ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const j = await r.json().catch(() => ({}));
  return { ok: true, sha: (j.content && j.content.sha) || null };
}

async function ghWrite(c, text, sha) {
  if (!ready(c)) throw new Error('Storage not configured');

  /* A client request carries no token — recover the stored one before failing. */
  if (!c.token) {
    await pullCfgFromRepo();
    if (cfg.token) c = { ...c, token: cfg.token };
  }
  if (!c.token) throw new Error('No storage token — save one in the admin panel');

  let r = await ghWriteOnce(c, text, sha, true);

  if (r && r.conflict && r.status === 422) {
    console.warn('[gh] 422 with branch, retrying without it:', r.detail);
    r = await ghWriteOnce(c, text, sha, false);
  }
  return r;
}

/* ================= CACHE + SERIALIZED WRITES ================= */
let cache = { data: null, sha: null, at: 0, sig: '' };
const TTL = 5000;
let queue = Promise.resolve();
function enqueue(fn) { queue = queue.then(fn, fn); return queue; }

async function getDb(force, c) {
  c = c || cfg;
  if (!ready(c)) return EMPTY_DB();
  const sig = sigOf(c);

  if (!force && cache.data && cache.sig === sig && Date.now() - cache.at < TTL) return cache.data;

  const f = await ghRead(c);
  let db;
  try { db = f && f.text ? JSON.parse(f.text) : null; } catch (e) { db = null; }
  if (!db || typeof db !== 'object') db = EMPTY_DB();
  if (!Array.isArray(db.keys)) db.keys = [];
  if (!db.maintenance) db.maintenance = { ...DEFAULT_MAINT };
  db.keys.forEach(migrateRecord);

  cache = { data: db, sha: f ? f.sha : null, at: Date.now(), sig };
  return db;
}

async function putDb(db, c) {
  c = c || cfg;
  const text = JSON.stringify(db, null, 2);
  const sig = sigOf(c);
  return enqueue(async () => {
    let sha = (cache.sig === sig) ? cache.sha : null;
    if (!sha) {
      const f = await ghRead(c);
      sha = f ? f.sha : null;
    }
    let r = await ghWrite(c, text, sha);
    if (r && r.conflict) {
      const f = await ghRead(c);
      r = await ghWrite(c, text, f ? f.sha : null);
    }
    if (!r || !r.ok) throw new Error('Storage write failed');
    cache = { data: db, sha: r.sha, at: Date.now(), sig };
    return r;
  });
}

/* Work on a clone: if the write throws, the cache keeps the untouched source state
   and the next call retries cleanly instead of reading a half-applied mutation. */
async function mutate(c, fn) {
  const db = await getDb(true, c);
  const work = JSON.parse(JSON.stringify(db));
  const out = await fn(work);
  await putDb(work, c);
  return out;
}

/* ================= DURATION ================= */
function parseDuration(body) {
  body = body || {};
  if (body.days != null) {
    const d = Number(body.days);
    if (Number.isFinite(d) && d > 0) return Math.round(d * 24);
  }
  for (const field of ['durationHours', 'duration', 'hours']) {
    if (body[field] != null) {
      const n = Number(body[field]);
      if (Number.isFinite(n) && n > 0) return Math.round(n);
    }
  }
  console.warn('[duration] nothing usable in body — defaulting to 24h:', JSON.stringify(body));
  return 24;
}
function normalizeHours(h) {
  const n = Number(h);
  return (Number.isFinite(n) && n > 0) ? Math.round(n) : 24;
}

/* ================= DEVICE LIMIT ================= */
/* 0 = unlimited devices, 1 = single device (HWID locked on first unlock) */
function parseDeviceLimit(body) {
  body = body || {};
  const v = body.deviceLimit;
  if (v === 'single' || v === 'one' || v === '1' || v === 1) return 1;
  if (body.maxDevices != null) {
    const n = Number(body.maxDevices);
    if (n === 1) return 1;
  }
  return 0;
}

/* Normalize whatever the client sends into a compact id we can store safely. */
function deviceOf(req) {
  const raw = String(
    (req.query && (req.query.did || req.query.device || req.query.hwid)) ||
    req.headers['x-device-id'] || ''
  ).trim();
  return raw.replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 48);
}
function deviceUa(req) {
  return String((req.headers && req.headers['user-agent']) || '').slice(0, 200);
}

function migrateRecord(r) {
  if (r.durationHours == null) {
    const c = r.createdAt ? new Date(r.createdAt).getTime() : 0;
    const e = r.expiresAt ? new Date(r.expiresAt).getTime() : 0;
    const d = (e - c) / 3600000;
    r.durationHours = (d > 0 && Math.round(d) !== 24) ? Math.round(d) : 24;
  } else {
    r.durationHours = normalizeHours(r.durationHours);
  }
  if (r.startedAt == null) r.startedAt = r.activatedAt || null;
  if (r.expiresAt && !r.activatedAt) r.activatedAt = r.createdAt || new Date().toISOString();

  if (r.maxDevices == null) {
    r.maxDevices = (r.deviceLimit === 'single' || r.deviceLimit === 1 || r.deviceLimit === 'one') ? 1 : 0;
  }
  r.maxDevices = (Number(r.maxDevices) === 1) ? 1 : 0;
  r.deviceLimit = r.maxDevices === 1 ? 'single' : 'unlimited';
  if (!Array.isArray(r.devices)) r.devices = [];
  r.devices = r.devices
    .filter(d => d && d.id)
    .map(d => ({ id: String(d.id).slice(0, 48), firstSeen: d.firstSeen || null, lastSeen: d.lastSeen || null, ua: d.ua || '' }));
}

/* ================= KEY RESOLUTION ================= */
/* Binds the device on a single-device key the first time it is seen. */
async function bindDevice(c, key, did, ua) {
  return mutate(c, db => {
    const rec = db.keys.find(k => k.key === key);
    if (!rec) return null;
    if (!Array.isArray(rec.devices)) rec.devices = [];
    const now = new Date().toISOString();
    const known = rec.devices.find(d => d.id === did);
    if (known) {
      known.lastSeen = now;
      if (ua) known.ua = ua;
    } else if (rec.maxDevices === 1 && rec.devices.length === 0) {
      rec.devices.push({ id: did, firstSeen: now, lastSeen: now, ua: ua || '' });
      console.log(`[device] locked ${rec.key} -> ${did}`);
    }
    return rec;
  });
}

/*
  Returns { ok, reason, record }.
  reason: invalid | expired | no-device | device-mismatch
*/
async function accessKey(key, c, did, ua) {
  let db = await getDb(false, c);
  let r = db.keys.find(k => k.key === key);
  if (!r) return { ok: false, reason: 'invalid' };

  if (!r.activatedAt) {
    const now = Date.now();
    const hours = normalizeHours(r.durationHours);
    const startedAt = new Date(now).toISOString();
    const expiresAt = new Date(now + hours * 3600000).toISOString();
    const before = r;

    try {
      r = await mutate(c, fresh => {
        const rec = fresh.keys.find(k => k.key === key);
        if (!rec) return null;
        if (rec.activatedAt) return rec;
        rec.activatedAt = startedAt;
        rec.startedAt = startedAt;
        rec.durationHours = hours;
        rec.expiresAt = expiresAt;
        console.log(`[key] activated ${rec.key} -> ${rec.durationHours}h, expires ${rec.expiresAt}`);
        return rec;
      });
      if (!r) return { ok: false, reason: 'invalid' };
    } catch (e) {
      /* Never block the buyer on a storage hiccup — serve it in memory,
         the cache still holds the unactivated record so the next call retries. */
      console.warn('[key] activation write failed, serving in-memory:', e.message);
      r = { ...before, activatedAt: startedAt, startedAt, durationHours: hours, expiresAt };
    }
  }

  if (!r.expiresAt || Date.now() > new Date(r.expiresAt).getTime()) {
    return { ok: false, reason: 'expired', record: r };
  }

  if (r.maxDevices === 1) {
    if (!did) return { ok: false, reason: 'no-device', record: r };

    const bound = (r.devices || [])[0];
    if (bound && bound.id !== did) {
      return { ok: false, reason: 'device-mismatch', record: r };
    }

    if (!bound) {
      try {
        const updated = await bindDevice(c, key, did, ua);
        if (updated) r = updated;
        else r = { ...r, devices: [{ id: did, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), ua: ua || '' }] };
      } catch (e) {
        console.warn('[device] lock write failed, serving in-memory:', e.message);
        r = { ...r, devices: [{ id: did, firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), ua: ua || '' }] };
      }
    }
  }

  return { ok: true, record: r };
}

const REASON_TEXT = {
  'invalid': 'Invalid key.',
  'expired': 'Key has expired.',
  'no-device': 'Device could not be identified. Reopen the app.',
  'device-mismatch': 'This key is locked to another device.'
};

/* ================= ROUTING CONFIG ================= */
const BASE_CONFIG = {
  "remarks": "PC5 ANDROID [Secured]",
  "profile-update-interval": 1,
  "inbounds": [
    { "tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": { "auth": "noauth", "udp": true }, "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false } },
    { "tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": false } }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "hysteria",
      "settings": { "address": "wraith-bom.xreg.site", "port": 443, "version": 2 },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": { "serverName": "wraith-bom.xreg.site", "alpn": ["h3"] },
        "hysteriaSettings": { "version": 2, "auth": "XREG-E472-1EF2-8D79.1793018457.4f51e32b10e2a44595314baee488cb83" }
      }
    },
    { "tag": "direct", "protocol": "freedom" }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "domain": [
          "full:clientbp.ggpolarbear.com", "full:loginbp.ggpolarbear.com", "full:core-bs.ggpolarbear.com",
          "full:core-bs.freefiremobile.com", "full:core-tata.freefireind.in", "full:core-gmc.freefiremobile.com",
          "full:client.ind.freefiremobile.com", "full:client.us.freefiremobile.com", "full:sgnetwork.ggblueshark.com",
          "full:menetwork.ggblueshark.com", "full:bdnetwork.ggpolarbear.com", "full:100067.connect.garena.com",
          "full:100067.msdk.garena.com", "full:clientbp.ppmainecoonghj.com", "full:loginbp.ppmainecoonghj.com",
          "full:ffmconnect.ppmainecoonghj.com", "full:ffmmsdk.ppmainecoonghj.com",
          "regexp:^(clientbp|loginbp|core-[a-z0-9]+|[a-z]+network|ffmconnect|ffmmsdk)\\."
        ],
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "ip": [
          "0.0.0.0/24","101.32.114.0/23","101.33.44.0/22","102.204.191.0/24","102.217.238.0/24",
          "103.103.244.0/24","103.108.100.0/22","103.117.4.0/22","103.123.54.0/23","103.127.228.0/22",
          "103.16.32.0/22","103.215.127.0/24","103.219.200.0/22","103.237.102.0/23","103.247.204.0/22"
        ],
        "outboundTag": "proxy"
      },
      { "type": "field", "network": "tcp", "port": "39000-39999", "outboundTag": "proxy" },
      { "type": "field", "network": "udp", "port": "10000-10999", "outboundTag": "proxy" },
      {
        "type": "field",
        "domain": [
          "full:event-vodka.freefireind.in","full:indevent.ggblueshark.com","full:sgevent.ggblueshark.com",
          "full:meevent.ggblueshark.com","full:thevent.ggblueshark.com","full:sacevent.ggblueshark.com",
          "full:idevent.ggblueshark.com","full:bdevent.ggpolarbear.com","regexp:event\\.gg(blueshark|polarbear)\\.com$",
          "full:gin.freefireind.in","full:gin.freefiremobile.com","full:vodka.freefireind.in",
          "full:dl.castle.freefiremobile.com","full:dl.cdn.freefiremobile.com","full:dl-core.cdn.freefiremobile.com",
          "domain:freefiremobile-a.akamaihd.net","full:client.nulldash.store","full:client.xreg.site","full:client.silentx.store"
        ],
        "outboundTag": "direct"
      },
      { "type": "field", "network": "tcp,udp", "outboundTag": "direct" }
    ]
  }
};

const EXPIRED_CONFIG = {
  "remarks": "❌ SUBSCRIPTION EXPIRED OR TERMINATED",
  "profile-update-interval": 1,
  "inbounds": [],
  "outbounds": [{ "tag": "blocked", "protocol": "blackhole" }],
  "routing": { "rules": [] }
};

/* ================= HAPP LINK ================= */
const happLinkCache = new Map();
function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  return `${proto}://${req.get('host')}`;
}
function encryptHappLink(subUrl) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ url: subUrl });
    const req = https.request({
      hostname: 'crypto.happ.su', path: '/api-v2.php', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { const j = JSON.parse(data); resolve(j && j.encrypted_link ? j.encrypted_link : null); } catch (e) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(9000, () => { req.destroy(); resolve(null); });
    req.write(body); req.end();
  });
}

/* ================= PUBLIC API ================= */
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const db = await getDb(false, credsFrom(req));
    res.json(db.maintenance || DEFAULT_MAINT);
  } catch (e) {
    res.json(DEFAULT_MAINT);
  }
});

app.get('/api/happ-link', async (req, res) => {
  const { key } = req.query;
  if (!key) return res.json({ ok: false, reason: 'no-key' });
  try {
    const c = credsFrom(req);
    const did = deviceOf(req);
    const out = await accessKey(key, c, did, deviceUa(req));
    if (!out.ok) return res.json({ ok: false, reason: out.reason, message: REASON_TEXT[out.reason] });

    const subUrl = `${baseUrl(req)}/sub?key=${encodeURIComponent(key)}${did ? `&did=${encodeURIComponent(did)}` : ''}`;
    const cacheKey = `${key}|${did}`;
    if (happLinkCache.has(cacheKey)) return res.json({ ok: true, link: happLinkCache.get(cacheKey), raw: subUrl });
    const link = await encryptHappLink(subUrl);
    if (link) happLinkCache.set(cacheKey, link);
    return res.json({ ok: !!link, link: link || subUrl, raw: subUrl, encrypted: !!link });
  } catch (e) {
    return res.json({ ok: false, reason: 'storage-error', detail: e.message });
  }
});

app.get('/sub', async (req, res) => {
  res.setHeader('profile-update-interval', '1');
  res.setHeader('subscription-auto-update-enable', '1');
  res.setHeader('subscription-auto-update-open-enable', '1');
  res.setHeader('hide-settings', '1');
  if (HAPP_PROVIDER_ID) res.setHeader('providerid', HAPP_PROVIDER_ID);
  res.setHeader('content-disposition', 'attachment; filename="pc5-android"');
  res.setHeader('Content-Type', 'application/json');

  let targetConfig = BASE_CONFIG;
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;

    if (m.enabled) {
      targetConfig = { ...EXPIRED_CONFIG, remarks: `⚠️ MAINTENANCE: ${m.message}` };
    } else {
      const { key } = req.query;
      const did = deviceOf(req);
      const out = key ? await accessKey(key, c, did, deviceUa(req)) : { ok: false, reason: 'invalid' };
      if (!out.ok) {
        res.setHeader('x-pc5-status', out.reason);
        targetConfig = { ...EXPIRED_CONFIG, remarks: `❌ ${REASON_TEXT[out.reason] || 'SUBSCRIPTION EXPIRED OR TERMINATED'}` };
      } else {
        const expiresAt = new Date(out.record.expiresAt);
        res.setHeader('x-pc5-status', 'ok');
        res.setHeader('subscription-userinfo', `upload=0; download=0; total=107374182400; expire=${Math.floor(expiresAt.getTime() / 1000)}`);
      }
    }
  } catch (e) {
    targetConfig = EXPIRED_CONFIG;
  }

  return res.status(200).send(JSON.stringify(targetConfig));
});

app.get('/api/check-key', async (req, res) => {
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;
    if (m.enabled) return res.json({ valid: false, maintenance: true, message: m.message });

    const { key } = req.query;
    if (!key) return res.json({ valid: false, message: "Please enter an access key." });
    if (!db.keys.find(k => k.key === key)) return res.json({ valid: false, message: "Invalid key." });

    const out = await accessKey(key, c, deviceOf(req), deviceUa(req));
    if (!out.ok) {
      return res.json({ valid: false, reason: out.reason, message: REASON_TEXT[out.reason] || "Invalid key." });
    }

    const record = out.record;
    return res.json({
      valid: true,
      key: record.key,
      startedAt: record.startedAt || record.activatedAt,
      activatedAt: record.activatedAt,
      expiresAt: record.expiresAt,
      durationHours: record.durationHours,
      remainingMs: new Date(record.expiresAt).getTime() - Date.now(),
      deviceLimit: record.maxDevices === 1 ? 'single' : 'unlimited',
      deviceLocked: record.maxDevices === 1 && (record.devices || []).length > 0,
      deviceCount: (record.devices || []).length,
      message: "Access Key Validated!"
    });
  } catch (e) {
    return res.json({ valid: false, message: "Storage error: " + e.message });
  }
});

/* ================= ADMIN ================= */
app.post('/api/admin/login', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  return res.json({ success: true, ver: state.ver });
});

app.post('/api/admin/verify', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  return res.json({ success: true, ver: state.ver });
});

app.post('/api/admin/diag', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const c = credsFrom(req);
  const info = {
    storage: 'github',
    owner: c.owner,
    repo: c.repo,
    branch: c.branch,
    file: c.file,
    tokenSet: !!c.token,
    tokenLength: c.token ? c.token.length : 0,
    tokenShape: tokenShape(c.token),
    tokenSource: process.env.GITHUB_TOKEN && c.token === process.env.GITHUB_TOKEN.trim()
      ? 'env GITHUB_TOKEN'
      : (c.token === HARD.token ? 'hardcoded' : 'panel override'),
    adminKeyVer: state.ver
  };

  try {
    const f = await ghRead(c);
    info.reachable = true;
    info.fileExists = f ? f.text !== null : false;
    if (f && f.text) {
      try { info.keys = JSON.parse(f.text).keys.length; } catch (e) { info.keys = 'unparsable JSON'; }
    } else {
      info.keys = 0;
    }
    info.hint = 'Read OK. If writes fail, the token needs Contents: Read and write.';
  } catch (e) {
    info.reachable = false;
    info.error = e.message;
    info.hint = 'Read failed. 401 = token dead or mistyped. 403 = permissions. 404 = wrong owner/repo/path/branch.';
  }
  return res.json(info);
});

app.post('/api/admin/github-config', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const incoming = req.body.gh || {};
  const next = { ...cfg };
  for (const k of ['owner', 'repo', 'branch', 'file', 'token']) {
    if (incoming[k] && String(incoming[k]).trim()) next[k] = String(incoming[k]).trim();
  }

  try {
    const f = await ghRead(next);
    if (f && f.text === null) {
      await ghWrite(next, JSON.stringify(EMPTY_DB(), null, 2), null);
    }
  } catch (e) {
    return res.status(400).json({ success: false, error: e.message });
  }

  cfg = next;
  saveCfg();
  cache = { data: null, sha: null, at: 0, sig: '' };
  console.log(`[cfg] storage set to ${cfg.owner}/${cfg.repo}:${cfg.file}`);
  await pushCfgToRepo(cfg, cfg);
  return res.json({ success: true, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch, file: cfg.file, persisted: true });
});

app.post('/api/admin/github-reset', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const prev = { ...cfg };
  cfg = { ...HARD, ...envOverrides() };
  try { fs.unlinkSync(LOCAL_CFG); } catch (e) {}
  cache = { data: null, sha: null, at: 0, sig: '' };
  console.log('[cfg] reset to hardcoded repo + env token');
  if (prev.token) await pushCfgToRepo(prev, { ...cfg, token: '' });
  return res.json({ success: true, owner: cfg.owner, repo: cfg.repo, branch: cfg.branch, file: cfg.file });
});

app.post('/api/admin/github-test', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const c = credsFrom(req);
  try {
    const f = await ghRead(c);
    if (f && f.text === null) {
      const w = await ghWrite(c, JSON.stringify(EMPTY_DB(), null, 2), null);
      if (!w.ok) return res.json({ success: false, error: 'read ok, write failed' });
      cache = { data: null, sha: null, at: 0, sig: '' };
      return res.json({ success: true, created: true, keys: 0, writable: true });
    }
    const db = await getDb(true, c);
    return res.json({ success: true, keys: db.keys.length, writable: !!c.token });
  } catch (e) {
    return res.json({ success: false, error: e.message });
  }
});

app.post('/api/admin/create-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;

  const { startNow } = req.body;
  const c = credsFrom(req);
  const durationHours = parseDuration(req.body);
  const maxDevices = parseDeviceLimit(req.body);
  console.log('[create-key] body =', JSON.stringify(req.body), '=> durationHours =', durationHours, 'maxDevices =', maxDevices);

  try {
    const record = await mutate(c, db => {
      let key;
      do { key = "PC5-" + Math.random().toString(36).substring(2, 8).toUpperCase(); }
      while (db.keys.find(k => k.key === key));

      const now = Date.now();
      const started = !!startNow;
      const rec = {
        key,
        durationHours,
        maxDevices,
        deviceLimit: maxDevices === 1 ? 'single' : 'unlimited',
        devices: [],
        createdAt: new Date(now).toISOString(),
        startedAt: started ? new Date(now).toISOString() : null,
        activatedAt: started ? new Date(now).toISOString() : null,
        expiresAt: started ? new Date(now + durationHours * 3600000).toISOString() : null
      };
      db.keys.push(rec);
      return rec;
    });
    return res.json({ success: true, record, durationHours, maxDevices });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/list-keys', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  try {
    const db = await getDb(true, credsFrom(req));
    const keys = [...db.keys].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    return res.json({ keys, maintenance: db.maintenance });
  } catch (e) {
    return res.status(500).json({ error: "Read failed: " + e.message, keys: [] });
  }
});

app.post('/api/admin/revoke-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);

  try {
    await mutate(c, db => {
      const idx = db.keys.findIndex(k => k.key === key);
      if (idx >= 0) db.keys.splice(idx, 1);
    });
    for (const k of [...happLinkCache.keys()]) if (k.startsWith(key + '|')) happLinkCache.delete(k);
    return res.json({ success: true, message: `Key ${key} revoked.` });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/repair-key', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);
  const durationHours = parseDuration(req.body);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.durationHours = durationHours;
      r.activatedAt = null;
      r.startedAt = null;
      r.expiresAt = null;
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    for (const k of [...happLinkCache.keys()]) if (k.startsWith(key + '|')) happLinkCache.delete(k);
    return res.json({ success: true, record: rec, durationHours });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* Clears the bound device so a single-device key can be used elsewhere. */
app.post('/api/admin/reset-device', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.devices = [];
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    for (const k of [...happLinkCache.keys()]) if (k.startsWith(key + '|')) happLinkCache.delete(k);
    return res.json({ success: true, message: `Device lock cleared for ${key}.` });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* Flips an existing key between unlimited and single-device. */
app.post('/api/admin/set-device-limit', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { key } = req.body;
  const c = credsFrom(req);
  const maxDevices = parseDeviceLimit(req.body);

  try {
    const rec = await mutate(c, db => {
      const r = db.keys.find(k => k.key === key);
      if (!r) return null;
      r.maxDevices = maxDevices;
      r.deviceLimit = maxDevices === 1 ? 'single' : 'unlimited';
      if (maxDevices === 0) r.devices = [];
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
    for (const k of [...happLinkCache.keys()]) if (k.startsWith(key + '|')) happLinkCache.delete(k);
    return res.json({ success: true, record: rec, maxDevices });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

app.post('/api/admin/maintenance', async (req, res) => {
  const state = await requireAdmin(req, res);
  if (!state) return;
  const { enabled, message } = req.body;
  const c = credsFrom(req);

  try {
    const m = await mutate(c, db => {
      db.maintenance = { enabled: !!enabled, message: message || "System under maintenance." };
      return db.maintenance;
    });
    return res.json({ success: true, maintenance: m });
  } catch (e) {
    return res.status(500).json({ error: "Write failed: " + e.message });
  }
});

/* ================= FRONTEND ================= */
app.get('/admin', (req, res) => res.sendFile(path.join(FRONTEND_DIR, 'admin.html')));
app.use(express.static(FRONTEND_DIR));

/* ================= BOOT ================= */
const PORT = process.env.PORT || 3000;

(async () => {
  loadCfg();
  await pullCfgFromRepo();
  app.listen(PORT, () => {
    console.log(`Server active on port ${PORT}`);
    console.log(`[cfg] storage -> ${cfg.owner}/${cfg.repo}:${cfg.file}`);
    console.log(`[cfg] token -> ${tokenShape(cfg.token)}`);
    console.log(`[admin] key source -> ${ADMIN_KEY_URL}`);
    getAdminKey(true);
  });
})();

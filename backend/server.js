const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
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
  'https://raw.githubusercontent.com/mranshurx/new-engine/refs/heads/main/key.txt';
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

const FRONTEND_DIR = fs.existsSync(path.join(__dirname, '..', 'frontend'))
  ? path.join(__dirname, '..', 'frontend')
  : path.join(__dirname, 'frontend');

const DEFAULT_MAINT = { enabled: false, message: 'System under maintenance.', since: null };
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
  if (!('since' in db.maintenance)) db.maintenance.since = null;
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

/* ================= MAINTENANCE CLOCK ================= */
/*
  Wall time spent in maintenance is never charged to the buyer. Two halves:

  - live  : effectiveExpiry() adds the *running* maintenance window on the fly,
            so no key reads as expired while the pause is in progress.
  - settle: when maintenance is switched off the window is written into every
            key's expiresAt, so the credit survives restarts and later reads.

  Only the overlap between the pause and the key's own active span is credited,
  so a key that was already dead before maintenance started gets nothing, and a
  key sold *during* maintenance only gets credited from its activation.
*/

function maintStart(db) {
  const m = (db && db.maintenance) || {};
  if (!m.enabled || !m.since) return null;
  const t = new Date(m.since).getTime();
  return Number.isFinite(t) ? t : null;
}

function effectiveExpiry(rec, since) {
  if (!rec || !rec.expiresAt) return null;
  const exp = new Date(rec.expiresAt).getTime();
  if (!Number.isFinite(exp)) return null;
  if (!since) return exp;
  const act = rec.activatedAt ? new Date(rec.activatedAt).getTime() : since;
  const from = Math.max(since, Number.isFinite(act) ? act : since);
  if (from >= exp) return exp;
  return exp + (Date.now() - from);
}

function settleMaintenance(db, startMs, endMs) {
  let credited = 0;
  for (const rec of db.keys) {
    if (!rec.expiresAt) continue;
    const exp = new Date(rec.expiresAt).getTime();
    if (!Number.isFinite(exp)) continue;
    const act = rec.activatedAt ? new Date(rec.activatedAt).getTime() : startMs;
    const from = Math.max(startMs, Number.isFinite(act) ? act : startMs);
    const to = Math.min(endMs, exp);
    const credit = to - from;
    if (credit <= 0) continue;
    rec.expiresAt = new Date(exp + credit).toISOString();
    rec.maintenancePausedMs = (Number(rec.maintenancePausedMs) || 0) + credit;
    credited++;
  }
  return credited;
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

  /* Test against the paused clock, not the raw stamp, so a key cannot die
     while the service is down. */
  const expMs = effectiveExpiry(r, maintStart(db));
  if (expMs == null || Date.now() > expMs) {
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

/* ================= ROUTING SOURCE =================
   Upstream: dripwire India, Hysteria2.
   Tester endpoints and game traffic go through the proxy so the client can
   measure a real latency; CDN and event hosts stay direct; catch-all is proxy.

   Kept as prefix-tagged strings ('full:', 'domain:', 'regexp:') so the three
   output formats below can all be generated from one source of truth.
*/
const NODE_HOST = 'proxy-ind.dripwire.cc';
const NODE_PORT = 443;
const NODE_AUTH = '2292878901';
const PROFILE_TITLE = 'PC5 ANDROID';

/* Auth handed to the node while the key is dead. The server rejects it, so the
   QUIC handshake dies and the client reports a genuine failure. */
const DEAD_AUTH = 'PC5-BLOCKED';

const PROXY_HOSTS = [
  'full:cp.cloudflare.com', 'domain:cloudflare.com', 'full:connectivitycheck.gstatic.com',
  'full:www.gstatic.com', 'domain:gstatic.com', 'full:www.google.com', 'domain:google.com',
  'domain:googleapis.com', 'domain:gvt1.com', 'domain:gvt2.com', 'domain:googleusercontent.com',
  'full:time.android.com', 'domain:whatsapp.net', 'domain:facebook.com', 'domain:instagram.com',
  'domain:youtube.com', 'domain:ggpht.com'
];

const PROXY_GAME_HOSTS = [
  'full:clientbp.ggpolarbear.com', 'full:loginbp.ggpolarbear.com', 'full:core-bs.ggpolarbear.com',
  'full:core-bs.freefiremobile.com', 'full:core-tata.freefireind.in', 'full:core-gmc.freefiremobile.com',
  'full:client.ind.freefiremobile.com', 'full:client.us.freefiremobile.com', 'full:sgnetwork.ggblueshark.com',
  'full:menetwork.ggblueshark.com', 'full:bdnetwork.ggpolarbear.com', 'full:100067.connect.garena.com',
  'full:100067.msdk.garena.com', 'full:clientbp.ppmainecoonghj.com', 'full:loginbp.ppmainecoonghj.com',
  'full:ffmconnect.ppmainecoonghj.com', 'full:ffmmsdk.ppmainecoonghj.com',
  'regexp:^(clientbp|loginbp|core-[a-z0-9]+|[a-z]+network|ffmconnect|ffmmsdk)\\.'
];

const PROXY_IPS = [
  '101.32.114.0/23', '101.33.44.0/22', '102.204.191.0/24', '102.217.238.0/24',
  '103.103.244.0/24', '103.108.100.0/22', '103.117.4.0/22', '103.123.54.0/23',
  '103.127.228.0/22', '103.16.32.0/22', '103.215.127.0/24', '103.219.200.0/22',
  '103.237.102.0/23', '103.247.204.0/22'
];

const DIRECT_HOSTS = [
  'full:event-vodka.freefireind.in', 'full:indevent.ggblueshark.com', 'full:sgevent.ggblueshark.com',
  'full:meevent.ggblueshark.com', 'full:thevent.ggblueshark.com', 'full:sacevent.ggblueshark.com',
  'full:idevent.ggblueshark.com', 'full:bdevent.ggpolarbear.com', 'regexp:event\\.gg(blueshark|polarbear)\\.com$',
  'full:gin.freefireind.in', 'full:gin.freefiremobile.com', 'full:vodka.freefireind.in',
  'full:dl.castle.freefiremobile.com', 'full:dl.cdn.freefiremobile.com', 'full:dl-core.cdn.freefiremobile.com',
  'domain:freefiremobile-a.akamaihd.net'
];

const TCP_GAME_PORTS = '39000:39999';
const UDP_GAME_PORTS = '10000:10999';

/* sing-box accepts the same prefixes, but spells regex as 'regex:'. */
function sbHost(item) { return item.replace(/^regexp:/, 'regex:'); }

/* Clash spells the prefixes as rule types. */
function clashHost(item) {
  if (item.startsWith('full:')) return 'DOMAIN,' + item.slice(5);
  if (item.startsWith('domain:')) return 'DOMAIN-SUFFIX,' + item.slice(7);
  if (item.startsWith('regexp:')) return 'DOMAIN-REGEX,' + item.slice(7);
  return 'DOMAIN-SUFFIX,' + item;
}

/* ================= PROFILE BUILDERS ================= */

/*
  Every format keeps the node present while the key is dead, so the client always
  renders a profile instead of an empty file. A blackhole outbound is NOT used:
  it accepts the local socket and only then discards the payload, so the handshake
  never leaves the device and the client prints a fake ~0ms ping on a dead key.
  Instead the node keeps its name and gets a rejected auth, and routing is
  collapsed onto it, so ping fails for real (N/A).
*/

function singboxProfile(blocked, remarks) {
  const outbounds = [
    {
      type: 'hysteria2',
      tag: 'proxy',
      server: NODE_HOST,
      server_port: NODE_PORT,
      password: blocked ? DEAD_AUTH : NODE_AUTH,
      tls: {
        enabled: true,
        server_name: NODE_HOST,
        alpn: ['h3']
      }
    },
    { type: 'direct', tag: 'direct' },
    { type: 'block', tag: 'block' }
  ];

  const rules = [];
  if (!blocked) {
    rules.push({ domain: [...PROXY_HOSTS, ...PROXY_GAME_HOSTS].map(sbHost), outbound: 'proxy' });
    rules.push({ ip_cidr: PROXY_IPS, outbound: 'proxy' });
    rules.push({ network: 'tcp', port_range: TCP_GAME_PORTS, outbound: 'proxy' });
    rules.push({ network: 'udp', port_range: UDP_GAME_PORTS, outbound: 'proxy' });
    rules.push({ domain: DIRECT_HOSTS.map(sbHost), outbound: 'direct' });
  }

  return {
    log: { level: 'warn', timestamp: true },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true,
        sniff_override_destination: false
      }
    ],
    outbounds,
    route: {
      rules,
      final: 'proxy',
      auto_detect_interface: true
    },
    experimental: {
      cache_file: { enabled: true }
    }
  };
}

function clashProfile(blocked, remarks) {
  const lines = [
    '# ' + (remarks || PROFILE_TITLE),
    'mixed-port: 2080',
    'allow-lan: false',
    'mode: rule',
    'log-level: info',
    'ipv6: false',
    'proxies:',
    `  - name: "${PROFILE_TITLE}"`,
    '    type: hysteria2',
    `    server: ${NODE_HOST}`,
    `    port: ${NODE_PORT}`,
    `    password: "${blocked ? DEAD_AUTH : NODE_AUTH}"`,
    `    sni: ${NODE_HOST}`,
    '    alpn:',
    '      - h3',
    '    skip-cert-verify: false',
    'proxy-groups:',
    '  - name: PROXY',
    '    type: select',
    '    proxies:',
    `      - "${PROFILE_TITLE}"`,
    'rules:'
  ];

  if (!blocked) {
    [...PROXY_HOSTS, ...PROXY_GAME_HOSTS].forEach(h => lines.push('  - ' + clashHost(h) + ',PROXY'));
    PROXY_IPS.forEach(ip => lines.push('  - IP-CIDR,' + ip + ',PROXY,no-resolve'));
    lines.push(`  - DST-PORT,${TCP_GAME_PORTS.replace(':', '-')},PROXY`);
    lines.push(`  - DST-PORT,${UDP_GAME_PORTS.replace(':', '-')},PROXY`);
    DIRECT_HOSTS.forEach(h => lines.push('  - ' + clashHost(h) + ',DIRECT'));
  }

  lines.push('  - MATCH,PROXY');
  return lines.join('\n') + '\n';
}

function base64Profile(blocked) {
  const auth = blocked ? DEAD_AUTH : NODE_AUTH;
  const uri =
    `hysteria2://${encodeURIComponent(auth)}@${NODE_HOST}:${NODE_PORT}` +
    `?sni=${encodeURIComponent(NODE_HOST)}&alpn=h3#${encodeURIComponent(PROFILE_TITLE)}`;
  return Buffer.from(uri + '\n', 'utf8').toString('base64');
}

/* ================= SUB LINK ================= */
function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  return `${proto}://${req.get('host')}`;
}

/* Hiddify wants a plain https subscription URL; it fetches the profile itself. */
function subUrlFor(req, key, did, format) {
  const qs = new URLSearchParams();
  qs.set('key', key);
  if (did) qs.set('did', did);
  if (format) qs.set('format', format);
  return `${baseUrl(req)}/sub?${qs.toString()}`;
}

/* hiddify://import/<sublink>#name — the app reads the URL out of the path. */
function hiddifyDeepLink(subUrl) {
  return `hiddify://import/${encodeURIComponent(subUrl)}#${encodeURIComponent(PROFILE_TITLE)}`;
}

const FORMATS = new Set(['singbox', 'clash', 'base64']);

/* ================= PUBLIC API ================= */
app.get('/api/maintenance-status', async (req, res) => {
  try {
    const db = await getDb(false, credsFrom(req));
    const m = { ...DEFAULT_MAINT, ...(db.maintenance || {}) };
    const since = maintStart(db);
    if (since) m.pausedMs = Math.max(0, Date.now() - since);
    res.json(m);
  } catch (e) {
    res.json(DEFAULT_MAINT);
  }
});

app.get('/api/sub-link', async (req, res) => {
  const { key } = req.query;
  if (!key) return res.json({ ok: false, reason: 'no-key' });
  try {
    const c = credsFrom(req);
    const did = deviceOf(req);
    const out = await accessKey(key, c, did, deviceUa(req));
    if (!out.ok) return res.json({ ok: false, reason: out.reason, message: REASON_TEXT[out.reason] });

    const raw = subUrlFor(req, key, did, 'singbox');
    return res.json({ ok: true, link: hiddifyDeepLink(raw), raw });
  } catch (e) {
    return res.json({ ok: false, reason: 'storage-error', detail: e.message });
  }
});

/* Old path kept so an older cached page keeps working. */
app.get('/api/happ-link', (req, res) => {
  req.url = '/api/sub-link' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  app.handle(req, res);
});

app.get('/sub', async (req, res) => {
  const format = FORMATS.has(String(req.query.format)) ? String(req.query.format) : 'singbox';

  res.setHeader('profile-update-interval', '1');
  res.setHeader('profile-title', PROFILE_TITLE);
  res.setHeader('subscription-auto-update-enable', '1');
  res.setHeader('subscription-auto-update-open-enable', '1');
  res.setHeader('hide-settings', '1');
  res.setHeader('cache-control', 'no-store');
  if (format === 'singbox') res.setHeader('Content-Type', 'application/json; charset=utf-8');
  else if (format === 'clash') res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
  else res.setHeader('Content-Type', 'text/plain; charset=utf-8');

  let body;
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;

    if (m.enabled) {
      res.setHeader('x-pc5-status', 'maintenance');
      body = render(format, true, `⚠️ MAINTENANCE: ${m.message}`);
    } else {
      const { key } = req.query;
      const did = deviceOf(req);
      const out = key ? await accessKey(key, c, did, deviceUa(req)) : { ok: false, reason: 'invalid' };
      if (!out.ok) {
        res.setHeader('x-pc5-status', out.reason);
        body = render(format, true, `❌ ${REASON_TEXT[out.reason] || 'SUBSCRIPTION EXPIRED OR TERMINATED'}`);
      } else {
        /* Advertised expiry uses the paused clock so the date does not creep
           forward in the client while the service is down. */
        const liveExpiry = effectiveExpiry(out.record, maintStart(db));
        res.setHeader('x-pc5-status', 'ok');
        res.setHeader('subscription-userinfo', `upload=0; download=0; total=107374182400; expire=${Math.floor(liveExpiry / 1000)}`);
        body = render(format, false, PROFILE_TITLE);
      }
    }
  } catch (e) {
    res.setHeader('x-pc5-status', 'storage-error');
    body = render(format, true, '❌ SUBSCRIPTION EXPIRED OR TERMINATED');
  }

  return res.status(200).send(body);
});

function render(format, blocked, remarks) {
  if (format === 'clash') return clashProfile(blocked, remarks);
  if (format === 'base64') return base64Profile(blocked);
  return JSON.stringify(singboxProfile(blocked, remarks));
}

app.get('/api/check-key', async (req, res) => {
  try {
    const c = credsFrom(req);
    const db = await getDb(false, c);
    const m = db.maintenance || DEFAULT_MAINT;
    const since = maintStart(db);
    const { key } = req.query;

    if (!key) {
      return res.json({
        valid: false,
        maintenance: !!m.enabled,
        message: m.enabled ? m.message : "Please enter an access key."
      });
    }

    const known = db.keys.find(k => k.key === key);
    if (!known) {
      return res.json({ valid: false, maintenance: !!m.enabled, message: m.enabled ? m.message : "Invalid key." });
    }

    const out = await accessKey(key, c, deviceOf(req), deviceUa(req));
    const record = out.record || known;
    const expMs = effectiveExpiry(record, since);
    const remainingMs = expMs == null ? null : Math.max(0, expMs - Date.now());

    const payload = {
      key: record.key,
      startedAt: record.startedAt || record.activatedAt,
      activatedAt: record.activatedAt,
      expiresAt: record.expiresAt,
      durationHours: record.durationHours,
      remainingMs,
      deviceLimit: record.maxDevices === 1 ? 'single' : 'unlimited',
      deviceLocked: record.maxDevices === 1 && (record.devices || []).length > 0,
      deviceCount: (record.devices || []).length
    };

    /* Maintenance still reports the key as good and hands over a frozen
       remainingMs, so the countdown holds instead of draining to zero. */
    if (m.enabled) {
      return res.json({
        ...payload,
        valid: out.ok,
        maintenance: true,
        paused: true,
        pausedMs: since ? Math.max(0, Date.now() - since) : 0,
        message: m.message
      });
    }

    if (!out.ok) {
      return res.json({
        ...payload,
        valid: false,
        reason: out.reason,
        message: REASON_TEXT[out.reason] || "Invalid key."
      });
    }

    return res.json({ ...payload, valid: true, message: "Access Key Validated!" });
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
      r.maintenancePausedMs = 0;
      return r;
    });
    if (!rec) return res.status(404).json({ error: "Key not found." });
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
      const prev = db.maintenance || DEFAULT_MAINT;
      const nowMs = Date.now();
      const wantOn = !!enabled;
      const msg = message || prev.message || 'System under maintenance.';

      if (wantOn) {
        /* `since` is stamped once and kept — repeated saves while already on
           must not restart the window or the earlier minutes get refunded twice. */
        db.maintenance = {
          enabled: true,
          message: msg,
          since: prev.enabled ? (prev.since || new Date(nowMs).toISOString()) : new Date(nowMs).toISOString()
        };
        return db.maintenance;
      }

      if (prev.enabled) {
        const raw = prev.since ? new Date(prev.since).getTime() : nowMs;
        const start = Number.isFinite(raw) ? Math.min(raw, nowMs) : nowMs;
        const credited = settleMaintenance(db, start, nowMs);
        db.maintenance = {
          enabled: false,
          message: msg,
          since: null,
          lastPausedMs: Math.max(0, nowMs - start),
          lastPausedKeys: credited,
          lastEndedAt: new Date(nowMs).toISOString()
        };
        console.log(`[maint] resumed — credited ${credited} key(s) for ${Math.round((nowMs - start) / 1000)}s`);
        return db.maintenance;
      }

      db.maintenance = { enabled: false, message: msg, since: null };
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
process.on('unhandledRejection', (e) => {
  console.warn('[unhandledRejection]', (e && e.message) || e);
});
process.on('uncaughtException', (e) => {
  console.warn('[uncaughtException]', (e && e.stack) || e);
});

const PORT = process.env.PORT || 3000;

(async () => {
  loadCfg();
  await pullCfgFromRepo();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server active on port ${PORT}`);
    console.log(`[cfg] storage -> ${cfg.owner}/${cfg.repo}:${cfg.file}`);
    console.log(`[cfg] token -> ${tokenShape(cfg.token)}`);
    console.log(`[admin] key source -> ${ADMIN_KEY_URL}`);
    console.log(`[node] ${NODE_HOST}:${NODE_PORT} hysteria2`);
    getAdminKey(true);
  });
})();

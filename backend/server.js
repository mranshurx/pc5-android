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

/*
  Provider ID — REQUIRED for every advanced parameter, including hide-settings.
  Get one free at https://happ-proxy.com (top-right of the dashboard) and put it
  here or in the HAPP_PROVIDER_ID env var. Without it Happ ignores hide-settings
  and the user can open the profile and read the raw JSON.
*/
const HAPP_PROVIDER_ID = (process.env.HAPP_PROVIDER_ID || '').trim();

const FRONTEND_DIR = fs.existsSync(path.join(__dirname, '..', 'frontend'))
  ? path.join(__dirname, '..', 'frontend')
  : path.join(__dirname, 'frontend');

const DEFAULT_MAINT = { enabled: false, message: 'System under maintenance.', since: null };
const EMPTY_FEATURES = { aimbot: '', location: '' };
const EMPTY_DB = () => ({ keys: [], maintenance: { ...DEFAULT_MAINT }, features: { ...EMPTY_FEATURES } });

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
  if (!db.features || typeof db.features !== 'object') db.features = { ...EMPTY_FEATURES };
  if (typeof db.features.aimbot !== 'string') db.features.aimbot = '';
  if (typeof db.features.location !== 'string') db.features.location = '';
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

/* ================= ROUTING CONFIG ================= */
/*
  Upstream: DRIPWIRE India — Hysteria2 over TLS (h3/QUIC), port 443.
  Delivered as a full Xray/Happ JSON config rather than a share link, so the
  client gets the local SOCKS/HTTP inbounds and the split routing table with it.
  Port-based routing keeps only the Free Fire game ranges on the tunnel;
  per-app proxy (response headers) limits which packages get captured at all.
*/
const DEFAULT_HYST_AUTH = '6914422730:ca0a93b7b5698e52';
const HYST_HOST = 'proxy-ind.dripwire.cc';
const HYST_PORT = 443;
const PROFILE_NAME = 'PC5';

/* Auth handed to the node while the key is dead. The server rejects it, so the
   handshake dies and the client reports a genuine failure instead of a fake ping. */
const DEAD_AUTH = 'PC5-BLOCKED:0';

const PER_APP_LIST = 'com.garena.game.ffi,com.dts.freefiremax';

/* Builds a fresh config object every call — never mutates a shared template. */
function buildConfig(blocked, label, auth, host, port) {
  const addr = host || HYST_HOST;
  const prt = Number(port) || HYST_PORT;
  const cred = blocked ? DEAD_AUTH : (auth || DEFAULT_HYST_AUTH);

  return {
    remarks: label,
    inbounds: [
      {
        listen: '127.0.0.1',
        port: 10808,
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true },
        sniffing: { destOverride: ['http', 'tls', 'quic'], enabled: true, routeOnly: false },
        tag: 'socks'
      },
      {
        listen: '127.0.0.1',
        port: 10809,
        protocol: 'http',
        sniffing: { destOverride: ['http', 'tls', 'quic'], enabled: true, routeOnly: false },
        tag: 'http'
      }
    ],
    outbounds: [
      {
        protocol: 'hysteria',
        settings: { address: addr, port:

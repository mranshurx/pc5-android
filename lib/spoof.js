'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SHARED_AUTH = 'XREG-E472-1EF2-8D79.1793018457.4f51e32b10e2a44595314baee488cb83';
const STORE = path.join(__dirname, '..', 'data', 'warp.json');
const API = 'https://api.cloudflareclient.com/v0a2158/reg';
const HDRS = {
  'CF-Client-Version': 'a-6.11-2223',
  'User-Agent': 'okhttp/3.12.1',
  'Content-Type': 'application/json'
};
const BODY = {
  install_id: '', fcm_token: '', tos: '2021-09-14T17:30:26.000+00:00',
  model: 'PC', serial_number: '', locale: 'en_US'
};

/* Cloudflare WARP ingress. Anycast, so a fixed IP always lands on the nearest
   colo — beats the random peer the registration API returns (changes every
   restart, often on the far side of the planet). Override with
   WARP_ENDPOINT=host:port, comma separated to try alternatives in order. */
const PINNED = (process.env.WARP_ENDPOINT || '162.159.192.1:2408')
  .split(',').map(s => s.trim()).filter(Boolean);

const MTU = Number(process.env.WARP_MTU || 1280) || 1280;
const KEEPALIVE = Number(process.env.WARP_KEEPALIVE || 25) || 25;
const OFF = String(process.env.WARP_OFF || '') === '1';
const REG_TIMEOUT = Number(process.env.WARP_REG_TIMEOUT || 10000) || 10000;

/* Handles "host:port", "1.2.3.4:2408" and bracketed/raw IPv6
   ("[2606:4700::1]:2408", "2606:4700::1:2408"). */
function parseEp(ep) {
  const s = String(ep || '').trim();
  if (!s) return { host: '162.159.192.1', port: 2408 };
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close > 0) {
      const host = s.slice(1, close);
      const port = Number(s.slice(close + 1).replace(/^:/, '')) || 2408;
      return { host, port };
    }
  }
  const colon = s.lastIndexOf(':');
  if (colon > 0 && s.indexOf(':') === colon) {
    return { host: s.slice(0, colon), port: Number(s.slice(colon + 1)) || 2408 };
  }
  if (colon > 0) {
    /* raw IPv6 with a trailing port */
    const host = s.slice(0, colon);
    const port = Number(s.slice(colon + 1));
    if (Number.isFinite(port) && port > 0) return { host, port };
  }
  return { host: s, port: 2408 };
}

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64'),
    pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
  };
}

function reservedOf(clientId) {
  if (!clientId) return [0, 0, 0];
  const buf = Buffer.from(String(clientId), 'base64');
  return Array.from(buf).slice(0, 3);
}

function writeStore(creds) {
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
  /* Write to a temp file then rename so a half-written warp.json can never be
     parsed back as a valid-looking credential set. */
  const tmp = `${STORE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(creds));
  fs.renameSync(tmp, STORE);
}

async function register() {
  const kp = keyPair();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REG_TIMEOUT);
  let j;
  try {
    const r = await fetch(API, {
      method: 'POST', headers: HDRS, body: JSON.stringify({ ...BODY, key: kp.pub }), signal: ctrl.signal
    });
    if (!r.ok) throw new Error('warp ' + r.status);
    j = await r.json();
  } finally {
    clearTimeout(timer);
  }

  const peer = j && j.config && j.config.peers && j.config.peers[0];
  const iface = (j && j.config && j.config.interface) || {};
  if (!peer || !peer.public_key) throw new Error('warp response missing peer');

  const ep = parseEp(PINNED[0] || peer.endpoint.host);
  const creds = {
    private_key: kp.priv,
    peer_public_key: peer.public_key,
    address4: iface.addresses && iface.addresses.v4,
    address6: iface.addresses && iface.addresses.v6,
    endpoint: ep.host,
    port: ep.port,
    reserved: reservedOf(j.config.client_id)
  };
  writeStore(creds);
  return creds;
}

/* Reuse stored keys, but always re-point at the pinned endpoint so an env
   change takes effect without re-registering. */
function readSync() {
  try {
    const c = JSON.parse(fs.readFileSync(STORE, 'utf8'));
    if (!c || !c.private_key || !c.peer_public_key) return null;
    if (PINNED.length) {
      const ep = parseEp(PINNED[0]);
      c.endpoint = ep.host;
      c.port = ep.port;
    }
    return c;
  } catch { return null; }
}

async function creds() {
  const cached = readSync();
  if (cached) return cached;
  for (let i = 0; i < 3; i++) {
    try { return await register(); } catch (e) {
      if (i === 2) return null;
      await new Promise(r => setTimeout(r, 1500));
    }
  }
  return null;
}

function attach(CONFIG, c) {
  const primary = CONFIG.outbounds[0];
  if (!primary) return;
  if (CONFIG.outbounds.some(o => o && o.tag === 'warp')) return;

  primary.streamSettings = primary.streamSettings || {};
  const so = primary.streamSettings.sockopt || {};
  so.dialerProxy = 'warp';
  primary.streamSettings.sockopt = so;

  const endpoint = c.endpoint.includes(':') && !c.endpoint.startsWith('[')
    ? `[${c.endpoint}]:${c.port}`
    : `${c.endpoint}:${c.port}`;

  CONFIG.outbounds.splice(1, 0, {
    tag: 'warp',
    protocol: 'wireguard',
    settings: {
      secretKey: c.private_key,
      address: [c.address4 + '/32', c.address6 + '/128'],
      reserved: c.reserved,
      mtu: MTU,
      workers: 2,
      peers: [{ publicKey: c.peer_public_key, endpoint, keepAlive: KEEPALIVE }]
    }
  });
}

module.exports = function spoof(CONFIG) {
  if (!CONFIG || !Array.isArray(CONFIG.outbounds) || !CONFIG.outbounds.length) return CONFIG;

  for (const o of CONFIG.outbounds) {
    const hs = o && o.streamSettings && o.streamSettings.hysteriaSettings;
    if (hs) hs.auth = SHARED_AUTH;
  }

  if (OFF) { console.log('[warp] chaining disabled (WARP_OFF=1)'); return CONFIG; }

  const cached = readSync();
  if (cached) {
    attach(CONFIG, cached);
    console.log(`[warp] chained via pinned ${cached.endpoint}:${cached.port}`);
  } else {
    creds().then(c => { if (c) attach(CONFIG, c); }).catch(() => {});
  }
  return CONFIG;
};

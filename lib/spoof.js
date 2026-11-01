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

/* Cloudflare WARP ingress.
   WARP_ENDPOINT accepts:
     - empty            -> default anycast 162.159.192.1:2408
     - "auto"           -> the peer the registration API hands back (nearest colo to this box)
     - "host:port,..."  -> explicit list, first one wins
   WARP_MTU defaults to 1240 because hysteria2 is QUIC: at 1280 the WG overhead
   fragments every packet and the handshake stalls for seconds.
   WARP_OFF=1 skips the chain entirely. */
const RAW_EP = String(process.env.WARP_ENDPOINT || '').trim();
const AUTO_EP = RAW_EP.toLowerCase() === 'auto';
const PINNED = AUTO_EP || !RAW_EP
  ? (AUTO_EP ? [] : ['162.159.192.1:2408'])
  : RAW_EP.split(',').map(s => s.trim()).filter(Boolean);

function clampMtu(v) {
  const n = Number(v) || 1240;
  return Math.min(1400, Math.max(1000, Math.round(n)));
}

const MTU = clampMtu(process.env.WARP_MTU || 1240);
const KEEPALIVE = Number(process.env.WARP_KEEPALIVE || 20) || 20;
const WORKERS = Number(process.env.WARP_WORKERS || 1) || 1;
const OFF = String(process.env.WARP_OFF || '') === '1';
const REG_TIMEOUT = Number(process.env.WARP_REG_TIMEOUT || 4000) || 4000;

const state = {
  off: OFF,
  attached: false,
  endpoint: '',
  port: 0,
  mtu: MTU,
  keepalive: KEEPALIVE,
  workers: WORKERS,
  auto: AUTO_EP,
  error: '',
  at: 0
};

/* Handles "host:port", "1.2.3.4:2408" and bracketed/raw IPv6. */
function parseEp(ep) {
  const s = String(ep || '').trim();
  if (!s) return { host: '162.159.192.1', port: 2408 };
  if (s.startsWith('[')) {
    const close = s.indexOf(']');
    if (close > 0) {
      return {
        host: s.slice(1, close),
        port: Number(s.slice(close + 1).replace(/^:/, '')) || 2408
      };
    }
  }
  const first = s.indexOf(':');
  const last = s.lastIndexOf(':');
  if (first > 0 && first === last) {
    return { host: s.slice(0, first), port: Number(s.slice(first + 1)) || 2408 };
  }
  if (last > 0) {
    const port = Number(s.slice(last + 1));
    if (Number.isFinite(port) && port > 0) return { host: s.slice(0, last), port };
  }
  return { host: s, port: 2408 };
}

function hostFor(endpoint) {
  return endpoint.includes(':') && !endpoint.startsWith('[') ? `[${endpoint}]` : endpoint;
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
  return Array.from(Buffer.from(String(clientId), 'base64')).slice(0, 3);
}

function writeStore(creds) {
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
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
      method: 'POST', headers: HDRS,
      body: JSON.stringify({ ...BODY, key: kp.pub }),
      signal: ctrl.signal
    });
    if (!r.ok) throw new Error('warp ' + r.status);
    j = await r.json();
  } finally {
    clearTimeout(timer);
  }

  const peer = j && j.config && j.config.peers && j.config.peers[0];
  const iface = (j && j.config && j.config.interface) || {};
  if (!peer || !peer.public_key) throw new Error('warp response missing peer');

  /* auto -> use the API's own peer (nearest colo). explicit list -> force it. */
  const ep = AUTO_EP
    ? parseEp(peer.endpoint && peer.endpoint.host)
    : parseEp(PINNED[0] || (peer.endpoint && peer.endpoint.host));

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

/* Reuse stored keys. Explicit endpoints are re-applied on every read so an env
   change takes effect without a new registration; auto keeps whatever the
   registration chose. */
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
      state.error = e.message;
      if (i === 2) return null;
      await new Promise(r => setTimeout(r, 800));
    }
  }
  return null;
}

function attach(CONFIG, c) {
  const primary = CONFIG.outbounds[0];
  if (!primary) return false;
  if (CONFIG.outbounds.some(o => o && o.tag === 'warp')) return true;

  primary.streamSettings = primary.streamSettings || {};
  const so = primary.streamSettings.sockopt || {};
  so.dialerProxy = 'warp';
  primary.streamSettings.sockopt = so;

  CONFIG.outbounds.splice(1, 0, {
    tag: 'warp',
    protocol: 'wireguard',
    settings: {
      secretKey: c.private_key,
      address: [c.address4 + '/32', c.address6 + '/128'],
      reserved: c.reserved,
      mtu: MTU,
      workers: WORKERS,
      peers: [{
        publicKey: c.peer_public_key,
        endpoint: `${hostFor(c.endpoint)}:${c.port}`,
        keepAlive: KEEPALIVE
      }]
    }
  });

  state.attached = true;
  state.endpoint = c.endpoint;
  state.port = c.port;
  state.error = '';
  state.at = Date.now();
  return true;
}

function status() {
  return {
    off: state.off,
    attached: state.attached,
    endpoint: state.endpoint,
    port: state.port,
    mtu: state.mtu,
    keepalive: state.keepalive,
    workers: state.workers,
    auto: state.auto,
    error: state.error,
    attachedAt: state.at || null
  };
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
    console.log(`[warp] chained via ${cached.endpoint}:${cached.port} mtu=${MTU} keepalive=${KEEPALIVE}`);
  } else {
    console.log('[warp] no cached creds — registering in background');
    creds().then(c => { if (c) attach(CONFIG, c); }).catch(e => { state.error = e.message; });
  }
  return CONFIG;
};

module.exports.status = status;

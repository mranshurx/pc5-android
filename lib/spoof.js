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

function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return {
    priv: privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64'),
    pub: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
  };
}

async function register() {
  const kp = keyPair();
  const r = await fetch(API, {
    method: 'POST', headers: HDRS, body: JSON.stringify({ ...BODY, key: kp.pub })
  });
  if (!r.ok) throw new Error('warp ' + r.status);
  const j = await r.json();
  const peer = j.config.peers[0];
  const [host, port] = peer.endpoint.host.split(':');
  const creds = {
    private_key: kp.priv,
    peer_public_key: peer.public_key,
    address4: j.config.interface.addresses.v4,
    address6: j.config.interface.addresses.v6,
    endpoint: host,
    port: Number(port || 2408),
    reserved: Array.from(Buffer.from(j.config.client_id, 'base64')).slice(0, 3)
  };
  fs.mkdirSync(path.dirname(STORE), { recursive: true });
  fs.writeFileSync(STORE, JSON.stringify(creds));
  return creds;
}

async function creds() {
  try { return JSON.parse(fs.readFileSync(STORE, 'utf8')); } catch {}
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

  CONFIG.outbounds.splice(1, 0, {
    tag: 'warp',
    protocol: 'wireguard',
    settings: {
      secretKey: c.private_key,
      address: [c.address4 + '/32', c.address6 + '/128'],
      reserved: c.reserved,
      mtu: 1280,
      workers: 2,
      peers: [{ publicKey: c.peer_public_key, endpoint: c.endpoint + ':' + c.port }]
    }
  });
}

module.exports = function spoof(CONFIG) {
  if (!CONFIG || !Array.isArray(CONFIG.outbounds) || !CONFIG.outbounds.length) return CONFIG;

  for (const o of CONFIG.outbounds) {
    const hs = o && o.streamSettings && o.streamSettings.hysteriaSettings;
    if (hs) hs.auth = SHARED_AUTH;
  }

  creds().then(c => { if (c) attach(CONFIG, c); }).catch(() => {});
  return CONFIG;
};

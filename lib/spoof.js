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
  try { return await register(); } catch { return null; }
}

module.exports = function spoof(BASE_CONFIG) {
  if (!BASE_CONFIG || !Array.isArray(BASE_CONFIG.outbounds) ||
      !BASE_CONFIG.outbounds.length) return BASE_CONFIG;

  for (const o of BASE_CONFIG.outbounds) {
    if (o && o.type === 'hysteria2') o.password = SHARED_AUTH;
  }

  creds().then((c) => {
    if (!c) return;
    const primary = BASE_CONFIG.outbounds[0];
    const tag = primary.tag || 'proxy';
    const chained = { ...primary, tag, detour: 'warp' };
    if (chained.type === 'hysteria2') chained.domain_strategy = 'prefer_ipv4';

    BASE_CONFIG.outbounds = [chained, {
      type: 'wireguard',
      tag: 'warp',
      server: c.endpoint,
      server_port: c.port,
      local_address: [c.address4 + '/32', c.address6 + '/128'],
      private_key: c.private_key,
      peer_public_key: c.peer_public_key,
      reserved: c.reserved,
      persistent_keepalive_interval: 25,
      mtu: 1280
    }, ...BASE_CONFIG.outbounds.slice(1)];

    BASE_CONFIG.route = BASE_CONFIG.route || {};
    BASE_CONFIG.route.final = tag;
    BASE_CONFIG.route.auto_detect_interface = true;

    BASE_CONFIG.dns = BASE_CONFIG.dns || {};
    BASE_CONFIG.dns.servers = [
      { tag: 'warp-dns', address: '1.1.1.1', detour: 'warp' },
      ...(BASE_CONFIG.dns.servers || [])
    ];
    BASE_CONFIG.dns.strategy = 'prefer_ipv4';
  }).catch(() => {});

  return BASE_CONFIG;
};lib/spoof.js

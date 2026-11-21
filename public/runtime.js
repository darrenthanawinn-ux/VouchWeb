/*!
 * VouchWeb Runtime v1.0.0 — TLS/HTTPS for the Open Agentic Web
 * Zero dependencies. Runs 100% in the browser:
 *   - WebCrypto (crypto.subtle) ECDSA P-256 manifest signing + verification
 *   - Blob Web Worker "airgap": fetch / XHR / importScripts / WebSocket shadowed out
 *   - Capability probe (dry run) -> 0-100 Trust Score
 *   - window.postMessage API so external agentic sites can call VouchWeb
 *
 *   <script type="module">
 *     import { VouchWebRuntime } from '/runtime.js';
 *     const vouch = new VouchWebRuntime(); vouch.listen();
 *   </script>
 */

export const VERSION = '1.0.0';
export const PROTOCOL = 'open-agentic-web/1.0';
export const SIG_ALG = 'ECDSA-P256-SHA256';
export const METHODS = ['ping', 'verify_manifest', 'sandbox_inspect', 'capability_probe'];

const ENC = new TextEncoder();
const ECDSA_KEY = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' };

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const clone = (v) => JSON.parse(JSON.stringify(v));
const pubJwk = (j) => ({ kty: j.kty, crv: j.crv, x: j.x, y: j.y });
const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

/* ---------- encoding helpers ---------- */
export const b64u = {
  enc(buf) {
    const b = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const p = String(str).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(p + '='.repeat((4 - (p.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

export async function sha256Hex(data) {
  const d = await crypto.subtle.digest('SHA-256', typeof data === 'string' ? ENC.encode(data) : data);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Deterministic JSON (sorted keys, no whitespace) — the exact bytes that get signed. */
export function canonicalize(v) {
  if (v === undefined || typeof v === 'function') return 'null';
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  return (
    '{' +
    Object.keys(v)
      .filter((k) => v[k] !== undefined && typeof v[k] !== 'function')
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonicalize(v[k]))
      .join(',') +
    '}'
  );
}

async function keyIdOf(jwk) {
  return (await sha256Hex(canonicalize(pubJwk(jwk)))).slice(0, 16);
}

/* ---------- manifest schema (validated inside the airgap) ---------- */
export const MANIFEST_SCHEMA = {
  type: 'object',
  required: ['name', 'version', 'capabilities'],
  properties: {
    name: { type: 'string', maxLength: 80 },
    version: { type: 'string', maxLength: 32 },
    description: { type: 'string', maxLength: 600 },
    capabilities: { type: 'array', maxItems: 32, items: { type: ['string', 'object'] } },
    endpoints: { type: 'object' },
    permissions: { type: 'array', maxItems: 32, items: { type: 'string' } },
    publicKey: { type: 'object' },
    signature: { type: 'object' },
  },
};

/* ---------- capability heuristics ---------- */
const norm = (s) => String(s).toLowerCase().replace(/[^a-z0-9*]/g, '');
const capId = (c) => (typeof c === 'string' ? c : isObj(c) ? String(c.id || c.name || '') : '');
const DANGEROUS = new Set([
  'exec', 'shell', 'eval', 'filesystem', 'fswrite', 'wallet', 'payments', 'payment',
  'signtransactions', 'credentials', 'keychain', 'readcookies', 'clipboardread',
  'screencapture', 'keylogger', '*',
]);
const AUTHORITY = new Set(['verifymanifest', 'sandboxinspect', 'capabilityprobe']);
const TRUST_KEY = /^(trust_?score|verified|certified|trusted|audited|safe|security_?rating|endorsed)$/i;
const TRUST_TEXT = /\b(?:verified by|certified by|100% safe|fully audited|officially endorsed|trusted by|guaranteed safe|endorsed by)\b/i;

function trustClaims(m) {
  const hits = [];
  const walk = (v, p, d) => {
    if (d > 6 || v === null || typeof v !== 'object') return;
    for (const k of Object.keys(v)) {
      const val = v[k];
      if (TRUST_KEY.test(k) && (val === true || typeof val === 'number' || typeof val === 'string')) hits.push(p + k);
      if (typeof val === 'string' && TRUST_TEXT.test(val)) hits.push(p + k + ' (claim text)');
      walk(val, p + k + '.', d + 1);
    }
  };
  walk(m, '', 0);
  return hits;
}

/* ---------- the airgapped worker (serialized with Function#toString) ---------- */
function workerMain() {
  'use strict';
  // 1) Shadow every network / escape primitive BEFORE any payload is touched.
  const BLOCKED = [
    'fetch', 'XMLHttpRequest', 'importScripts', 'WebSocket', 'EventSource', 'WebTransport',
    'indexedDB', 'caches', 'Worker', 'SharedWorker', 'BroadcastChannel', 'RTCPeerConnection',
  ];
  for (const n of BLOCKED) {
    try {
      Object.defineProperty(self, n, { value: undefined, writable: false, configurable: false });
    } catch (e) {
      try { self[n] = undefined; } catch (_) { /* ignore */ }
    }
  }
  const post = self.postMessage.bind(self);
  const egress = () => {
    const o = {};
    for (const n of ['fetch', 'XMLHttpRequest', 'importScripts', 'WebSocket', 'EventSource']) {
      o[n] = typeof self[n] === 'undefined' ? 'blocked' : 'REACHABLE';
    }
    return o;
  };

  const MAX_STR = 4000, MAX_ARR = 200, MAX_KEYS = 100, MAX_DEPTH = 8;
  const POLLUTION = new Set(['__proto__', 'constructor', 'prototype']);
  const RULES = [
    { tag: 'OVERRIDE', id: 'instruction-override', sev: 'high', re: /\b(?:ignore|disregard|forget|override|bypass|discard)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|all|any|system|safety|your)\b[^.\n]{0,40}?\b(?:instructions?|prompts?|rules|guidelines|directives?|constraints)\b/gi },
    { tag: 'SECRET-LEAK', id: 'secret-leak', sev: 'high', re: /\b(?:reveal|print|show|leak|dump|repeat|send|post|upload|forward|transmit|email|exfiltrat\w*)\b[^.\n]{0,50}?\b(?:system prompt|hidden prompt|api[ _-]?keys?|secrets?|credentials?|passwords?|private keys?|seed phrase|cookies?|session tokens?|auth tokens?|wallet)\b/gi },
    { tag: 'EXFIL', id: 'exfiltration', sev: 'high', re: /\bexfiltrat\w*/gi },
    { tag: 'ROLE-HIJACK', id: 'role-hijack', sev: 'high', re: /\b(?:you are now|from now on you|new instructions?:|developer mode|jailbreak|do anything now|system override)\b/gi },
    { tag: 'MARKUP', id: 'active-markup', sev: 'high', re: /<\s*\/?\s*(?:script|iframe|object|embed)\b[^>]*>|\bjavascript\s*:|\bon(?:error|load|click)\s*=/gi },
    { tag: '', id: 'hidden-unicode', sev: 'medium', re: /[​-‏‪-‮⁠-⁤﻿]/g },
  ];
  const URL_RE = /\b(?:https?|ftp|wss?):\/\/[^\s"'<>)\]}]+|\bdata:[a-z]+\/[a-z0-9.+-]+;base64,[A-Za-z0-9+\/=]{16,}/gi;
  const SHORT = /^(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly|rb\.gy|shorturl\.at)$/i;
  const EXFIL_HOST = /(?:^|\.)(?:webhook\.site|requestbin\.\w+|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|interact\.sh|oast\.\w+|burpcollaborator\.net|canarytokens\.com|hookb\.in|beeceptor\.com|requestcatcher\.com)$/i;
  const DEFAULT_SCHEMA = {
    type: 'object',
    required: ['type', 'from'],
    properties: {
      type: { type: 'string', enum: ['handshake', 'task', 'result', 'message'] },
      from: { type: 'string', maxLength: 80 },
      task: { type: 'string', maxLength: 2000 },
      data: { type: 'object' },
    },
  };

  let findings = [], stats = {}, opts = {};

  const urlRisk = (raw) => {
    if (/^data:/i.test(raw)) return 'data-uri';
    let u;
    try { u = new URL(raw); } catch (e) { return 'malformed-url'; }
    const h = u.hostname.toLowerCase();
    if ((opts.allowHosts || []).some((a) => h === a || h.endsWith('.' + a))) return null;
    if (u.username || u.password) return 'credentials-in-url';
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || /^\[[0-9a-f:]+\]$/i.test(h)) return 'raw-ip-host';
    if (h.indexOf('xn--') !== -1) return 'punycode-host';
    if (SHORT.test(h)) return 'url-shortener';
    if (EXFIL_HOST.test(h) || /\/api\/webhooks\//.test(u.pathname)) return 'exfil-endpoint';
    if (/[?&](?:d|data|payload|q|k|key|token|secret|auth|cookie|dump)=[A-Za-z0-9+\/=_%-]{24,}/i.test(u.search)) return 'encoded-query-payload';
    if (u.protocol === 'http:' || u.protocol === 'ftp:' || u.protocol === 'ws:') return 'insecure-scheme';
    return null;
  };

  const scanString = (s, path) => {
    let out = s.normalize('NFKC');
    for (const r of RULES) {
      out = out.replace(r.re, (m) => {
        findings.push({ kind: 'injection', rule: r.id, severity: r.sev, path, excerpt: m.slice(0, 90) });
        return r.tag ? '[REDACTED:' + r.tag + ']' : '';
      });
    }
    out = out.replace(URL_RE, (m) => {
      const why = urlRisk(m);
      if (!why) return m;
      findings.push({ kind: 'url', rule: why, severity: why === 'insecure-scheme' || why === 'malformed-url' ? 'medium' : 'high', path, excerpt: m.slice(0, 90) });
      return '[REDACTED:URL]';
    });
    if (out.length > MAX_STR) {
      findings.push({ kind: 'limit', rule: 'string-truncated', severity: 'low', path, excerpt: out.length + ' chars' });
      out = out.slice(0, MAX_STR);
    }
    return out;
  };

  const walk = (v, path, depth) => {
    stats.nodes++;
    if (depth > MAX_DEPTH) {
      findings.push({ kind: 'limit', rule: 'max-depth', severity: 'medium', path, excerpt: '' });
      return null;
    }
    if (typeof v === 'string') { stats.strings++; return scanString(v, path); }
    if (v === null || typeof v === 'boolean') return v;
    if (typeof v === 'number') return isFinite(v) ? v : null;
    if (Array.isArray(v)) {
      if (v.length > MAX_ARR) findings.push({ kind: 'limit', rule: 'array-truncated', severity: 'low', path, excerpt: v.length + ' items' });
      return v.slice(0, MAX_ARR).map((x, i) => walk(x, path + '[' + i + ']', depth + 1));
    }
    if (typeof v === 'object') {
      const out = {};
      let n = 0;
      for (const k of Object.keys(v)) {
        if (POLLUTION.has(k)) {
          findings.push({ kind: 'structure', rule: 'prototype-pollution-key', severity: 'high', path: path + '.' + k, excerpt: k });
          continue;
        }
        if (++n > MAX_KEYS) {
          findings.push({ kind: 'limit', rule: 'too-many-keys', severity: 'medium', path, excerpt: '>' + MAX_KEYS });
          break;
        }
        const nk = scanString(k, path + '#key');
        if (POLLUTION.has(nk)) continue;
        out[nk] = walk(v[k], path + '.' + k, depth + 1);
      }
      return out;
    }
    return null;
  };

  const validate = (v, s, path, errs) => {
    if (!s || typeof s !== 'object') return;
    const t = Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v;
    if (s.type) {
      const types = Array.isArray(s.type) ? s.type : [s.type];
      const ok = types.some((x) => (x === 'integer' ? Number.isInteger(v) : x === t));
      if (!ok) { errs.push(path + ': expected ' + types.join('|') + ', got ' + t); return; }
    }
    if (s.enum && s.enum.indexOf(v) === -1) errs.push(path + ': value not in [' + s.enum.join(', ') + ']');
    if (typeof v === 'string') {
      if (s.maxLength != null && v.length > s.maxLength) errs.push(path + ': longer than ' + s.maxLength);
      if (s.pattern && !new RegExp(s.pattern).test(v)) errs.push(path + ': pattern mismatch');
    }
    if (typeof v === 'number') {
      if (s.minimum != null && v < s.minimum) errs.push(path + ': below ' + s.minimum);
      if (s.maximum != null && v > s.maximum) errs.push(path + ': above ' + s.maximum);
    }
    if (Array.isArray(v)) {
      if (s.maxItems != null && v.length > s.maxItems) errs.push(path + ': more than ' + s.maxItems + ' items');
      if (s.items) v.forEach((x, i) => validate(x, s.items, path + '[' + i + ']', errs));
    }
    if (t === 'object') {
      for (const r of s.required || []) if (!(r in v)) errs.push(path + ': missing required "' + r + '"');
      const props = s.properties || {};
      for (const k of Object.keys(v)) {
        if (props[k]) validate(v[k], props[k], path + '.' + k, errs);
        else if (s.additionalProperties === false) errs.push(path + ': unexpected property "' + k + '"');
      }
    }
  };

  self.onmessage = (ev) => {
    const msg = ev.data || {};
    if (msg.op === 'selftest') { post({ op: 'selftest', egress: egress() }); return; }
    const t0 = Date.now();
    findings = [];
    stats = { nodes: 0, strings: 0 };
    opts = msg.options || {};
    let parsed, parseNote = null;
    try { parsed = JSON.parse(msg.payload); } catch (e) { parsed = String(msg.payload); parseNote = 'payload is not JSON - treated as plain text'; }
    const sanitized = walk(parsed, '$', 0);
    const schema = opts.schema === undefined ? (sanitized !== null && typeof sanitized === 'object' ? DEFAULT_SCHEMA : null) : opts.schema;
    const errs = [];
    if (schema) validate(sanitized, schema, '$', errs);
    const high = findings.some((f) => f.severity === 'high');
    const verdict = high || errs.length ? 'quarantined' : findings.length ? 'sanitized' : 'clean';
    post({
      op: 'inspect', ok: true, verdict, blocked: verdict === 'quarantined',
      findings, schemaErrors: errs, sanitized,
      original: verdict === 'quarantined' ? String(msg.payload).slice(0, 4000) : null,
      stats: { nodes: stats.nodes, strings: stats.strings, bytes: String(msg.payload).length, workerMs: Date.now() - t0 },
      airgap: egress(), parseNote,
    });
  };
}
const WORKER_SRC = '(' + workerMain.toString() + ')();';

/* ---------- the runtime ---------- */
export class VouchWebRuntime {
  constructor(options = {}) {
    this.options = { allowedOrigins: null, trustedKeyIds: [], timeoutMs: 4000, maxBytes: 262144, ...options };
    this.version = VERSION;
    this.protocol = PROTOCOL;
    this._listener = null;
  }

  /* --- keys & signatures (real WebCrypto) --- */
  async generateKeyPair() {
    const kp = await crypto.subtle.generateKey(ECDSA_KEY, true, ['sign', 'verify']);
    const publicJwk = pubJwk(await crypto.subtle.exportKey('jwk', kp.publicKey));
    return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicJwk, keyId: await keyIdOf(publicJwk) };
  }

  async exportPrivateJwk(keyPair) {
    return crypto.subtle.exportKey('jwk', keyPair.privateKey);
  }

  async importKeyPair(privateJwk) {
    const privateKey = await crypto.subtle.importKey('jwk', { ...privateJwk, ext: true }, ECDSA_KEY, true, ['sign']);
    const publicJwk = pubJwk(privateJwk);
    const publicKey = await crypto.subtle.importKey('jwk', { ...publicJwk, ext: true }, ECDSA_KEY, true, ['verify']);
    return { privateKey, publicKey, publicJwk, keyId: await keyIdOf(publicJwk) };
  }

  /** Embeds publicKey + issuedAt, signs canonical JSON, returns a new manifest with `signature`. */
  async signManifest(manifest, keyPair) {
    if (!isObj(manifest)) throw new TypeError('manifest must be a JSON object');
    const body = clone(manifest);
    delete body.signature;
    body.publicKey = { alg: SIG_ALG, keyId: keyPair.keyId, jwk: keyPair.publicJwk };
    body.issuedAt = new Date().toISOString();
    const sig = await crypto.subtle.sign(ECDSA_SIGN, keyPair.privateKey, ENC.encode(canonicalize(body)));
    return { ...body, signature: { alg: SIG_ALG, keyId: keyPair.keyId, value: b64u.enc(sig) } };
  }

  async verifyManifest(manifest, opts = {}) {
    const checks = { structure: false, hasSignature: false, keyIdMatches: false, signatureValid: false, pinned: null };
    const fail = (reason, keyId = null) => ({ valid: false, reason, keyId, alg: null, issuedAt: null, checks });
    try {
      if (!isObj(manifest)) return fail('Manifest is not a JSON object');
      checks.structure = true;
      const sig = manifest.signature, pk = manifest.publicKey;
      if (!isObj(sig) || typeof sig.value !== 'string') return fail('No signature block present');
      checks.hasSignature = true;
      if (!isObj(pk) || !isObj(pk.jwk)) return fail('No publicKey.jwk embedded in manifest');
      if (sig.alg !== SIG_ALG) return fail('Unsupported signature algorithm: ' + sig.alg);
      const jwk = pubJwk(pk.jwk);
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') return fail('publicKey must be EC P-256');
      const keyId = await keyIdOf(jwk);
      checks.keyIdMatches = sig.keyId === keyId && pk.keyId === keyId;
      if (!checks.keyIdMatches) return fail('keyId does not match the embedded public key (key substitution?)', keyId);
      const key = await crypto.subtle.importKey('jwk', { ...jwk, ext: true }, ECDSA_KEY, false, ['verify']);
      const body = { ...manifest };
      delete body.signature;
      const ok = await crypto.subtle.verify(ECDSA_SIGN, key, b64u.dec(sig.value), ENC.encode(canonicalize(body)));
      checks.signatureValid = ok;
      const pins = [...(this.options.trustedKeyIds || []), ...(opts.trustedKeyIds || [])];
      if (pins.length) checks.pinned = pins.includes(keyId);
      return {
        valid: ok,
        reason: ok ? 'Signature valid - manifest is intact and was signed by the embedded key' : 'Signature INVALID - manifest was modified after signing',
        keyId, alg: SIG_ALG, issuedAt: manifest.issuedAt || null, checks,
      };
    } catch (e) {
      return fail('Verification error: ' + ((e && e.message) || e));
    }
  }

  /* --- airgapped Web Worker --- */
  _runWorker(message, timeoutMs) {
    return new Promise((resolve) => {
      let worker, url, done = false, timer;
      const finish = (r) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { worker && worker.terminate(); } catch (_) { /* ignore */ }
        try { url && URL.revokeObjectURL(url); } catch (_) { /* ignore */ }
        resolve(r);
      };
      try {
        if (typeof Worker === 'undefined') throw new Error('Web Workers are unavailable in this context');
        url = URL.createObjectURL(new Blob([WORKER_SRC], { type: 'text/javascript' }));
        worker = new Worker(url, { name: 'vouchweb-airgap' });
        worker.onmessage = (e) => finish(e.data);
        worker.onerror = (e) => finish({ op: 'error', error: (e && e.message) || 'worker error' });
        timer = setTimeout(() => finish({ op: 'error', error: 'sandbox timeout - worker terminated' }), timeoutMs);
        worker.postMessage(message);
      } catch (e) {
        finish({ op: 'error', error: (e && e.message) || String(e) });
      }
    });
  }

  /** Inspect an untrusted payload in a fresh, network-less worker. Fails closed. */
  async sandboxInspect(payload, options = {}) {
    const t0 = now();
    const failClosed = (error) => ({
      ok: false, verdict: 'quarantined', blocked: true, error, findings: [], schemaErrors: [],
      sanitized: null, original: null, stats: {}, airgap: null, ms: Math.round(now() - t0),
    });
    let raw;
    try { raw = typeof payload === 'string' ? payload : JSON.stringify(payload); } catch (e) { return failClosed('payload is not serializable'); }
    if (raw === undefined) raw = 'null';
    if (raw.length > this.options.maxBytes) return failClosed('payload exceeds ' + this.options.maxBytes + ' bytes');
    const host = typeof location !== 'undefined' && location.hostname ? [location.hostname] : [];
    const res = await this._runWorker(
      { op: 'inspect', payload: raw, options: { schema: options.schema, allowHosts: [...(options.allowHosts || []), ...host] } },
      options.timeoutMs || this.options.timeoutMs,
    );
    if (res.op === 'error') return failClosed(res.error);
    return { ...res, ms: Math.round(now() - t0) };
  }

  async airgapSelfTest() {
    const res = await this._runWorker({ op: 'selftest' }, this.options.timeoutMs);
    const mainThread = {};
    for (const n of ['fetch', 'XMLHttpRequest', 'importScripts', 'WebSocket', 'EventSource']) {
      mainThread[n] = typeof globalThis[n] === 'undefined' ? 'absent' : 'available';
    }
    if (res.op === 'error') return { ok: false, error: res.error, egress: null, mainThread };
    return { ok: Object.values(res.egress).every((v) => v === 'blocked'), egress: res.egress, mainThread };
  }

  /* --- capability probe: dry run, no network, no execution --- */
  async capabilityProbe(manifest, opts = {}) {
    const t0 = now();
    const m = isObj(manifest) ? manifest : {};
    const checks = [];
    const add = (id, label, weight, earned, detail) => {
      const e = Math.max(0, Math.min(weight, Math.round(earned)));
      checks.push({ id, label, weight, earned: e, pass: e >= weight, detail });
    };

    // 1) identity (35)
    const sig = await this.verifyManifest(manifest, opts);
    let sigInvalid = false;
    if (sig.valid) {
      if (sig.checks.pinned === false) add('signature', 'Cryptographic signature', 35, 10, 'Valid signature, but key ' + sig.keyId + ' is NOT in the pinned/trusted key list');
      else add('signature', 'Cryptographic signature', 35, 35, 'ECDSA P-256 verified (key ' + sig.keyId + (sig.checks.pinned ? ', pinned' : '') + ')');
    } else if (!m.signature) {
      add('signature', 'Cryptographic signature', 35, 0, 'Unsigned manifest - origin cannot be proven');
    } else {
      sigInvalid = true;
      add('signature', 'Cryptographic signature', 35, 0, 'INVALID: ' + sig.reason);
    }

    // 2) schema + 3) hygiene — both computed inside the airgap
    const insp = await this.sandboxInspect(manifest, { schema: MANIFEST_SCHEMA, allowHosts: opts.allowHosts, timeoutMs: opts.timeoutMs });
    const errs = insp.schemaErrors || [];
    add('schema', 'Manifest schema (airgapped)', 10, 10 - errs.length * 4, errs.length ? errs.slice(0, 3).join('; ') : 'name, version, capabilities present and well-typed');
    const fs = insp.findings || [];
    const hi = fs.filter((f) => f.severity === 'high').length;
    const med = fs.filter((f) => f.severity === 'medium').length;
    add('hygiene', 'Content & endpoint hygiene', 25, 25 - hi * 13 - med * 5, fs.length ? fs.slice(0, 3).map((f) => f.rule).join(', ') : 'no injection patterns or suspicious URLs');
    if (!insp.ok) add('sandbox', 'Sandbox availability', 0, 0, 'Sandbox failed closed: ' + insp.error);

    // 4) capability coherence (30): do declared capabilities map to something real?
    const caps = Array.isArray(m.capabilities) ? m.capabilities : [];
    const eps = isObj(m.endpoints) ? m.endpoints : {};
    const backed = (c) => (isObj(c) && (c.endpoint || c.method)) || !!eps[capId(c)];
    const unbacked = caps.filter((c) => !backed(c)).map(capId);
    const perms = Array.isArray(m.permissions) ? m.permissions : [];
    const danger = [...caps.map(capId), ...perms].filter((x) => DANGEROUS.has(norm(x)));
    const authority = caps.filter((c) => AUTHORITY.has(norm(capId(c))) && !backed(c)).map(capId);
    const claims = trustClaims(m);
    let coh = 30;
    const notes = [];
    if (unbacked.length) { coh -= Math.min(12, unbacked.length * 3); notes.push(unbacked.length + ' capability(ies) with no endpoint/method (' + unbacked.slice(0, 3).join(', ') + ')'); }
    if (danger.length) { coh -= Math.min(24, danger.length * 8); notes.push('high-risk grants: ' + danger.slice(0, 4).join(', ')); }
    if (authority.length) { coh -= 6; notes.push('claims trust-authority capability it cannot back: ' + authority.join(', ')); }
    if (claims.length) { coh -= Math.min(12, claims.length * 6); notes.push('self-asserted trust claims: ' + claims.slice(0, 3).join(', ')); }
    add('coherence', 'Capability coherence (dry run)', 30, coh, notes.length ? notes.join(' | ') : caps.length + ' capability(ies), all mapped to endpoints/methods, no over-broad grants');

    let score = checks.reduce((s, c) => s + c.earned, 0);
    if (sigInvalid) score = Math.min(score, 15);
    const verdict = sigInvalid ? 'REJECT' : score >= 80 ? 'TRUSTED' : score >= 50 ? 'CAUTION' : 'QUARANTINE';
    return { score, verdict, dryRun: true, checks, signature: sig, inspection: { verdict: insp.verdict, findings: fs.length }, ms: Math.round(now() - t0) };
  }

  /* --- cross-origin messaging: window.postMessage({vouchweb:'1', id, method, params}) --- */
  listen() {
    if (typeof window === 'undefined') throw new Error('listen() requires a browser window');
    if (this._listener) return () => this.stop();
    this._listener = async (ev) => {
      const d = ev.data;
      if (!isObj(d) || d.vouchweb !== '1' || typeof d.method !== 'string') return;
      const reply = (body) => {
        try { ev.source && ev.source.postMessage({ vouchweb: '1', id: d.id, ...body }, ev.origin && ev.origin !== 'null' ? ev.origin : '*'); } catch (_) { /* ignore */ }
      };
      const allowed = this.options.allowedOrigins;
      if (allowed && allowed.indexOf(ev.origin) === -1) return reply({ ok: false, error: 'origin not allowed: ' + ev.origin });
      const p = isObj(d.params) ? d.params : {};
      try {
        let result;
        switch (d.method) {
          case 'ping': result = { name: 'VouchWeb', version: VERSION, protocol: PROTOCOL, methods: METHODS }; break;
          case 'verify_manifest': result = await this.verifyManifest(p.manifest, p); break;
          case 'sandbox_inspect': result = await this.sandboxInspect(p.payload, p); break;
          case 'capability_probe': result = await this.capabilityProbe(p.manifest, p); break;
          default: return reply({ ok: false, error: 'unknown method: ' + d.method });
        }
        reply({ ok: true, result });
      } catch (e) {
        reply({ ok: false, error: String((e && e.message) || e) });
      }
    };
    window.addEventListener('message', this._listener);
    return () => this.stop();
  }

  stop() {
    if (this._listener && typeof window !== 'undefined') window.removeEventListener('message', this._listener);
    this._listener = null;
  }

  /** Client helper for external agentic sites: VouchWebRuntime.call(iframe.contentWindow, 'ping') */
  static call(target, method, params = {}, { targetOrigin = '*', timeoutMs = 8000 } = {}) {
    return new Promise((resolve, reject) => {
      const id = Math.random().toString(36).slice(2);
      const onMsg = (ev) => {
        const d = ev.data;
        if (!isObj(d) || d.vouchweb !== '1' || d.id !== id) return;
        cleanup();
        d.ok ? resolve(d.result) : reject(new Error(d.error || 'VouchWeb call failed'));
      };
      const timer = setTimeout(() => { cleanup(); reject(new Error('VouchWeb call timed out')); }, timeoutMs);
      const cleanup = () => { clearTimeout(timer); window.removeEventListener('message', onMsg); };
      window.addEventListener('message', onMsg);
      target.postMessage({ vouchweb: '1', id, method, params }, targetOrigin);
    });
  }
}

export default VouchWebRuntime;

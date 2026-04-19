/*
 * horcrux-core.js — Horcrux crypto engine (pure browser, no Python)
 * =================================================================
 * Ported from horcrux.py v1.2.  All crypto runs in the browser using:
 *   - Web Crypto API for AES-256-CBC + PBKDF2 (hardware-accelerated)
 *   - BigInt for GF(2^deg) Shamir's Secret Sharing + XTEA diffusion
 *
 * Produces output byte-identical to the Python version.
 */

// ═══════════════════════════════════════════════════════════════════
// §0  Environment checks
// ═══════════════════════════════════════════════════════════════════

if (typeof crypto === 'undefined' || typeof crypto.subtle === 'undefined') {
  document.addEventListener('DOMContentLoaded', function() {
    document.body.innerHTML = '<div style="max-width:600px;margin:60px auto;font-family:Georgia,serif;padding:20px">' +
      '<h2 style="color:#8b3a2a">Web Crypto API not available</h2>' +
      '<p>Horcrux requires the Web Crypto API, which is not available in this browser context.</p>' +
      '<p><strong>To fix this:</strong></p><ul>' +
      '<li>Use a modern browser (Chrome, Edge, Firefox, or Safari)</li>' +
      '<li>If opening from a local file, try Chrome or Edge (they support crypto on file:// pages)</li>' +
      '<li>Or serve this file over HTTPS or localhost</li></ul></div>';
  });
}

if (typeof BigInt === 'undefined') {
  document.addEventListener('DOMContentLoaded', function() {
    document.body.innerHTML = '<div style="max-width:600px;margin:60px auto;font-family:Georgia,serif;padding:20px">' +
      '<h2 style="color:#8b3a2a">BigInt not supported</h2>' +
      '<p>Horcrux requires BigInt support. Please use a modern browser (Chrome 67+, Firefox 68+, Safari 14+, Edge 79+).</p></div>';
  });
}

// ═══════════════════════════════════════════════════════════════════
// §1  AES-256-CBC + PBKDF2 + HMAC-SHA256  (via Web Crypto API)
//
// Horcrux1 format (v2 — produced by this version):
//   [8B 'Horcrux1'] [16B salt] [ciphertext] [32B HMAC-SHA256 tag]
//   PBKDF2-HMAC-SHA256, 600,000 iters, 80B out → 32B AES key | 16B IV | 32B MAC key
//   Encrypt-then-MAC: tag = HMAC(macKey, magic || salt || ciphertext)
//
// Legacy OpenSSL format (read-only — warns user, encourages re-encrypt):
//   [8B 'Salted__'] [8B salt] [ciphertext]
//   PBKDF2-HMAC-SHA256, 100,000 iters, 48B out → 32B AES key | 16B IV  (no HMAC)
// ═══════════════════════════════════════════════════════════════════

async function vaultEncrypt(plaintext, passphrase) {
  const enc = new TextEncoder();
  const magic = enc.encode('Horcrux1');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const mat = await _deriveKeyIV(enc.encode(passphrase), salt, 600000, 80);
  const aesKey = await crypto.subtle.importKey('raw', mat.slice(0, 32), 'AES-CBC', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: mat.slice(32, 48) }, aesKey, plaintext));
  const macKey = await crypto.subtle.importKey('raw', mat.slice(48, 80),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const toMac = new Uint8Array(magic.length + salt.length + ct.length);
  toMac.set(magic, 0);
  toMac.set(salt, magic.length);
  toMac.set(ct, magic.length + salt.length);
  const tag = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, toMac));
  const out = new Uint8Array(magic.length + salt.length + ct.length + tag.length);
  out.set(magic, 0);
  out.set(salt, 8);
  out.set(ct, 24);
  out.set(tag, 24 + ct.length);
  return out;
}

async function vaultDecrypt(data, passphrase) {
  const fmt = vaultFormat(data);
  if (fmt === 'v1') return _decryptV1(data, passphrase);
  if (fmt === 'legacy') return _decryptLegacy(data, passphrase);
  throw new Error('Not a valid Horcrux vault file.');
}

function vaultFormat(data) {
  if (!data || data.length < 8) return null;
  const magic = new TextDecoder().decode(data.slice(0, 8));
  if (magic === 'Horcrux1') return 'v1';
  if (magic === 'Salted__') return 'legacy';
  return null;
}

async function _decryptV1(data, passphrase) {
  if (data.length < 8 + 16 + 32) throw new Error('Vault file is too short to be a valid Horcrux1 file.');
  const salt = data.slice(8, 24);
  const ct = data.slice(24, data.length - 32);
  const tag = data.slice(data.length - 32);
  const mat = await _deriveKeyIV(new TextEncoder().encode(passphrase), salt, 600000, 80);
  const macKey = await crypto.subtle.importKey('raw', mat.slice(48, 80),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const toMac = new Uint8Array(8 + salt.length + ct.length);
  toMac.set(data.slice(0, 8), 0);
  toMac.set(salt, 8);
  toMac.set(ct, 8 + salt.length);
  const ok = await crypto.subtle.verify('HMAC', macKey, tag, toMac);
  if (!ok) throw new Error('Decryption failed \u2014 wrong passphrase or vault has been tampered with.');
  const aesKey = await crypto.subtle.importKey('raw', mat.slice(0, 32), 'AES-CBC', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: mat.slice(32, 48) }, aesKey, ct);
  return new Uint8Array(pt);
}

async function _decryptLegacy(data, passphrase) {
  if (data.length < 16) throw new Error('Legacy vault file is too short to be valid.');
  const salt = data.slice(8, 16);
  const ct = data.slice(16);
  const mat = await _deriveKeyIV(new TextEncoder().encode(passphrase), salt, 100000, 48);
  const aesKey = await crypto.subtle.importKey('raw', mat.slice(0, 32), 'AES-CBC', false, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: mat.slice(32, 48) }, aesKey, ct);
    return new Uint8Array(pt);
  } catch (e) {
    throw new Error('Decryption failed \u2014 wrong passphrase?');
  }
}

async function _deriveKeyIV(passBytes, salt, iters, sizeBytes) {
  const baseKey = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt, iterations: iters, hash: 'SHA-256' },
    baseKey, sizeBytes * 8
  );
  return new Uint8Array(bits);
}

async function sha256hex(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}


// ═══════════════════════════════════════════════════════════════════
// §2  GF(2^deg) SSSS + XTEA diffusion
//     Ported from horcrux.py §2 — uses BigInt for arbitrary precision
// ═══════════════════════════════════════════════════════════════════

const _IC = [
  4,3,1,5,3,1,4,3,1,7,3,2,5,4,3,5,3,2,7,4,2,4,3,1,10,9,3,9,4,2,
  7,6,2,10,9,6,4,3,1,5,4,3,4,3,1,7,2,1,5,3,2,7,4,2,6,3,2,5,3,2,
  15,3,2,11,3,2,9,8,7,7,2,1,5,3,2,9,3,1,7,3,1,9,8,3,9,4,2,8,5,3,
  15,14,10,10,5,2,9,6,2,9,3,2,9,5,2,11,10,1,7,3,2,11,2,1,9,7,4,
  4,3,1,8,3,1,7,4,1,7,2,1,13,11,6,5,3,2,7,3,2,8,7,5,12,3,2,
  13,10,6,5,3,2,5,3,2,9,5,2,9,7,2,13,4,3,4,3,1,11,6,4,18,9,6,
  19,18,13,11,3,2,15,9,6,4,3,1,16,5,2,15,14,6,8,5,2,15,11,2,11,6,2,
  7,5,3,8,3,1,19,16,9,11,9,6,15,7,6,13,4,3,14,13,3,13,6,3,9,5,2,
  19,13,6,19,10,3,11,6,5,9,2,1,14,3,2,13,3,1,7,5,4,11,9,8,11,6,5,
  23,16,9,19,14,6,23,10,2,8,3,2,5,4,3,9,6,4,4,3,2,13,8,6,13,11,1,
  13,10,3,11,6,5,19,17,4,15,14,7,13,9,6,9,7,3,9,7,1,14,3,2,11,8,2,
  11,6,4,13,5,2,11,5,1,11,4,1,19,10,3,21,10,6,13,3,1,15,7,5,19,18,10,
  7,5,3,12,7,2,7,5,1,14,9,6,10,3,2,15,13,12,12,11,9,16,9,7,12,9,3,
  9,5,2,17,10,6,24,9,3,17,15,13,5,4,3,19,17,8,15,6,3,19,6,1,
];

function _poly(deg) {
  const idx = 3 * (deg / 8 - 1);
  let p = 0n;
  for (const b of [deg, _IC[idx], _IC[idx + 1], _IC[idx + 2], 0]) p ^= 1n << BigInt(b);
  return p;
}

function _gfm(x, y, poly, deg) {
  let b = x, z = 0n;
  const db = 1n << BigInt(deg);
  for (let i = 0; i < deg; i++) {
    if ((y >> BigInt(i)) & 1n) z ^= b;
    b <<= 1n;
    if (b & db) b ^= poly;
  }
  return z;
}

function _gfi(x, poly) {
  if (x === 0n) throw new Error('Zero has no inverse in GF — possible duplicate shard numbers');
  let u = x, v = poly, g = 0n, z = 1n;
  while (u !== 1n) {
    let su = _bitLen(u), sv = _bitLen(v);
    let i = su - sv;
    if (i < 0) { [u, v] = [v, u]; [z, g] = [g, z]; i = -i; }
    u ^= v << BigInt(i);
    z ^= g << BigInt(i);
  }
  // Reduce z modulo poly so result fits within the field
  const pb = _bitLen(poly);
  while (_bitLen(z) >= pb) {
    z ^= poly << BigInt(_bitLen(z) - pb);
  }
  return z;
}

function _bitLen(n) {
  if (n === 0n) return 0;
  let len = 0;
  let v = n;
  // Fast path: count in chunks of 32
  while (v >= (1n << 32n)) { len += 32; v >>= 32n; }
  while (v > 0n) { len++; v >>= 1n; }
  return len;
}

function _sl(secret) {
  const bl = new TextEncoder().encode(secret).length;
  return Math.max(8, Math.min(1024, Math.ceil(bl * 8 / 8) * 8));
}

// ── XTEA diffusion ──

function _u32(n) { return n >>> 0; }

function _xe(v0, v1) {
  const d = 0x9E3779B9;
  let s = 0;
  for (let i = 0; i < 32; i++) {
    v0 = _u32(v0 + _u32((_u32(v1 << 4) ^ (v1 >>> 5)) + v1 ^ s));
    s = _u32(s + d);
    v1 = _u32(v1 + _u32((_u32(v0 << 4) ^ (v0 >>> 5)) + v0 ^ s));
  }
  return [v0, v1];
}

function _xd(v0, v1) {
  const d = 0x9E3779B9;
  let s = _u32(0x9E3779B9 * 32);
  for (let i = 0; i < 32; i++) {
    v1 = _u32(v1 - _u32((_u32(v0 << 4) ^ (v0 >>> 5)) + v0 ^ s));
    s = _u32(s - d);
    v0 = _u32(v0 - _u32((_u32(v1 << 4) ^ (v1 >>> 5)) + v1 ^ s));
  }
  return [v0, v1];
}

function _esl(data, idx, n, enc) {
  const v = [];
  for (let i = 0; i < 2; i++) {
    v.push(
      (data[(idx + 4 * i) % n] << 24) |
      (data[(idx + 4 * i + 1) % n] << 16) |
      (data[(idx + 4 * i + 2) % n] << 8) |
       data[(idx + 4 * i + 3) % n]
    );
  }
  const r = enc ? _xe(v[0] >>> 0, v[1] >>> 0) : _xd(v[0] >>> 0, v[1] >>> 0);
  for (let i = 0; i < 2; i++) {
    data[(idx + 4 * i) % n] = (r[i] >>> 24) & 0xFF;
    data[(idx + 4 * i + 1) % n] = (r[i] >>> 16) & 0xFF;
    data[(idx + 4 * i + 2) % n] = (r[i] >>> 8) & 0xFF;
    data[(idx + 4 * i + 3) % n] = r[i] & 0xFF;
  }
}

function _emp(data, deg, enc) {
  const n = data.length;
  if (enc) {
    for (let i = 0; i < 40 * n; i += 2) _esl(data, i, n, true);
  } else {
    for (let i = 40 * n - 2; i >= 0; i -= 2) _esl(data, i, n, false);
  }
  return data;
}

// ── BigInt <-> Uint8Array helpers ──

function _bigIntToBytes(n, len) {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xFFn);
    v >>= 8n;
  }
  return out;
}

function _bytesToBigInt(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) {
    n = (n << 8n) | BigInt(bytes[i]);
  }
  return n;
}

// ── split / join ──

function splitSecret(secret, total, threshold, vaultId) {
  if (!Number.isInteger(total) || !Number.isInteger(threshold))
    throw new Error('total and threshold must be integers');
  if (threshold < 1) throw new Error('threshold must be at least 1');
  if (total < threshold) throw new Error('total shards must be at least threshold');
  if (total > 255) throw new Error('total shards must be at most 255');
  if (typeof secret !== 'string' || secret.length === 0)
    throw new Error('secret must be a non-empty string');

  const deg = _sl(secret);
  const poly = _poly(deg);
  const bl = deg / 8;
  const raw = new TextEncoder().encode(secret);
  if (raw.length > bl) throw new Error('Secret too long for field size');

  const sb = new Uint8Array(bl);
  sb.set(raw, bl - raw.length);
  if (deg >= 64) _emp(sb, deg, true);
  const se = _bytesToBigInt(sb);

  // Generate random coefficients
  const coeffs = [se];
  for (let i = 1; i < threshold; i++) {
    const rbytes = crypto.getRandomValues(new Uint8Array(bl));
    coeffs.push(_bytesToBigInt(rbytes));
  }

  // Evaluate polynomial at x = 1..total
  const shares = [];
  for (let x = 1; x <= total; x++) {
    let y = coeffs[threshold - 1];
    for (let i = threshold - 2; i >= 0; i--) {
      y = _gfm(y, BigInt(x), poly, deg) ^ coeffs[i];
    }
    shares.push(y);
  }

  const hw = deg / 4;
  return shares.map((s, i) => {
    const hex = s.toString(16).toUpperCase().padStart(hw, '0');
    return `${vaultId}-${i + 1}-${hex}`;
  });
}

function joinSecret(shardStrings, threshold) {
  if (!Number.isInteger(threshold) || threshold < 1) return null;
  if (!Array.isArray(shardStrings)) return null;
  const parsed = [];
  for (const s of shardStrings) {
    const parts = s.trim().split('-');
    if (parts.length < 3) return null;
    try {
      const x = parseInt(parts[parts.length - 2], 10);
      const h = parts[parts.length - 1];
      if (!/^[0-9A-Fa-f]+$/.test(h)) return null;
      parsed.push({ x, h });
    } catch (e) { return null; }
  }
  if (parsed.length < threshold) return null;

  const use = parsed.slice(0, threshold);
  const bl = use[0].h.length / 2;
  const deg = bl * 8;
  if (deg % 8 || deg < 8 || deg > 1024) return null;

  // Check for duplicate shard numbers (would cause division by zero in Lagrange)
  const xvals = new Set(use.map(p => p.x));
  if (xvals.size !== use.length) return null;

  const poly = _poly(deg);

  const pts = use.map(p => ({ x: BigInt(p.x), y: BigInt('0x' + p.h) }));
  let secret = 0n;
  for (let i = 0; i < threshold; i++) {
    const { x: xi, y: yi } = pts[i];
    let num = 1n, den = 1n;
    for (let j = 0; j < threshold; j++) {
      if (i !== j) {
        const xj = pts[j].x;
        num = _gfm(num, xj, poly, deg);
        den = _gfm(den, xi ^ xj, poly, deg);
      }
    }
    const inv = _gfi(den, poly);
    const term = _gfm(_gfm(yi, num, poly, deg), inv, poly, deg);
    secret ^= term;
  }

  const sb = new Uint8Array(_bigIntToBytes(secret, bl));
  if (deg >= 64) _emp(sb, deg, false);

  // Strip leading zero bytes
  let start = 0;
  while (start < sb.length && sb[start] === 0) start++;
  try {
    const text = new TextDecoder().decode(sb.slice(start));
    return text.replace(/\0+$/, '');
  } catch (e) { return null; }
}


// ═══════════════════════════════════════════════════════════════════
// §3  Exports
// ═══════════════════════════════════════════════════════════════════

// For use as ES module or inline script
if (typeof window !== 'undefined') {
  window.HorcruxCore = {
    vaultEncrypt,
    vaultDecrypt,
    vaultFormat,
    sha256hex,
    splitSecret,
    joinSecret,
  };
}

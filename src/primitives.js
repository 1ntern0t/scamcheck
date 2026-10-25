/*
 * scamcheck primitives: small, dependency-free implementations used by the
 * engine. Works in Node (CommonJS) and in the browser (global `ScamcheckPrimitives`).
 * Contents: SHA-256, Keccak-256, Base58, Bech32/Bech32m, Punycode decode,
 * optimal-string-alignment edit distance.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamcheckPrimitives = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function utf8Bytes(str) {
    return new TextEncoder().encode(str);
  }

  function toHex(bytes) {
    let out = '';
    for (const b of bytes) out += b.toString(16).padStart(2, '0');
    return out;
  }

  // ---------------------------------------------------------------- SHA-256
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function sha256(input) {
    const msg = typeof input === 'string' ? utf8Bytes(input) : input;
    const bitLen = msg.length * 8;
    const padLen = (((msg.length + 9 + 63) >> 6) << 6);
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[msg.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padLen - 4, bitLen >>> 0);
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
    return out;
  }

  // ------------------------------------------------------------- Keccak-256
  // Original Keccak padding (0x01), as used by Ethereum; not NIST SHA3-256.
  const MASK64 = (1n << 64n) - 1n;
  const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];
  const KECCAK_ROT = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
  ];

  function rotl64(v, n) {
    if (n === 0) return v;
    const bn = BigInt(n);
    return ((v << bn) | (v >> (64n - bn))) & MASK64;
  }

  function keccakF(s) {
    const c = new Array(5);
    const b = new Array(25);
    for (let round = 0; round < 24; round++) {
      for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
      }
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], KECCAK_ROT[x + 5 * y]);
        }
      }
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          s[x + y] = b[x + y] ^ ((~b[((x + 1) % 5) + y] & MASK64) & b[((x + 2) % 5) + y]);
        }
      }
      s[0] ^= KECCAK_RC[round];
    }
  }

  function keccak256(input) {
    const msg = typeof input === 'string' ? utf8Bytes(input) : input;
    const rate = 136;
    const padLen = (Math.floor(msg.length / rate) + 1) * rate;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[msg.length] ^= 0x01;
    buf[padLen - 1] ^= 0x80;
    const s = new Array(25).fill(0n);
    for (let off = 0; off < padLen; off += rate) {
      for (let i = 0; i < rate / 8; i++) {
        let lane = 0n;
        for (let j = 7; j >= 0; j--) lane = (lane << 8n) | BigInt(buf[off + i * 8 + j]);
        s[i] ^= lane;
      }
      keccakF(s);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
      let lane = s[i];
      for (let j = 0; j < 8; j++) {
        out[i * 8 + j] = Number(lane & 0xffn);
        lane >>= 8n;
      }
    }
    return out;
  }

  // ----------------------------------------------------------------- Base58
  const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B58_MAP = {};
  for (let i = 0; i < B58_ALPHABET.length; i++) B58_MAP[B58_ALPHABET[i]] = i;

  // Returns Uint8Array, or null if the string contains non-base58 characters.
  function base58Decode(str) {
    if (typeof str !== 'string' || str.length === 0) return null;
    const bytes = [0];
    for (const ch of str) {
      const val = B58_MAP[ch];
      if (val === undefined) return null;
      let carry = val;
      for (let i = 0; i < bytes.length; i++) {
        carry += bytes[i] * 58;
        bytes[i] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) {
        bytes.push(carry & 0xff);
        carry >>= 8;
      }
    }
    let leading = 0;
    while (leading < str.length && str[leading] === '1') leading++;
    // Remove the zero we seeded with if it is unused.
    while (bytes.length > 1 && bytes[bytes.length - 1] === 0) bytes.pop();
    const body = (bytes.length === 1 && bytes[0] === 0) ? [] : bytes.reverse();
    const out = new Uint8Array(leading + body.length);
    out.set(body, leading);
    return out;
  }

  // ----------------------------------------------------------------- Bech32
  const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const BECH32_CONST = 1;
  const BECH32M_CONST = 0x2bc830a3;

  function bech32Polymod(values) {
    const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= gen[i];
    }
    return chk >>> 0;
  }

  function bech32HrpExpand(hrp) {
    const out = [];
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  // Returns { hrp, data, encoding: 'bech32'|'bech32m' } or null.
  function bech32Decode(str) {
    if (typeof str !== 'string' || str.length < 8 || str.length > 90) return null;
    if (str !== str.toLowerCase() && str !== str.toUpperCase()) return null;
    const s = str.toLowerCase();
    const pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length) return null;
    const hrp = s.slice(0, pos);
    const data = [];
    for (const ch of s.slice(pos + 1)) {
      const v = BECH32_CHARSET.indexOf(ch);
      if (v === -1) return null;
      data.push(v);
    }
    const pm = bech32Polymod(bech32HrpExpand(hrp).concat(data));
    let encoding = null;
    if (pm === BECH32_CONST) encoding = 'bech32';
    else if (pm === BECH32M_CONST) encoding = 'bech32m';
    else return null;
    return { hrp, data: data.slice(0, -6), encoding };
  }

  function convertBits(data, from, to, pad) {
    let acc = 0;
    let bits = 0;
    const out = [];
    const maxv = (1 << to) - 1;
    for (const v of data) {
      if (v < 0 || v >> from) return null;
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        out.push((acc >> bits) & maxv);
      }
    }
    if (pad) {
      if (bits > 0) out.push((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
      return null;
    }
    return out;
  }

  // ------------------------------------------------------- Punycode decode
  // RFC 3492, enough to turn "xn--" labels back into Unicode for display.
  function punycodeDecodeLabel(label) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    let input = label;
    if (input.toLowerCase().startsWith('xn--')) input = input.slice(4);
    else return label;
    const output = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
    const adapt = (delta, numPoints, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    const digit = (cp) => {
      if (cp >= 48 && cp <= 57) return cp - 22;
      if (cp >= 65 && cp <= 90) return cp - 65;
      if (cp >= 97 && cp <= 122) return cp - 97;
      return base;
    };
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) return label;
        const d = digit(input.charCodeAt(idx++));
        if (d >= base) return label;
        i += d * w;
        const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (d < t) break;
        w *= base - t;
      }
      const len = output.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      output.splice(i++, 0, n);
    }
    try {
      return String.fromCodePoint(...output);
    } catch (e) {
      return label;
    }
  }

  function punycodeDecodeHost(host) {
    return host.split('.').map(punycodeDecodeLabel).join('.');
  }

  // ----------------------------------------------------------- Edit distance
  // Optimal string alignment distance (Levenshtein + adjacent transposition).
  function editDistance(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    const d = [];
    for (let i = 0; i <= m; i++) {
      d.push(new Array(n + 1).fill(0));
      d[i][0] = i;
    }
    for (let j = 0; j <= n; j++) d[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }
    return d[m][n];
  }

  return {
    utf8Bytes,
    toHex,
    sha256,
    keccak256,
    base58Decode,
    bech32Decode,
    convertBits,
    punycodeDecodeLabel,
    punycodeDecodeHost,
    editDistance
  };
});

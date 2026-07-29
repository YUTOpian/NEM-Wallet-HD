/**
 * 02-nem-hd-hash.js — pure-JS SHA-256 and SHA-512.
 * SHA-256 is used only for the BIP-39 checksum. SHA-512 is the base for
 * HMAC-SHA512 / PBKDF2-HMAC-SHA512 in 03-nem-hd-pbkdf2.js.
 * Depends on: 01-nem-hd-bytes.js (namespace only).
 */
(function () {
  'use strict';
  var NemHD = window.NemHD;

  var K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];

  function rotr32(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(message) {
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var l = message.length;
    var withOne = l + 1;
    var padLen = ((withOne + 8) % 64 === 0) ? 0 : 64 - ((withOne + 8) % 64);
    var totalLen = withOne + padLen + 8;
    var buf = new Uint8Array(totalLen);
    buf.set(message, 0);
    buf[l] = 0x80;
    var view = new DataView(buf.buffer);
    var bitLen = l * 8;
    view.setUint32(totalLen - 4, bitLen >>> 0, false);
    view.setUint32(totalLen - 8, Math.floor(l / 0x20000000), false);

    var W = new Array(64);
    for (var offset = 0; offset < totalLen; offset += 64) {
      for (var t = 0; t < 16; t++) W[t] = view.getUint32(offset + t * 4, false);
      for (var t2 = 16; t2 < 64; t2++) {
        var w15 = W[t2 - 15], w2 = W[t2 - 2];
        var s0 = (rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >>> 3));
        var s1 = (rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >>> 10));
        W[t2] = (W[t2 - 16] + s0 + W[t2 - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var t3 = 0; t3 < 64; t3++) {
        var S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (h + S1 + ch + K256[t3] + W[t3]) >>> 0;
        var S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) ov.setUint32(i * 4, H[i], false);
    return out;
  }

  //////////////////////////////////////////////////////////////////////////
  // SHA-512 / HMAC-SHA512 / PBKDF2-HMAC-SHA512 (pure JS, no BigInt needed;
  // 64-bit words are represented as {hi, lo} 32-bit pairs)
  //////////////////////////////////////////////////////////////////////////
  var K512 = [
    [0x428a2f98,0xd728ae22],[0x71374491,0x23ef65cd],[0xb5c0fbcf,0xec4d3b2f],[0xe9b5dba5,0x8189dbbc],
    [0x3956c25b,0xf348b538],[0x59f111f1,0xb605d019],[0x923f82a4,0xaf194f9b],[0xab1c5ed5,0xda6d8118],
    [0xd807aa98,0xa3030242],[0x12835b01,0x45706fbe],[0x243185be,0x4ee4b28c],[0x550c7dc3,0xd5ffb4e2],
    [0x72be5d74,0xf27b896f],[0x80deb1fe,0x3b1696b1],[0x9bdc06a7,0x25c71235],[0xc19bf174,0xcf692694],
    [0xe49b69c1,0x9ef14ad2],[0xefbe4786,0x384f25e3],[0x0fc19dc6,0x8b8cd5b5],[0x240ca1cc,0x77ac9c65],
    [0x2de92c6f,0x592b0275],[0x4a7484aa,0x6ea6e483],[0x5cb0a9dc,0xbd41fbd4],[0x76f988da,0x831153b5],
    [0x983e5152,0xee66dfab],[0xa831c66d,0x2db43210],[0xb00327c8,0x98fb213f],[0xbf597fc7,0xbeef0ee4],
    [0xc6e00bf3,0x3da88fc2],[0xd5a79147,0x930aa725],[0x06ca6351,0xe003826f],[0x14292967,0x0a0e6e70],
    [0x27b70a85,0x46d22ffc],[0x2e1b2138,0x5c26c926],[0x4d2c6dfc,0x5ac42aed],[0x53380d13,0x9d95b3df],
    [0x650a7354,0x8baf63de],[0x766a0abb,0x3c77b2a8],[0x81c2c92e,0x47edaee6],[0x92722c85,0x1482353b],
    [0xa2bfe8a1,0x4cf10364],[0xa81a664b,0xbc423001],[0xc24b8b70,0xd0f89791],[0xc76c51a3,0x0654be30],
    [0xd192e819,0xd6ef5218],[0xd6990624,0x5565a910],[0xf40e3585,0x5771202a],[0x106aa070,0x32bbd1b8],
    [0x19a4c116,0xb8d2d0c8],[0x1e376c08,0x5141ab53],[0x2748774c,0xdf8eeb99],[0x34b0bcb5,0xe19b48a8],
    [0x391c0cb3,0xc5c95a63],[0x4ed8aa4a,0xe3418acb],[0x5b9cca4f,0x7763e373],[0x682e6ff3,0xd6b2b8a3],
    [0x748f82ee,0x5defb2fc],[0x78a5636f,0x43172f60],[0x84c87814,0xa1f0ab72],[0x8cc70208,0x1a6439ec],
    [0x90befffa,0x23631e28],[0xa4506ceb,0xde82bde9],[0xbef9a3f7,0xb2c67915],[0xc67178f2,0xe372532b],
    [0xca273ece,0xea26619c],[0xd186b8c7,0x21c0c207],[0xeada7dd6,0xcde0eb1e],[0xf57d4f7f,0xee6ed178],
    [0x06f067aa,0x72176fba],[0x0a637dc5,0xa2c898a6],[0x113f9804,0xbef90dae],[0x1b710b35,0x131c471b],
    [0x28db77f5,0x23047d84],[0x32caab7b,0x40c72493],[0x3c9ebe0a,0x15c9bebc],[0x431d67c4,0x9c100d4c],
    [0x4cc5d4be,0xcb3e42b6],[0x597f299c,0xfc657e2a],[0x5fcb6fab,0x3ad6faec],[0x6c44198c,0x4a475817]
  ];

  function u64(hi, lo) { return { hi: hi >>> 0, lo: lo >>> 0 }; }
  function add64(a, b) {
    var lo = (a.lo + b.lo) >>> 0;
    var carry = (lo < (a.lo >>> 0)) ? 1 : 0;
    var hi = (a.hi + b.hi + carry) >>> 0;
    return u64(hi, lo);
  }
  function add64_4(a,b,c,d){ return add64(add64(a,b), add64(c,d)); }
  function add64_5(a,b,c,d,e){ return add64(add64_4(a,b,c,d), e); }
  function rotr64(x, n) {
    if (n === 0) return u64(x.hi, x.lo);
    if (n < 32) {
      var lo = ((x.lo >>> n) | (x.hi << (32 - n))) >>> 0;
      var hi = ((x.hi >>> n) | (x.lo << (32 - n))) >>> 0;
      return u64(hi, lo);
    } else if (n === 32) {
      return u64(x.lo, x.hi);
    } else {
      var n2 = n - 32;
      var lo2 = ((x.hi >>> n2) | (x.lo << (32 - n2))) >>> 0;
      var hi2 = ((x.lo >>> n2) | (x.hi << (32 - n2))) >>> 0;
      return u64(hi2, lo2);
    }
  }
  function shr64(x, n) {
    if (n === 0) return u64(x.hi, x.lo);
    if (n < 32) {
      var lo = ((x.lo >>> n) | (x.hi << (32 - n))) >>> 0;
      var hi = (x.hi >>> n) >>> 0;
      return u64(hi, lo);
    } else {
      var lo2 = (x.hi >>> (n - 32)) >>> 0;
      return u64(0, lo2);
    }
  }
  function xor64(a,b){ return u64((a.hi ^ b.hi) >>> 0, (a.lo ^ b.lo) >>> 0); }
  function and64(a,b){ return u64((a.hi & b.hi) >>> 0, (a.lo & b.lo) >>> 0); }
  function not64(a){ return u64((~a.hi) >>> 0, (~a.lo) >>> 0); }

  function sha512(message) {
    var H = [
      u64(0x6a09e667,0xf3bcc908), u64(0xbb67ae85,0x84caa73b),
      u64(0x3c6ef372,0xfe94f82b), u64(0xa54ff53a,0x5f1d36f1),
      u64(0x510e527f,0xade682d1), u64(0x9b05688c,0x2b3e6c1f),
      u64(0x1f83d9ab,0xfb41bd6b), u64(0x5be0cd19,0x137e2179)
    ];
    var l = message.length;
    var withOne = l + 1;
    var padLen = ((withOne + 16) % 128 === 0) ? 0 : 128 - ((withOne + 16) % 128);
    var totalLen = withOne + padLen + 16;
    var buf = new Uint8Array(totalLen);
    buf.set(message, 0);
    buf[l] = 0x80;
    var bitLenLo = (l * 8) >>> 0;
    var bitLenHiPart = Math.floor(l / 0x20000000);
    var view = new DataView(buf.buffer);
    view.setUint32(totalLen - 4, bitLenLo, false);
    view.setUint32(totalLen - 8, bitLenHiPart, false);

    var W = new Array(80);
    for (var offset = 0; offset < totalLen; offset += 128) {
      for (var t = 0; t < 16; t++) {
        var o = offset + t * 8;
        W[t] = u64(view.getUint32(o, false), view.getUint32(o + 4, false));
      }
      for (var t2 = 16; t2 < 80; t2++) {
        var w15 = W[t2-15], w2 = W[t2-2];
        var s0 = xor64(xor64(rotr64(w15,1), rotr64(w15,8)), shr64(w15,7));
        var s1 = xor64(xor64(rotr64(w2,19), rotr64(w2,61)), shr64(w2,6));
        W[t2] = add64_4(W[t2-16], s0, W[t2-7], s1);
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (var t3 = 0; t3 < 80; t3++) {
        var S1 = xor64(xor64(rotr64(e,14), rotr64(e,18)), rotr64(e,41));
        var ch = xor64(and64(e,f), and64(not64(e), g));
        var temp1 = add64_5(h, S1, ch, u64(K512[t3][0],K512[t3][1]), W[t3]);
        var S0 = xor64(xor64(rotr64(a,28), rotr64(a,34)), rotr64(a,39));
        var maj = xor64(xor64(and64(a,b), and64(a,c)), and64(b,c));
        var temp2 = add64(S0, maj);
        h=g; g=f; f=e; e=add64(d,temp1); d=c; c=b; b=a; a=add64(temp1,temp2);
      }
      H[0]=add64(H[0],a); H[1]=add64(H[1],b); H[2]=add64(H[2],c); H[3]=add64(H[3],d);
      H[4]=add64(H[4],e); H[5]=add64(H[5],f); H[6]=add64(H[6],g); H[7]=add64(H[7],h);
    }
    var out = new Uint8Array(64);
    var ov = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) {
      ov.setUint32(i*8, H[i].hi, false);
      ov.setUint32(i*8+4, H[i].lo, false);
    }
    return out;
  }

  function concatBytes() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var off = 0;
    for (var i2 = 0; i2 < arguments.length; i2++) {
      out.set(arguments[i2], off);
      off += arguments[i2].length;
    }
    return out;
  }

  NemHD.sha256 = sha256;
  NemHD.sha512 = sha512;
  NemHD.concatBytes = concatBytes;
})();

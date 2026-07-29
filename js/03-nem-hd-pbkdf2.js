/**
 * 03-nem-hd-pbkdf2.js — HMAC-SHA512 and PBKDF2-HMAC-SHA512 (2048 rounds for
 * BIP-39 seed derivation, per spec). Depends on: 01-nem-hd-bytes.js,
 * 02-nem-hd-hash.js.
 */
(function () {
  'use strict';
  var NemHD = window.NemHD;
  var sha512 = NemHD.sha512;
  var concatBytes = NemHD.concatBytes;

  function hmacSha512(key, message) {
    var blockSize = 128;
    if (key.length > blockSize) key = sha512(key);
    if (key.length < blockSize) {
      var k2 = new Uint8Array(blockSize);
      k2.set(key, 0);
      key = k2;
    }
    var oKeyPad = new Uint8Array(blockSize);
    var iKeyPad = new Uint8Array(blockSize);
    for (var i = 0; i < blockSize; i++) {
      oKeyPad[i] = key[i] ^ 0x5c;
      iKeyPad[i] = key[i] ^ 0x36;
    }
    var inner = sha512(concatBytes(iKeyPad, message));
    return sha512(concatBytes(oKeyPad, inner));
  }

  function pbkdf2Sha512(password, salt, iterations, keylen) {
    var hLen = 64;
    var l = Math.ceil(keylen / hLen);
    var out = new Uint8Array(l * hLen);
    for (var i = 1; i <= l; i++) {
      var intBlock = new Uint8Array(4);
      var dv = new DataView(intBlock.buffer);
      dv.setUint32(0, i, false);
      var u = hmacSha512(password, concatBytes(salt, intBlock));
      var t = u.slice();
      for (var c = 1; c < iterations; c++) {
        u = hmacSha512(password, u);
        for (var j = 0; j < hLen; j++) t[j] ^= u[j];
      }
      out.set(t, (i - 1) * hLen);
    }
    return out.slice(0, keylen);
  }

  NemHD.hmacSha512 = hmacSha512;
  NemHD.pbkdf2Sha512 = pbkdf2Sha512;
})();

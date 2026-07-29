/**
 * 05-nem-hd-slip0010.js — SLIP-0010 hardened-only key derivation for the
 * ed25519 curve. Depends on: 01-nem-hd-bytes.js, 02-nem-hd-hash.js,
 * 03-nem-hd-pbkdf2.js (for hmacSha512).
 */
(function () {
  'use strict';
  var NemHD = window.NemHD;
  var hmacSha512 = NemHD.hmacSha512;
  var concatBytes = NemHD.concatBytes;
  var utf8Bytes = NemHD.utf8Bytes;

  function ser32(i) {
    var b = new Uint8Array(4);
    b[0] = (i >>> 24) & 0xff;
    b[1] = (i >>> 16) & 0xff;
    b[2] = (i >>> 8) & 0xff;
    b[3] = i & 0xff;
    return b;
  }

  function deriveEd25519Master(seed) {
    var key = utf8Bytes('ed25519 seed');
    var I = hmacSha512(key, seed);
    return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
  }

  function ckdPrivHardened(kpar, cpar, index) {
    var hardenedIndex = (index >>> 0) | 0x80000000;
    var data = concatBytes(new Uint8Array([0]), kpar, ser32(hardenedIndex));
    var I = hmacSha512(cpar, data);
    return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
  }

  // path like "m/44'/43'/0'/0'/0'" — every segment must be hardened (').
  function derivePath(seed, path) {
    var segments = path.split('/').slice(1).map(function (s) {
      return parseInt(s.replace("'", ''), 10);
    });
    var node = deriveEd25519Master(seed);
    for (var i = 0; i < segments.length; i++) {
      node = ckdPrivHardened(node.key, node.chainCode, segments[i]);
    }
    return node;
  }

  NemHD.deriveEd25519Master = deriveEd25519Master;
  NemHD.ckdPrivHardened = ckdPrivHardened;
  NemHD.derivePath = derivePath;
})();

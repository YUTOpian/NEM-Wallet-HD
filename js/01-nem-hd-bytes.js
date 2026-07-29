/**
 * 01-nem-hd-bytes.js — shared byte/encoding helpers for the NemHD module set.
 * Must be loaded FIRST: it creates the shared `window.NemHD` namespace that
 * every other nem-hd-*.js file attaches to.
 *
 * Load order (all plain <script> tags, no bundler, no ES modules):
 *   01-nem-hd-bytes.js
 *   02-nem-hd-hash.js       (SHA-256 / SHA-512)
 *   03-nem-hd-pbkdf2.js     (HMAC-SHA512 / PBKDF2-HMAC-SHA512, 2048 rounds)
 *   04-nem-hd-bip39.js      (mnemonic <-> entropy <-> seed)
 *   05-nem-hd-slip0010.js   (ed25519 HD key derivation)
 *   06-nem-hd-derive.js     (BIP-44 path, SLIP-44 coin type 43, NEM key)
 *   mnemonic-wallet.js      (UI / AngularJS wiring — unchanged behaviour)
 */
(function () {
  'use strict';
  window.NemHD = window.NemHD || {};
  var NemHD = window.NemHD;

  function bytesToHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return s;
  }

  function utf8Bytes(str) {
    return new Uint8Array(new TextEncoder().encode(str));
  }

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    window.crypto.getRandomValues(b);
    return b;
  }

  NemHD.bytesToHex = bytesToHex;
  NemHD.utf8Bytes = utf8Bytes;
  NemHD.hexToBytes = hexToBytes;
  NemHD.randomBytes = randomBytes;
})();

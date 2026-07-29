/**
 * 06-nem-hd-derive.js — BIP-44 derivation path (m/44'/coin'/account'/0'/0')
 * using NEM's registered SLIP-44 coin type 43, wired up to produce a NEM
 * private key straight from a mnemonic.
 * Depends on: 01-nem-hd-bytes.js, 04-nem-hd-bip39.js, 05-nem-hd-slip0010.js.
 */
(function () {
  'use strict';
  var NemHD = window.NemHD;
  var mnemonicToSeed = NemHD.mnemonicToSeed;
  var derivePath = NemHD.derivePath;
  var bytesToHex = NemHD.bytesToHex;

  // NEM's registered SLIP-44 coin type.
  var NEM_COIN_TYPE = 43;

  function nemPrivateKeyFromMnemonic(mnemonic, passphrase, accountIndex) {
    accountIndex = accountIndex || 0;
    var seed = mnemonicToSeed(mnemonic, passphrase);
    var node = derivePath(seed, "m/44'/" + NEM_COIN_TYPE + "'/" + accountIndex + "'/0'/0'");
    return bytesToHex(node.key);
  }

  NemHD.NEM_COIN_TYPE = NEM_COIN_TYPE;
  NemHD.nemPrivateKeyFromMnemonic = nemPrivateKeyFromMnemonic;
})();

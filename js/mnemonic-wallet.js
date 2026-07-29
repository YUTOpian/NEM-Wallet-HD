/**
 * mnemonic-wallet.js — BIP-39 mnemonic wallet creation & import for NEM Wallet
 * ---------------------------------------------------------------------------
 * Adds two things to the running app, without touching main.js:
 *   1. A "Mnemonic wallet" button (bottom-right) that opens a small dialog to
 *      either GENERATE a new 12/24-word BIP-39 mnemonic and create a wallet
 *      from it, or IMPORT an existing BIP-39 mnemonic into a new wallet.
 *   2. UI wiring only. The actual key derivation now lives in the NemHD.*
 *      modules (loaded before this file — see load order below):
 *        - SHA-256 / SHA-512 / HMAC-SHA512 / PBKDF2-HMAC-SHA512 (BIP-39)
 *        - SLIP-0010 derivation for the ed25519 curve (hardened-only),
 *          using NEM's registered SLIP-44 coin type 43, at path
 *              m / 44' / 43' / <account>' / 0' / 0'
 *          which is the same scheme used by NEM-compatible hardware
 *          wallets / other multi-currency wallets, so a mnemonic generated
 *          here can be restored elsewhere (and vice-versa).
 *
 * Load order (plain <script> tags, no bundler, no ES modules):
 *   01-nem-hd-bytes.js
 *   02-nem-hd-hash.js
 *   03-nem-hd-pbkdf2.js
 *   04-nem-hd-bip39.js
 *   05-nem-hd-slip0010.js
 *   06-nem-hd-derive.js
 *   mnemonic-wallet.js   <- this file, loaded last
 *
 * The derived 32-byte key is handed to the app's own, already-audited
 * `WalletBuilder.createPrivateKeyWallet(...)` pipeline (the exact same
 * function used by the existing "import private key" flow), so the
 * resulting wallet is encrypted/stored/decrypted with the exact same code
 * path as every other wallet in the app. This file never re-implements
 * wallet encryption/decryption.
 *
 * IMPORTANT ABOUT NEM's ECOSYSTEM:
 * The original NEM (NIS1) wallet standard has no *official* mnemonic spec.
 * This implementation uses BIP-39 (mnemonic -> seed) + SLIP-0010 (seed ->
 * ed25519 key), coin type 43 (NEM's registered SLIP-44 number). This is a
 * commonly used, standard, well-documented combination (the same one used
 * for HD derivation of NEM keys on hardware wallets), but please note it is
 * a convention, not something enforced by the NEM protocol itself — as long
 * as this script (or another implementation using the same standard) is used
 * for both creation and recovery, the wallet will always be derivable from
 * its mnemonic.
 *
 * Fails safe: any unexpected error anywhere in this file only disables the
 * mnemonic-wallet button; it never breaks the rest of the app.
 */
(function () {
  'use strict';

  if (!window.NemHD) {
    console.error('mnemonic-wallet.js: NemHD modules not loaded — check <script> order.');
    return;
  }
  var NemHD = window.NemHD;
  var bytesToHex = NemHD.bytesToHex;
  var hexToBytes = NemHD.hexToBytes;
  var utf8Bytes = NemHD.utf8Bytes;
  var randomBytes = NemHD.randomBytes;
  var generateMnemonic = NemHD.generateMnemonic;
  var validateMnemonic = NemHD.validateMnemonic;
  var nemPrivateKeyFromMnemonic = NemHD.nemPrivateKeyFromMnemonic;

  // Mnemonic backup storage (encrypted at rest with the wallet password,
  // via the browser's own Web Crypto AES-GCM implementation — this file
  // never re-implements AES itself). Stored separately from `wallets` so
  // it never interferes with anything the rest of the app reads/writes.
  //////////////////////////////////////////////////////////////////////////

  function encryptMnemonicBackup(mnemonic, password) {
    if (!window.crypto || !window.crypto.subtle) return Promise.reject(new Error('Web Crypto not available'));
    var salt = randomBytes(16);
    var iv = randomBytes(12);
    return window.crypto.subtle.importKey('raw', utf8Bytes(password), { name: 'PBKDF2' }, false, ['deriveKey']).then(function (keyMaterial) {
      return window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
      );
    }).then(function (key) {
      return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, utf8Bytes(mnemonic));
    }).then(function (cipherBuf) {
      return { salt: bytesToHex(salt), iv: bytesToHex(iv), ciphertext: bytesToHex(new Uint8Array(cipherBuf)) };
    });
  }

  function decryptMnemonicBackup(backup, password) {
    if (!window.crypto || !window.crypto.subtle) return Promise.reject(new Error('Web Crypto not available'));
    var salt = hexToBytes(backup.salt);
    var iv = hexToBytes(backup.iv);
    return window.crypto.subtle.importKey('raw', utf8Bytes(password), { name: 'PBKDF2' }, false, ['deriveKey']).then(function (keyMaterial) {
      return window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
    }).then(function (key) {
      return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, hexToBytes(backup.ciphertext));
    }).then(function (plainBuf) {
      return new TextDecoder().decode(plainBuf);
    });
    // Wrong password => AES-GCM auth tag check fails => promise rejects.
  }

  function getBackups(injector) {
    var storage = injector.get('$localStorage');
    return storage.mnemonicBackups || {};
  }

  function saveBackup(injector, address, backup) {
    var storage = injector.get('$localStorage');
    var backups = Object.assign({}, storage.mnemonicBackups || {});
    backups[address] = backup;
    storage.mnemonicBackups = backups;
    injector.get('$rootScope').$applyAsync();
  }

  function deleteBackup(injector, address) {
    var storage = injector.get('$localStorage');
    var backups = Object.assign({}, storage.mnemonicBackups || {});
    delete backups[address];
    storage.mnemonicBackups = backups;
    injector.get('$rootScope').$applyAsync();
  }
  //////////////////////////////////////////////////////////////////////////
  // Small DOM helpers
  //////////////////////////////////////////////////////////////////////////

  function el(tag, styles, attrs) {
    var e = document.createElement(tag);
    if (styles) for (var k in styles) if (styles.hasOwnProperty(k)) e.style[k] = styles[k];
    if (attrs) for (var a in attrs) if (attrs.hasOwnProperty(a)) e.setAttribute(a, attrs[a]);
    return e;
  }

  function formGroup(labelText, inputEl) {
    var wrap = el('div', {}, { 'class': 'form-group' });
    var label = document.createElement('label');
    label.textContent = labelText;
    wrap.appendChild(label);
    wrap.appendChild(inputEl);
    return wrap;
  }

  function textInput(placeholder, type) {
    return el('input', {}, { type: type || 'text', 'class': 'form-control', placeholder: placeholder || '' });
  }

  function showMessage(container, text, isError) {
    var m = container._msgEl;
    if (!m) {
      m = el('p', { marginTop: '10px' });
      container.appendChild(m);
      container._msgEl = m;
    }
    m.textContent = text;
    m.className = isError ? 'bg-danger' : 'bg-success';
  }

  //////////////////////////////////////////////////////////////////////////
  // Wallet creation, shared by every entry point in this file. Reuses the
  // app's own WalletBuilder.createPrivateKeyWallet(...) pipeline (the exact
  // function behind "import private key") so storage / encryption /
  // decryption stay 100% consistent with every other wallet in the app,
  // then logs straight into the new wallet the same way the normal signup
  // flow does.
  //////////////////////////////////////////////////////////////////////////

  function finalizeWallet(injector, opts, onDone, onError) {
    try {
      var WalletBuilder = injector.get('WalletBuilder');
      var AddressBook = injector.get('AddressBook');
      var storage = injector.get('$localStorage');
      var ngToast = injector.get('ngToast');
      var rootScope = injector.get('$rootScope');
      var Login = injector.get('Login');

      WalletBuilder.createPrivateKeyWallet(opts.walletName, opts.password, opts.privateKey, opts.network).then(function (wallet) {
        if (!wallet || typeof wallet !== 'object') { onError('ウォレットを作成できませんでした（入力内容を確認するか、同じ名前のウォレットが既にあります）。'); return; }
        try {
          AddressBook.addAccount(wallet.accounts[0].address);
          storage.wallets = (storage.wallets || []).concat(wallet);
          ngToast.create({ className: 'success', content: 'ニーモニックからウォレットを作成しました。' });

          var common = { password: opts.password, privateKey: '', isHW: false };
          var loggedIn = false;
          try { loggedIn = Login.login(common, wallet); } catch (e3) { loggedIn = false; }

          rootScope.$applyAsync();
          onDone(wallet, loggedIn);
        } catch (e2) {
          onError('ウォレットは作成されましたが保存に失敗しました: ' + e2.message);
        }
      }, function () {
        onError('ウォレットを作成できませんでした（入力内容を確認するか、同じ名前のウォレットが既にあります）。');
      });
    } catch (e) {
      onError('予期しないエラー: ' + e.message);
    }
  }

  //////////////////////////////////////////////////////////////////////////
  // Create / Import panel — a single reusable piece of UI, used inline on
  // the signup page (no floating window, no separate modal).
  //////////////////////////////////////////////////////////////////////////

  var NETWORKS = [
    { id: 104, label: 'メインネット' },
    { id: -104, label: 'テストネット' }
  ];

  function buildAdvancedFields() {
    var wrap = document.createDocumentFragment();
    var toggle = el('a', { display: 'inline-block', marginBottom: '10px', cursor: 'pointer' }, { href: '' });
    toggle.textContent = '詳細オプション（パスフレーズ／アカウント番号）';
    var box = el('div', { display: 'none' });
    var passphraseInput = textInput('追加パスフレーズ（省略可・25番目の単語）');
    box.appendChild(formGroup('パスフレーズ（省略可）', passphraseInput));
    var accountIndexInput = textInput('0');
    accountIndexInput.value = '0';
    box.appendChild(formGroup('アカウント番号', accountIndexInput));
    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
    });
    wrap.appendChild(toggle);
    wrap.appendChild(box);
    return { frag: wrap, passphraseInput: passphraseInput, accountIndexInput: accountIndexInput };
  }

  function buildCommonFields() {
    var frag = document.createDocumentFragment();
    var nameInput = textInput('例）マイウォレット');
    frag.appendChild(formGroup('ウォレット名', nameInput));
    var passInput = textInput('8文字以上を入力', 'password');
    frag.appendChild(formGroup('パスワード', passInput));
    var passConfirm = textInput('パスワード（確認）', 'password');
    frag.appendChild(formGroup('パスワード（確認）', passConfirm));
    var networkSelect = el('select', {}, { 'class': 'form-control' });
    NETWORKS.forEach(function (n) {
      var opt = el('option', {}, { value: String(n.id) });
      opt.textContent = n.label;
      networkSelect.appendChild(opt);
    });
    frag.appendChild(formGroup('ネットワーク', networkSelect));
    var adv = buildAdvancedFields();
    frag.appendChild(adv.frag);
    return {
      frag: frag, nameInput: nameInput, passInput: passInput, passConfirm: passConfirm,
      networkSelect: networkSelect, passphraseInput: adv.passphraseInput, accountIndexInput: adv.accountIndexInput
    };
  }

  function validateCommon(fields, msgContainer) {
    if (!fields.nameInput.value.trim()) { showMessage(msgContainer, 'ウォレット名を入力してください。', true); return null; }
    if (!fields.passInput.value || fields.passInput.value.length < 8) { showMessage(msgContainer, 'パスワードは8文字以上にしてください。', true); return null; }
    if (fields.passInput.value !== fields.passConfirm.value) { showMessage(msgContainer, 'パスワードが一致しません。', true); return null; }
    var accountIndex = parseInt(fields.accountIndexInput.value, 10);
    if (isNaN(accountIndex) || accountIndex < 0) accountIndex = 0;
    return {
      walletName: fields.nameInput.value.trim(), password: fields.passInput.value,
      network: parseInt(fields.networkSelect.value, 10), passphrase: fields.passphraseInput.value || '',
      accountIndex: accountIndex
    };
  }

  function buildCreatePanel(injector, onDone) {
    var pane = el('div', {}, { 'class': 'form-group' });

    var mnemonicBox = el('p', { fontFamily: 'monospace', wordBreak: 'break-word', filter: 'blur(4px)' }, { 'class': 'bg-info' });
    var currentMnemonic = generateMnemonic(256);
    mnemonicBox.textContent = currentMnemonic;
    pane.appendChild(mnemonicBox);

    var revealed = false;
    var actionsRow = el('div', { display: 'flex', gap: '8px', marginBottom: '10px' });
    var revealBtn = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-default' });
    revealBtn.textContent = '表示する';
    var copyBtn = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-default' });
    copyBtn.textContent = 'コピー';
    function setRevealed(v) {
      revealed = v;
      mnemonicBox.style.filter = revealed ? 'none' : 'blur(4px)';
      revealBtn.textContent = revealed ? '隠す' : '表示する';
    }
    revealBtn.addEventListener('click', function () { setRevealed(!revealed); });
    copyBtn.addEventListener('click', function () {
      setRevealed(true);
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(currentMnemonic);
        copyBtn.textContent = 'コピーしました';
        setTimeout(function () { copyBtn.textContent = 'コピー'; }, 1500);
      } catch (e) { /* clipboard unavailable: words are already shown for manual copy */ }
    });
    actionsRow.appendChild(revealBtn); actionsRow.appendChild(copyBtn);
    pane.appendChild(actionsRow);

    var warn = el('p', {}, { 'class': 'bg-warning' });
    warn.textContent = 'この単語列を順番通りに書き留め、オフラインの安全な場所に保管してください。このフレーズを知る人は誰でも資金を送金できます。';
    pane.appendChild(warn);

    function regen() {
      currentMnemonic = generateMnemonic(256);
      mnemonicBox.textContent = currentMnemonic;
      setRevealed(false);
      setBackupChecked(false);
    }

    var refreshLink = el('a', { display: 'inline-block', marginBottom: '10px', cursor: 'pointer' }, { href: '' });
    refreshLink.textContent = '別のフレーズを生成する';
    refreshLink.addEventListener('click', function (e) { e.preventDefault(); regen(); });
    pane.appendChild(refreshLink);

    var backupChecked = false;
    var backupRow = el('div', {
      display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer', padding: '10px',
      borderRadius: '4px', border: '1px solid #d43f3a', marginBottom: '14px'
    });
    var backupBox = el('div', {
      width: '20px', height: '20px', minWidth: '20px', borderRadius: '3px', border: '2px solid #d43f3a',
      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: '0'
    });
    var backupText = el('span', {
      color: '#333333', fontSize: '13px', lineHeight: '1.4', display: 'inline-block',
      flex: '1 1 auto', whiteSpace: 'normal'
    });
    backupText.textContent = 'このニーモニックフレーズを書き留め、安全に保管しました。';
    backupRow.appendChild(backupBox); backupRow.appendChild(backupText);
    pane.appendChild(backupRow);
    var backupCheck = { checked: false };
    function setBackupChecked(v) {
      backupChecked = v; backupCheck.checked = v;
      backupBox.style.background = v ? '#3c763d' : 'transparent';
      backupBox.style.borderColor = v ? '#3c763d' : '#d43f3a';
      backupBox.textContent = v ? '\u2713' : '';
      backupRow.style.borderColor = v ? '#3c763d' : '#d43f3a';
    }
    backupRow.addEventListener('click', function () { setBackupChecked(!backupChecked); });

    var fields = buildCommonFields();
    pane.appendChild(fields.frag);

    var submitBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-primary' });
    submitBtn.textContent = 'ウォレットを作成';
    pane.appendChild(submitBtn);

    submitBtn.addEventListener('click', function () {
      if (!backupCheck.checked) { showMessage(pane, 'ニーモニックフレーズをバックアップしたことを確認してください。', true); return; }
      var common = validateCommon(fields, pane);
      if (!common) return;
      submitBtn.disabled = true;
      submitBtn.textContent = '作成中...';
      try {
        var privateKey = nemPrivateKeyFromMnemonic(currentMnemonic, common.passphrase, common.accountIndex);
        finalizeWallet(injector, {
          walletName: common.walletName, password: common.password, network: common.network, privateKey: privateKey
        }, function (wallet, loggedIn) {
          submitBtn.textContent = '完了';
          encryptMnemonicBackup(currentMnemonic, common.password).then(function (backup) {
            saveBackup(injector, wallet.accounts[0].address, backup);
          }).catch(function () { /* backup storage is best-effort */ });
          showMessage(pane, loggedIn ? 'ウォレット「' + common.walletName + '」を作成しました。ダッシュボードに移動します...' : 'ウォレットは作成されましたが自動的に開けませんでした。ログイン画面から選択してください。', !loggedIn);
          if (onDone) onDone(wallet, loggedIn);
        }, function (msg) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'ウォレットを作成';
          showMessage(pane, msg, true);
        });
      } catch (e) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'ウォレットを作成';
        showMessage(pane, 'このニーモニックから鍵を導出できませんでした: ' + e.message, true);
      }
    });

    return pane;
  }

  function buildImportPanel(injector, onDone) {
    var pane = el('div', {}, { 'class': 'form-group' });

    var mnemonicArea = el('textarea', { fontFamily: 'monospace', minHeight: '70px' }, { 'class': 'form-control', placeholder: '12語または24語のニーモニックフレーズをスペース区切りで入力してください' });
    pane.appendChild(formGroup('ニーモニックフレーズ', mnemonicArea));

    var validityMsg = el('p', { fontSize: '12px' });
    pane.appendChild(validityMsg);

    mnemonicArea.addEventListener('input', function () {
      var v = validateMnemonic(mnemonicArea.value);
      if (!mnemonicArea.value.trim()) { validityMsg.textContent = ''; return; }
      if (v.valid) {
        validityMsg.textContent = '有効なニーモニックフレーズです。';
        validityMsg.style.color = '#3c763d';
      } else {
        var reasons = {
          WORD_COUNT: '単語数は12, 15, 18, 21, 24のいずれかである必要があります。',
          UNKNOWN_WORD: '認識できない単語です: ' + (v.word || ''),
          CHECKSUM: 'チェックサムが一致しません。単語と順番を確認してください。',
          EMPTY: 'ニーモニックフレーズを入力してください。'
        };
        validityMsg.textContent = reasons[v.reason] || '無効なニーモニックフレーズです。';
        validityMsg.style.color = '#a94442';
      }
    });

    var fields = buildCommonFields();
    pane.appendChild(fields.frag);

    var submitBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-primary' });
    submitBtn.textContent = 'ウォレットをインポート';
    pane.appendChild(submitBtn);

    submitBtn.addEventListener('click', function () {
      var v = validateMnemonic(mnemonicArea.value);
      if (!v.valid) { showMessage(pane, '有効なニーモニックフレーズを入力してください。', true); return; }
      var common = validateCommon(fields, pane);
      if (!common) return;
      submitBtn.disabled = true;
      submitBtn.textContent = 'インポート中...';
      try {
        var privateKey = nemPrivateKeyFromMnemonic(mnemonicArea.value.trim(), common.passphrase, common.accountIndex);
        finalizeWallet(injector, {
          walletName: common.walletName, password: common.password, network: common.network, privateKey: privateKey
        }, function (wallet, loggedIn) {
          submitBtn.textContent = '完了';
          encryptMnemonicBackup(mnemonicArea.value.trim(), common.password).then(function (backup) {
            saveBackup(injector, wallet.accounts[0].address, backup);
          }).catch(function () { /* backup storage is best-effort */ });
          showMessage(pane, loggedIn ? 'ウォレット「' + common.walletName + '」をインポートしました。ダッシュボードに移動します...' : 'ウォレットはインポートされましたが自動的に開けませんでした。ログイン画面から選択してください。', !loggedIn);
          if (onDone) onDone(wallet, loggedIn);
        }, function (msg) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'ウォレットをインポート';
          showMessage(pane, msg, true);
        });
      } catch (e) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'ウォレットをインポート';
        showMessage(pane, 'このニーモニックから鍵を導出できませんでした: ' + e.message, true);
      }
    });

    return pane;
  }


  //////////////////////////////////////////////////////////////////////////
  // Template patches — insert new markup into the app's own real templates
  // (fetched from $templateCache, patched, put back), instead of using a
  // separate floating window. Idempotent: safe to call repeatedly.
  //////////////////////////////////////////////////////////////////////////

  function patchSignupTemplate(injector) {
    try {
      var $templateCache = injector.get('$templateCache');
      var html = $templateCache.get('modules/signup/signup.html');
      if (!html || html.indexOf('hdWalletContainer') !== -1) return;

      var hdContainer = [
        '<div class="col-md-offset-3 col-md-6" id="hdWalletContainer" style="display:none;">',
        '  <div class="form-group text-center">',
        '    <button type="button" class="btn btn-dark" id="hdWalletBackBtn" style="width:auto;"><span class="fa fa-chevron-left" aria-hidden="true"></span> 戻る</button>',
        '  </div>',
        '  <ul class="nav nav-tabs" style="margin-bottom:15px;">',
        '    <li class="active" id="hdTabCreateLi"><a href="" id="hdTabCreate" style="color:#333;">新規作成</a></li>',
        '    <li id="hdTabImportLi"><a href="" id="hdTabImport" style="color:#333;">インポート</a></li>',
        '  </ul>',
        '  <div id="hdTabBody"></div>',
        '</div>'
      ].join('\n');

      var insertAnchor = '<!-- Start the signup process -->';
      if (html.indexOf(insertAnchor) === -1) return;
      html = html.replace(insertAnchor, hdContainer + '\n    ' + insertAnchor);

      $templateCache.put('modules/signup/signup.html', html);
    } catch (e) { /* fail safe: signup screen stays exactly as before */ }
  }

  //////////////////////////////////////////////////////////////////////////
  // HD wallet type button + info box — injected directly into the live DOM
  // (rather than into the $templateCache string) so it keeps working even
  // if the wallet-type selection screen gets re-rendered from a fresh,
  // unpatched template (e.g. after an in-app reload/reset). Runs on every
  // scanAndWire pass, so it's self-healing: idempotent checks mean it's
  // cheap to call repeatedly and safe if elements already exist.
  //////////////////////////////////////////////////////////////////////////

  function injectGlobalStyles() {
    try {
      if (document.getElementById('mnemonicWalletStyles')) return;
      var style = document.createElement('style');
      style.id = 'mnemonicWalletStyles';
      style.textContent =
        '#walletTypeButtonsRow{display:flex;flex-wrap:nowrap;gap:6px;}' +
        '#walletTypeButtonsRow button{flex:1 1 0;min-width:0;white-space:normal;padding-left:6px;padding-right:6px;font-size:13px;}';
      (document.head || document.documentElement).appendChild(style);
    } catch (e) { /* best-effort: original (wrapping) layout stays as fallback */ }
  }

  function findElementWithText(selector, text) {
    var els = document.querySelectorAll(selector);
    for (var i = 0; i < els.length; i++) {
      if (els[i].textContent.indexOf(text) !== -1) return els[i];
    }
    return null;
  }

  function ensureHdWalletUi(injector) {
    try {
      injectGlobalStyles();

      // Anchor on the "シンプルウォレット" button and its info paragraph specifically
      // (rather than a generic ng-show attribute selector, which can also match an
      // unrelated ancestor/heading wrapper and cause the injected box to land in
      // the wrong place).
      var simpleBtn = document.querySelector('button[ng-click*="changeWalletType(1)"]');
      var buttonsRow = simpleBtn && simpleBtn.parentNode;
      if (!buttonsRow) return;
      if (!buttonsRow.id) buttonsRow.id = 'walletTypeButtonsRow';

      var simpleInfoP = findElementWithText('p', 'シンプルウォレットは');
      var infoRow = simpleInfoP && simpleInfoP.parentNode;
      if (infoRow && !infoRow.id) infoRow.id = 'walletTypeInfoRow';

      var hdBtn = document.getElementById('hdWalletTypeBtn');
      if (!hdBtn) {
        hdBtn = document.createElement('button');
        hdBtn.type = 'button';
        hdBtn.id = 'hdWalletTypeBtn';
        hdBtn.className = 'btn btn-primary';
        hdBtn.textContent = 'HDウォレット';
        buttonsRow.insertBefore(hdBtn, simpleBtn);
      }

      if (infoRow && !document.getElementById('hdWalletInfoBox')) {
        var box = document.createElement('div');
        box.id = 'hdWalletInfoBox';
        box.style.display = 'none';
        box.innerHTML =
          '<p><i class="fa fa-info-circle" aria-hidden="true"></i> HDウォレットは、1つのニーモニックフレーズから複数のアカウントを生成・復元できるウォレットです。</p>' +
          '<p><i class="fa fa-warning" aria-hidden="true"></i> ニーモニックフレーズを知っている人は誰でも資金を送金できます。書き留めてオフラインの安全な場所に保管してください。</p>';
        infoRow.insertBefore(box, infoRow.firstChild);
      }

      if (hdBtn && !hdBtn._mnemonicWired) {
        hdBtn._mnemonicWired = true;
        wireSignupButton(injector, hdBtn);
      }
    } catch (e) { /* fail safe: falls back to whatever the page already shows */ }
  }

  function patchAccountTemplate(injector) {
    try {
      var $templateCache = injector.get('$templateCache');
      var html = $templateCache.get('modules/account/account.html');
      if (!html || html.indexOf('mnemBackupShowBtn') !== -1) return;

      var anchor = '<div class="panel-heading">\n          <h3>{{\'ACCOUNT_EXPORT_MOBILE\' | translate }}</h3>';
      if (html.indexOf(anchor) === -1) return; // template shape changed: bail out safely

      var panels = [
        '<div class="panel-heading">',
        '  <h3>ニーモニックのバックアップ</h3>',
        '</div>',
        '<div class="panel-body">',
        '  <div class="form-group">',
        '    <p class="bg-info">このウォレットをニーモニックフレーズから作成・インポートした場合のみ、パスワードを入力してバックアップを表示できます。</p>',
        '    <div class="input-group">',
        '      <input type="password" class="form-control" id="mnemBackupPw" placeholder="ウォレットのパスワード">',
        '      <span class="input-group-btn showHide">',
        '        <button class="btn btn-primary" type="button" id="mnemBackupShowBtn" style="margin-bottom:15px;"><i class="fa fa-plus"></i></button>',
        '      </span>',
        '    </div>',
        '    <div id="mnemBackupResult"></div>',
        '  </div>',
        '</div>',
        '',
        '<div class="panel-heading">',
        '  <h3>アカウント（ウォレット）の削除</h3>',
        '</div>',
        '<div class="panel-body">',
        '  <p class="bg-info">この端末に保存されているウォレット一覧から削除します。NEMブロックチェーン上のアカウント自体は削除されません。</p>',
        '  <div class="form-group">',
        '    <select class="form-control" id="acctDeleteSelect"></select>',
        '  </div>',
        '  <div id="acctDeleteConfirmArea"></div>',
        '  <button class="btn btn-danger" type="button" id="acctDeleteBtn" style="width:100%;">削除する</button>',
        '</div>',
        ''
      ].join('\n');

      html = html.replace(anchor, panels + anchor);
      $templateCache.put('modules/account/account.html', html);
    } catch (e) { /* fail safe: account screen stays exactly as before */ }
  }


  //////////////////////////////////////////////////////////////////////////
  // Signup page wiring
  //////////////////////////////////////////////////////////////////////////

  function renderSignupTab(injector, which) {
    var body = document.getElementById('hdTabBody');
    var liCreate = document.getElementById('hdTabCreateLi');
    var liImport = document.getElementById('hdTabImportLi');
    if (!body) return;
    liCreate.className = which === 'create' ? 'active' : '';
    liImport.className = which === 'import' ? 'active' : '';
    body.innerHTML = '';
    body.appendChild(which === 'create' ? buildCreatePanel(injector) : buildImportPanel(injector));
  }

  var WALLET_TYPE_HEADING_TEXT = 'ウォレットのタイプを選んでください';
  var HD_FLOW_HEADING_TEXT = 'HDウォレットを作成';

  function findWalletTypeHeading() {
    var candidates = document.querySelectorAll('h1, h2, h3, h4');
    for (var i = 0; i < candidates.length; i++) {
      var h = candidates[i];
      if (h._hdIsWalletTypeHeading || h.textContent.trim() === WALLET_TYPE_HEADING_TEXT) {
        h._hdIsWalletTypeHeading = true;
        return h;
      }
    }
    return null;
  }

  function setWalletTypeHeading(showHdText) {
    try {
      var h = findWalletTypeHeading();
      if (!h) return;
      h.textContent = showHdText ? HD_FLOW_HEADING_TEXT : WALLET_TYPE_HEADING_TEXT;
    } catch (e) { /* best-effort: heading text stays whatever it was */ }
  }

  function wireSignupButton(injector, hdBtn) {
    hdBtn.addEventListener('click', function () {
      var row1 = document.getElementById('walletTypeButtonsRow');
      var row2 = document.getElementById('walletTypeInfoRow');
      var container = document.getElementById('hdWalletContainer');
      if (row1) row1.style.display = 'none';
      if (row2) row2.style.display = 'none';
      if (container) container.style.display = '';
      setWalletTypeHeading(true);
      renderSignupTab(injector, 'create');
    });

    var backBtn = document.getElementById('hdWalletBackBtn');
    if (backBtn) backBtn.addEventListener('click', function () {
      var row1 = document.getElementById('walletTypeButtonsRow');
      var row2 = document.getElementById('walletTypeInfoRow');
      var container = document.getElementById('hdWalletContainer');
      if (container) container.style.display = 'none';
      if (row1) row1.style.display = '';
      if (row2) row2.style.display = '';
      setWalletTypeHeading(false);
    });

    var hdInfoBox = document.getElementById('hdWalletInfoBox');
    var infoRow = document.getElementById('walletTypeInfoRow');
    if (hdInfoBox && infoRow) {
      hdBtn.addEventListener('mouseenter', function () {
        Array.prototype.forEach.call(infoRow.children, function (child) {
          if (child !== hdInfoBox) child.style.display = 'none';
        });
        hdInfoBox.style.display = 'block';
      });
      hdBtn.addEventListener('mouseleave', function () {
        hdInfoBox.style.display = 'none';
        Array.prototype.forEach.call(infoRow.children, function (child) {
          if (child !== hdInfoBox) child.style.display = '';
        });
      });
    }

    var tabCreate = document.getElementById('hdTabCreate');
    var tabImport = document.getElementById('hdTabImport');
    if (tabCreate) tabCreate.addEventListener('click', function (e) { e.preventDefault(); renderSignupTab(injector, 'create'); });
    if (tabImport) tabImport.addEventListener('click', function (e) { e.preventDefault(); renderSignupTab(injector, 'import'); });
  }

  //////////////////////////////////////////////////////////////////////////
  // Account page wiring
  //////////////////////////////////////////////////////////////////////////

  function getCurrentAddress(injector) {
    try {
      var Wallet = injector.get('Wallet');
      return (Wallet.currentAccount && Wallet.currentAccount.address) ||
             (Wallet.current && Wallet.current.accounts && Wallet.current.accounts[0] && Wallet.current.accounts[0].address) || '';
    } catch (e) { return ''; }
  }

  function wireAccountBackup(injector, showBtn) {
    showBtn.addEventListener('click', function () {
      var pwInput = document.getElementById('mnemBackupPw');
      var result = document.getElementById('mnemBackupResult');
      result.innerHTML = '';
      var address = getCurrentAddress(injector);
      var backups = getBackups(injector);
      var backup = backups[address];
      if (!backup) { showMessage(result, 'このウォレットにはニーモニックのバックアップがありません（ニーモニックから作成／インポートしたウォレットのみ対象です）。', true); return; }

      showBtn.disabled = true;
      decryptMnemonicBackup(backup, pwInput.value).then(function (mnemonic) {
        showBtn.disabled = false;
        result.innerHTML = '';
        var box = el('p', { fontFamily: 'monospace', wordBreak: 'break-word' }, { 'class': 'bg-info' });
        box.textContent = mnemonic;
        result.appendChild(box);
        var copyBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-default' });
        copyBtn.textContent = 'コピー';
        copyBtn.addEventListener('click', function () {
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(mnemonic);
            copyBtn.textContent = 'コピーしました';
            setTimeout(function () { copyBtn.textContent = 'コピー'; }, 1500);
          } catch (e) { /* ignore */ }
        });
        result.appendChild(copyBtn);
      }).catch(function () {
        showBtn.disabled = false;
        showMessage(result, 'パスワードが違うか、バックアップを読み込めませんでした。', true);
      });
    });
  }

  function refreshDeleteSelect(injector, select) {
    var storage = injector.get('$localStorage');
    var wallets = storage.wallets || [];
    select.innerHTML = '';
    wallets.forEach(function (w, i) {
      var opt = el('option', {}, { value: String(i) });
      opt.textContent = w.name || '(no name)';
      select.appendChild(opt);
    });
  }

  function wireAccountDelete(injector, deleteBtn) {
    var select = document.getElementById('acctDeleteSelect');
    if (select) refreshDeleteSelect(injector, select);

    deleteBtn.addEventListener('click', function () {
      var confirmArea = document.getElementById('acctDeleteConfirmArea');
      confirmArea.innerHTML = '';
      var idx = parseInt(select.value, 10);
      var storage = injector.get('$localStorage');
      var wallets = storage.wallets || [];
      var wallet = wallets[idx];
      if (!wallet) { showMessage(confirmArea, '削除するウォレットを選択してください。', true); return; }

      var warn = el('p', {}, { 'class': 'bg-danger' });
      warn.textContent = 'この端末からウォレット「' + wallet.name + '」を削除します。確認のためウォレット名を入力してください。';
      confirmArea.appendChild(warn);
      var confirmInput = textInput('ウォレット名を正確に入力');
      confirmArea.appendChild(confirmInput);
      var confirmBtn = el('button', { width: '100%', marginTop: '8px' }, { type: 'button', 'class': 'btn btn-danger' });
      confirmBtn.textContent = '削除を確定';
      confirmArea.appendChild(confirmBtn);

      confirmBtn.addEventListener('click', function () {
        if (confirmInput.value !== wallet.name) { showMessage(confirmArea, '名前が一致しません。削除されませんでした。', true); return; }
        try {
          var address = (wallet.accounts && wallet.accounts[0] && wallet.accounts[0].address) || '';
          storage.wallets = wallets.filter(function (w, i) { return i !== idx; });
          deleteBackup(injector, address);

          var wasCurrent = false;
          try {
            var Wallet = injector.get('Wallet');
            if (getCurrentAddress(injector) === address) { wasCurrent = true; Wallet.current = undefined; }
          } catch (e2) { /* best-effort */ }

          injector.get('$rootScope').$applyAsync();
          refreshDeleteSelect(injector, select);
          confirmArea.innerHTML = '';
          showMessage(confirmArea, 'ウォレット「' + wallet.name + '」を削除しました。', false);
          if (wasCurrent) injector.get('$location').path('/login');
        } catch (e) {
          showMessage(confirmArea, '削除に失敗しました: ' + e.message, true);
        }
      });
    });
  }

  //////////////////////////////////////////////////////////////////////////
  // Boot: poll for the injector (mirrors dynamic-nodes.js elsewhere in this
  // app), patch templates once ready, then keep watching the DOM so newly
  // rendered pages get wired up as the user navigates around the app.
  //////////////////////////////////////////////////////////////////////////

  var INJECTOR_POLL_MS = 200;
  var INJECTOR_POLL_MAX = 50;

  function scanAndWire(injector) {
    ensureHdWalletUi(injector);

    var backupBtn = document.getElementById('mnemBackupShowBtn');
    if (backupBtn && !backupBtn._mnemonicWired) { backupBtn._mnemonicWired = true; wireAccountBackup(injector, backupBtn); }

    var deleteBtn = document.getElementById('acctDeleteBtn');
    if (deleteBtn && !deleteBtn._mnemonicWired) { deleteBtn._mnemonicWired = true; wireAccountDelete(injector, deleteBtn); }
  }

  function onInjectorReady(injector) {
    patchSignupTemplate(injector);
    patchAccountTemplate(injector);
    scanAndWire(injector);
    try {
      var observer = new MutationObserver(function () { scanAndWire(injector); });
      observer.observe(document.body, { childList: true, subtree: true });
    } catch (e) { /* MutationObserver unavailable: initial wiring still applied above */ }
  }

  function waitForInjector(attempt) {
    var injector = null;
    try {
      injector = window.angular && angular.element(document).injector();
    } catch (e) {
      injector = null;
    }
    if (injector) {
      try { onInjectorReady(injector); } catch (e) { /* fail safe: rest of the app is unaffected */ }
      return;
    }
    if (attempt >= INJECTOR_POLL_MAX) return;
    setTimeout(function () { waitForInjector(attempt + 1); }, INJECTOR_POLL_MS);
  }

  waitForInjector(0);
})();

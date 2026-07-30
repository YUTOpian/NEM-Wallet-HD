// js/mnemonic-wallet.js
// ニーモニック(BIP-39 + SLIP-10 ed25519)からNEMの秘密鍵を導出し、
// 「アカウント作成」画面にネイティブな "HDウォレット" タイプとして統合する。
//
// 【設計方針】
// - このNEM Walletアプリ本体(Angular/NanoWallet系)のソース(main.js)には一切手を入れない。
//   本体が起動しAngular injectorが取得できてから、$transitions を使って
//   「アカウント作成」(state: app.signup) 画面がレンダリングされたタイミングを検知し、
//   その時だけDOMへ要素を追加する。
// - 追加するのは主に:
//     1. 型選択画面の「シンプルウォレットを作成」ボタンの右に「HDウォレットを作成」ボタン
//     2. ステップ3(パスワード入力)用の「次へ」ボタン
//        (ネイティブの「次へ」はタイプ1/3専用のため、タイプ4=HDでは表示されない)
//     3. ステップ4用の独自パネル(ニーモニック入力/新規生成 → 秘密鍵プレビュー)
//   これ以降のステップ(安全確認・秘密鍵表示・完了画面)は、SignupCtrl側が
//   タイプの値を問わず共通で表示するため、そのままネイティブ実装を利用できる。
// - 最終的には SignupCtrl のインスタンス($ctrl、controllerAsで公開されている)を
//   scope経由で取得し、ニーモニックから導出した秘密鍵を
//   $ctrl.formData.privateKey に設定した上で $ctrl.createPrivateKeyWallet() を
//   呼び出すだけ。ウォレットの暗号化保存・安全確認画面・ローカルストレージへの
//   追加(WalletBuilder / arrangeSafetyProtocol / endSignup)は全て本体の
//   既存ロジックがそのまま担当するため、シンプルウォレット/プライベートキー
//   ウォレットと完全に同じ見た目・同じ安全性で「HDウォレット」を作成できる。
// - symbol-sdk(v3)はCDNから動的import()で読み込む。読み込みや導出に
//   失敗した場合は、その場にエラーメッセージを表示するだけにとどめ、
//   例外を外に漏らして他のスクリプト(main.js等)に影響しないようにする。
// - Angular側の想定と実際のテンプレート構造が変わっていた場合(将来のバージョン
//   アップ等)は、要素が見つからない時点で静かに機能を無効化する。

(function () {
  'use strict';

  var SDK_VERSION = '3.3.2';
  var BIP39_WORDLIST_URL = 'https://unpkg.com/bip39@3.1.0/src/wordlists/english.json';

  // $ctrl._selectedType.type に使う、本体未使用の値(1=シンプル/2=ブレイン/3=プライベートキー)。
  var HD_TYPE = 4;

  var INJECTOR_POLL_MS = 200;
  var INJECTOR_POLL_MAX = 50;

  var sdkCore = null;
  var NemFacade = null;
  var sdkLoadPromise = null;

  var wordlistCache = null;
  var wordlistLoadPromise = null;

  /* ============================================================
     symbol-sdk 遅延読み込み(ステップ4で最初に必要になった時にロードする)
  ============================================================ */
  function loadSdk() {
    if (sdkCore && NemFacade) return Promise.resolve();
    if (sdkLoadPromise) return sdkLoadPromise;

    sdkLoadPromise = Promise.resolve()
      .then(function () {
        return import(
          'https://unpkg.com/symbol-sdk@' + SDK_VERSION + '/dist/bundle.web.js'
        );
      })
      .then(function (sdk) {
        if (!sdk || !sdk.core || !sdk.core.Bip32 || !sdk.nem || !sdk.nem.NemFacade) {
          throw new Error(
            'symbol-sdkの読み込みに失敗しました(Bip32またはNemFacadeが見つかりません)'
          );
        }
        if (!sdk.nem.NemFacade.BIP32_CURVE_NAME) {
          throw new Error(
            'このバージョンのsymbol-sdkにはNemFacade.BIP32_CURVE_NAMEがありません。SDKのバージョンを確認してください。'
          );
        }
        sdkCore = sdk.core;
        NemFacade = sdk.nem.NemFacade;
      })
      .catch(function (e) {
        sdkLoadPromise = null; // 失敗時は次回また読み込みを試せるようにする
        throw e;
      });

    return sdkLoadPromise;
  }

  /* ============================================================
     BIP-39英単語リストの遅延読み込み(「新規生成」ボタンを押した時のみ)
  ============================================================ */
  function loadWordlist() {
    if (wordlistCache) return Promise.resolve(wordlistCache);
    if (wordlistLoadPromise) return wordlistLoadPromise;

    wordlistLoadPromise = fetch(BIP39_WORDLIST_URL, { cache: 'force-cache' })
      .then(function (res) {
        if (!res.ok) throw new Error('wordlist http ' + res.status);
        return res.json();
      })
      .then(function (list) {
        if (!Array.isArray(list) || list.length !== 2048) {
          throw new Error('単語リストの形式が想定と異なります');
        }
        wordlistCache = list;
        return list;
      })
      .catch(function (e) {
        wordlistLoadPromise = null;
        throw e;
      });

    return wordlistLoadPromise;
  }

  /* ============================================================
     BIP-39ニーモニックの新規生成(標準アルゴリズム、既定で24単語=256bit)
     entropy(乱数) → SHA-256チェックサム → 11bitずつ単語インデックスへ変換
  ============================================================ */
  function bytesToBinary(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) {
      bin += bytes[i].toString(2).padStart(8, '0');
    }
    return bin;
  }

  function generateMnemonicWords(strengthBits) {
    strengthBits = strengthBits || 256;
    return loadWordlist().then(function (wordlist) {
      var entropyBytes = crypto.getRandomValues(new Uint8Array(strengthBits / 8));
      return crypto.subtle.digest('SHA-256', entropyBytes).then(function (hashBuf) {
        var hashBytes = new Uint8Array(hashBuf);
        var entropyBits = bytesToBinary(entropyBytes);
        var checksumBitLength = strengthBits / 32;
        var checksumBits = bytesToBinary(hashBytes).slice(0, checksumBitLength);
        var bits = entropyBits + checksumBits;

        var words = [];
        for (var i = 0; i < bits.length; i += 11) {
          var idx = parseInt(bits.slice(i, i + 11), 2);
          words.push(wordlist[idx]);
        }
        return words.join(' ');
      });
    });
  }

  /* ============================================================
     ニーモニック → NEM秘密鍵 導出
     (symbol-sdk v3系の実際の使い方について:
      - bip32Path(accountIndex) は Facadeの「クラス」ではなく
        「インスタンス」のメソッド (例: facade.bip32Path(0))
      - bip32NodeToKeyPair という関数は存在しない。
        derivePath(...) が返すノードの .privateKey を直接使う
      - Bip32のコンストラクタは (curveName, language) を取る。
        curveNameは各Facadeクラスの静的プロパティ BIP32_CURVE_NAME を使う
      - 秘密鍵からアドレス/公開鍵を得るには facade.createAccount(privateKey)
      - bip32Pathの結果はNetworkType(mainnet/testnet)に依存しないため、
        パス計算のためだけに一時的にmainnetのFacadeを使って良い)
  ============================================================ */
  function derivePrivateKeyFromMnemonic(mnemonic, passphrase, accountIndex) {
    var normalized = mnemonic.trim().replace(/\s+/g, ' ');

    var bip32 = new sdkCore.Bip32(NemFacade.BIP32_CURVE_NAME, 'english');
    var root = bip32.fromMnemonic(normalized, passphrase || '');

    var tmpFacade = new NemFacade('mainnet');
    var childNode = root.derivePath(tmpFacade.bip32Path(accountIndex));

    return childNode.privateKey; // PrivateKeyインスタンス
  }

  function deriveAccountInfo(privateKey, isTestnet) {
    var identifier = isTestnet ? 'testnet' : 'mainnet';
    var facade = new NemFacade(identifier);
    var account = facade.createAccount(privateKey);

    return {
      privateKey: privateKey.toString(),
      publicKey: account.publicKey.toString(),
      address: account.address.toString()
    };
  }

  /* ============================================================
     ニーモニックを .wlt ファイル(ウォレットオブジェクトそのもの)に
     埋め込むための暗号化/復号ヘルパー。
     ウォレットのログインパスワードと同じパスワードでAES-GCM暗号化する
     (PBKDF2-HMAC-SHA256, 200,000回)。
     .wlt = base64(JSON(wallet)) というアプリ本体の仕様上、
     wallet オブジェクトに mnemonicBackup プロパティを足すだけで
     ダウンロードされる .wlt ファイルにも自動的に含まれる。
  ============================================================ */
  function toBase64(bytes) {
    var binary = '';
    bytes.forEach(function (b) { binary += String.fromCharCode(b); });
    return btoa(binary);
  }

  function fromBase64(str) {
    var binary = atob(str);
    return Uint8Array.from(binary, function (c) { return c.charCodeAt(0); });
  }

  function deriveAesKeyForWlt(password, salt) {
    var enc = new TextEncoder();
    return crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
      .then(function (keyMaterial) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: 200000, hash: 'SHA-256' },
          keyMaterial,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      });
  }

  function encryptMnemonicForWlt(mnemonic, password) {
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return deriveAesKeyForWlt(password, salt).then(function (key) {
      var enc = new TextEncoder();
      return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(mnemonic));
    }).then(function (ciphertext) {
      return {
        v: 1,
        salt: toBase64(salt),
        iv: toBase64(iv),
        data: toBase64(new Uint8Array(ciphertext))
      };
    });
  }

  function decryptMnemonicFromWlt(backup, password) {
    var salt = fromBase64(backup.salt);
    var iv = fromBase64(backup.iv);
    return deriveAesKeyForWlt(password, salt).then(function (key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, fromBase64(backup.data));
    }).then(function (plainBuf) {
      return new TextDecoder().decode(plainBuf);
    });
  }

  /* ============================================================
     小さなDOMヘルパー / debounce
  ============================================================ */
  function el(tag, attrs) {
    var node = document.createElement(tag);
    attrs = attrs || {};
    Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (k === 'text') node.textContent = v;
      else if (k.indexOf('on') === 0 && typeof v === 'function') node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    });
    for (var i = 2; i < arguments.length; i++) {
      var c = arguments[i];
      if (!c) continue;
      node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
    return node;
  }

  function debounce(fn, ms) {
    var t = null;
    return function () {
      var args = arguments;
      var ctx = this;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(ctx, args); }, ms);
    };
  }

  /* ============================================================
     Angular injector待ち → app.signup 画面への遷移を検知
  ============================================================ */
  function waitForInjector(attempt) {
    var injector = null;
    try {
      injector = window.angular && window.angular.element(document).injector();
    } catch (e) {
      injector = null;
    }
    if (injector) { onInjectorReady(injector); return; }
    if (attempt >= INJECTOR_POLL_MAX) return;
    setTimeout(function () { waitForInjector(attempt + 1); }, INJECTOR_POLL_MS);
  }

  function onInjectorReady(injector) {
    var $transitions, $state, $timeout;
    try {
      $transitions = injector.get('$transitions');
      $state = injector.get('$state');
      $timeout = injector.get('$timeout');
    } catch (e) {
      return; // 想定サービスが無いバージョン: 機能を無効化
    }

    function tryMount() {
      $timeout(function () {
        try {
          var signupPageEl = document.querySelector('.signup-page');
          if (signupPageEl) mountHdWalletFeature(signupPageEl, injector);
        } catch (e) {
          console.warn('[mnemonic-wallet] signup画面への統合に失敗しました:', e);
        }
      }, 50);
    }

    function tryMountAccount() {
      $timeout(function () {
        try {
          var accountPageEl = document.querySelector('.account-page');
          if (accountPageEl) mountAccountMnemonicPanel(accountPageEl, injector);
        } catch (e) {
          console.warn('[mnemonic-wallet] account画面への統合に失敗しました:', e);
        }
      }, 50);
    }

    try {
      $transitions.onSuccess({ to: 'app.signup' }, function () { tryMount(); });
    } catch (e) {
      /* $transitionsが無い/シグネチャが違う: 統合をあきらめる */
      return;
    }

    try {
      $transitions.onSuccess({ to: 'app.account' }, function () { tryMountAccount(); });
    } catch (e) { /* アカウント画面統合はベストエフォート */ }

    // スクリプト読み込み時点で既にsignup/account画面にいる場合(リロード等)にも対応
    try {
      if ($state.current && $state.current.name === 'app.signup') tryMount();
      if ($state.current && $state.current.name === 'app.account') tryMountAccount();
    } catch (e) {}
  }

  /* ============================================================
     アカウント作成画面への統合本体
  ============================================================ */
  function mountHdWalletFeature(signupPageEl, injector) {
    if (signupPageEl.__mnwMounted) return;
    signupPageEl.__mnwMounted = true;

    var ngScope;
    try {
      ngScope = window.angular.element(signupPageEl).scope();
    } catch (e) {
      return;
    }
    var $ctrl = ngScope && ngScope.$ctrl;
    if (
      !$ctrl ||
      typeof $ctrl.createPrivateKeyWallet !== 'function' ||
      typeof $ctrl.checkPasswordsMatch !== 'function' ||
      typeof $ctrl.hideAllSteps !== 'function' ||
      !$ctrl.formData
    ) {
      // 本体のコントローラ構造が想定と異なる: 何もせず終了(main.jsの動作には影響しない)
      return;
    }

    function apply(fn) {
      try {
        if (ngScope.$root.$$phase) fn();
        else ngScope.$apply(fn);
      } catch (e) {
        console.warn('[mnemonic-wallet] 内部エラー:', e);
      }
    }

    // signup.html には ng-show="!$ctrl._selectedType" を持つdivが2つあり、
    // ドキュメント順で 1つ目=タイプ選択ボタンの入れ物, 2つ目=タイプ説明パネルの入れ物。
    var typeSelectDivs = signupPageEl.querySelectorAll('div[ng-show="!$ctrl._selectedType"]');
    var buttonsContainer = typeSelectDivs[0];
    var infoContainer = typeSelectDivs[1];
    if (!buttonsContainer) return;

    var simpleBtn = buttonsContainer.querySelector('button[ng-click*="changeWalletType(1)"]');
    if (!simpleBtn) return;

    /* ---- 0. 「シンプルウォレット」の右に「HDウォレット」ボタンを追加 ---- */
    var hdBtn = el('button', {
      type: 'button',
      class: 'btn btn-primary',
      text: 'HDウォレットを作成',
      onmouseover: function () {
        apply(function () { $ctrl.showInfo = HD_TYPE; });
      },
      onclick: function () {
        apply(function () {
          $ctrl._selectedType = { type: HD_TYPE };
          $ctrl.start = true;
        });
      }
    });
    simpleBtn.parentNode.insertBefore(hdBtn, simpleBtn.nextSibling);

    /* ---- 説明パネル(タイプ選択画面でマウスオーバー時に表示) ---- */
    if (infoContainer) {
      var infoDiv = el(
        'div',
        { style: 'display:none;' },
        el(
          'p',
          {},
          el('span', { class: 'fa fa-info-circle', 'aria-hidden': 'true' }),
          ' ニーモニック(BIP-39)フレーズから鍵を導出してアカウントを作成します。ニーモニックさえ控えておけば、同じ単語列から何度でも同じアカウントを復元できます。'
        ),
        el(
          'p',
          {},
          el('i', { class: 'fa fa-exclamation-triangle' }),
          ' ニーモニックは秘密鍵と同じくらい重要です。画面の記録・共有は避け、紙などオフラインの安全な場所に控えてください。'
        )
      );
      infoContainer.appendChild(infoDiv);
      ngScope.$watch(
        function () { return $ctrl.showInfo; },
        function (v) { infoDiv.style.display = v === HD_TYPE ? '' : 'none'; }
      );
    }

    /* ---- タイトル(ネイティブはタイプ1/2/3専用のため、HD用に補完表示) ---- */
    var titleHost = signupPageEl.querySelector('.form-group.text-center');
    if (titleHost) {
      var titleEl = el('h4', { style: 'display:none;', text: 'HDウォレットを作成' });
      titleHost.appendChild(titleEl);
      ngScope.$watch(
        function () {
          return !!(
            $ctrl._selectedType &&
            $ctrl._selectedType.type === HD_TYPE &&
            !($ctrl.step5 || $ctrl.step6 || $ctrl.step7 || $ctrl.step8)
          );
        },
        function (show) { titleEl.style.display = show ? '' : 'none'; }
      );
    }

    /* ---- ステップ3(パスワード入力)用の「次へ」ボタン ----
       ネイティブの「次へ」はタイプ1・3専用の ng-show を持つため、
       タイプ4(HD)では表示されない。同じ見た目のボタンを追加する。 */
    var step3Container = signupPageEl.querySelector('[ng-show="$ctrl.step3"]');
    if (step3Container) {
      var step3Row = step3Container.querySelector('.row.form-group');
      if (step3Row) {
        var step3NextBtn = el('button', {
          type: 'button',
          class: 'btn btn-primary',
          style: 'width:100%;',
          onclick: function () {
            apply(function () {
              if ($ctrl.okPressed) return;
              if (!$ctrl.formData.password || !$ctrl.formData.confirmPassword) return;
              if (!$ctrl.checkPasswordsMatch()) return;
              $ctrl.step3 = false;
              $ctrl.step4 = true;
            });
          }
        });
        step3NextBtn.innerHTML = '次へ <span class="fa fa-chevron-right" aria-hidden="true"></span>';
        var step3NextCol = el('div', { class: 'col-md-10 col-sm-6', style: 'display:none;' }, step3NextBtn);
        step3Row.appendChild(step3NextCol);

        ngScope.$watch(
          function () {
            return !!($ctrl.step3 && $ctrl._selectedType && $ctrl._selectedType.type === HD_TYPE);
          },
          function (show) { step3NextCol.style.display = show ? '' : 'none'; }
        );
        ngScope.$watch(
          function () {
            return !!($ctrl.formData.password && $ctrl.formData.confirmPassword) && !$ctrl.okPressed;
          },
          function (enabled) { step3NextBtn.disabled = !enabled; }
        );
      }
    }

    /* ---- ステップ4: ニーモニック入力パネル ---- */
    mountStep4Panel(signupPageEl, ngScope, $ctrl, apply);

    /* ---- ステップ7をスキップし、ステップ8の文言をHD用に差し替え ---- */
    mountStep7SkipAndStep8Text(signupPageEl, ngScope, $ctrl, apply);
  }

  /* ============================================================
     ステップ7(プライベートキー表示)はHDウォレットでは不要なため、
     HDタイプの時だけステップ6→ステップ8に直接進むようにし、
     ステップ8の警告文を「秘密鍵」→「ニーモニックフレーズ」に差し替える。
     ネイティブのsignup.html自体は一切変更しない(HD以外のタイプは
     従来通りステップ7を通る)。
  ============================================================ */
  function mountStep7SkipAndStep8Text(signupPageEl, ngScope, $ctrl, apply) {
    var isHd = function () {
      return !!($ctrl._selectedType && $ctrl._selectedType.type === HD_TYPE);
    };

    /* ---- ステップ6→7への遷移をHDの時だけステップ8へ差し替える ---- */
    ngScope.$watch(
      function () { return !!($ctrl.step7 && isHd()); },
      function (skip) {
        if (!skip) return;
        apply(function () { $ctrl.step7 = false; $ctrl.step8 = true; });
      }
    );

    var step8Container = signupPageEl.querySelector('[ng-show="$ctrl.step8"]');
    if (!step8Container) return;

    /* ---- ステップ8の「戻る」ボタン: HDの時はステップ7を経由せずステップ6へ ----
       ネイティブのng-clickは step7=true; step8=false; のため、そのままだと
       上のwatchに即座にstep8へ戻されてしまう(＝戻るボタンが効かなくなる)。
       capture段階で先取りして処理し、ネイティブのng-clickは発火させない。 */
    var backBtn = step8Container.querySelector('button[ng-click*="step7 = true"]');
    if (backBtn) {
      backBtn.addEventListener('click', function (e) {
        if (!isHd()) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        apply(function () { $ctrl.step6 = true; $ctrl.step8 = false; });
      }, true);
    }

    /* ---- ステップ8の警告文言をHD用に差し替え ---- */
    var warningP = step8Container.querySelector('.form-group p');
    if (warningP) {
      var hdWarningP = el('p', { style: 'display:none;' },
        el('b', {},
          el('i', { class: 'fa fa-exclamation-triangle' }),
          ' あなたのニーモニックフレーズがバックアップされていることを確認した後に、あなたのアカウントに自己の責任において資金を送金してください。'
        )
      );
      warningP.parentNode.insertBefore(hdWarningP, warningP.nextSibling);

      ngScope.$watch(
        function () { return !!($ctrl.step8 && isHd()); },
        function (show) {
          warningP.style.display = show ? 'none' : '';
          hdWarningP.style.display = show ? '' : 'none';
        }
      );
    }
  }

  function mountStep4Panel(signupPageEl, ngScope, $ctrl, apply) {
    // ネイティブのタイプ3(プライベートキー)用ステップ4の直後に、HD用の独自ステップ4を挿入する。
    var privKeyStep4 = signupPageEl.querySelector(
      '[ng-show="$ctrl.step4 && $ctrl._selectedType.type === 3"]'
    );
    var host = privKeyStep4 ? privKeyStep4.parentNode : signupPageEl.querySelector('.container');
    if (!host) return;

    var deriveState = { privateKeyHex: null };

    var mnemonicInput = el('textarea', {
      class: 'form-control',
      rows: '3',
      wrap: 'soft',
      style: 'width:100%;box-sizing:border-box;white-space:pre-wrap;word-break:break-word;overflow-wrap:break-word;',
      placeholder: 'ニーモニック(12〜24単語)を入力、または下のボタンで新規生成してください'
    });
    var generateBtn = el('button', {
      type: 'button',
      class: 'btn btn-dark',
      text: '新しいニーモニックを生成(24語)'
    });
    // パスフレーズ／アカウント番号のUIは廃止。常に空パスフレーズ・アカウント番号0で導出する。
    var FIXED_PASSPHRASE = '';
    var FIXED_ACCOUNT_INDEX = 0;

    var errorText = el('p', { class: 'text-center', style: 'color:#a94442;' });
    var errorBox = el('div', { class: 'form-group', style: 'display:none;' }, errorText);

    var finalBtn = el('button', {
      type: 'button',
      class: 'btn btn-primary',
      style: 'width:100%;',
      disabled: 'disabled'
    });
    finalBtn.innerHTML = '作成 <span class="fa fa-chevron-right" aria-hidden="true"></span>';

    var backBtn = el('button', { type: 'button', class: 'btn btn-dark', style: 'width:auto;' });
    backBtn.innerHTML = '<span class="fa fa-chevron-left" aria-hidden="true"></span> 戻る';

    function showError(msg) {
      errorText.textContent = msg;
      errorBox.style.display = '';
      finalBtn.disabled = true;
      deriveState.privateKeyHex = null;
    }

    function currentNetworkKey() {
      if ($ctrl.network === 104) return 'mainnet';
      if ($ctrl.network === -104) return 'testnet';
      return null; // mijin等、symbol-sdk側のNemFacadeが対応していないネットワーク
    }

    var updatePreview = debounce(function () {
      errorBox.style.display = 'none';
      finalBtn.disabled = true;
      deriveState.privateKeyHex = null;

      var mnemonic = mnemonicInput.value.trim();
      if (!mnemonic) return;

      var netKey = currentNetworkKey();
      if (!netKey) {
        showError('このネットワークではHDウォレットの作成に対応していません(Mainnet / Testnetのみ)');
        return;
      }

      loadSdk()
        .then(function () {
          var privateKey = derivePrivateKeyFromMnemonic(mnemonic, FIXED_PASSPHRASE, FIXED_ACCOUNT_INDEX);
          var info = deriveAccountInfo(privateKey, netKey === 'testnet');
          deriveState.privateKeyHex = info.privateKey;
          finalBtn.disabled = false;
        })
        .catch(function (e) {
          showError('ニーモニックの読み込みに失敗しました: ' + (e && e.message ? e.message : e));
        });
    }, 400);

    mnemonicInput.addEventListener('input', updatePreview);

    generateBtn.addEventListener('click', function () {
      generateBtn.disabled = true;
      generateMnemonicWords(256)
        .then(function (words) {
          mnemonicInput.value = words;
          updatePreview();
        })
        .catch(function (e) {
          showError('ニーモニックの生成に失敗しました: ' + (e && e.message ? e.message : e));
        })
        .then(function () { generateBtn.disabled = false; });
    });

    backBtn.addEventListener('click', function () {
      apply(function () {
        $ctrl._selectedType = undefined;
        $ctrl.hideAllSteps();
      });
    });

    finalBtn.addEventListener('click', function () {
      if (!deriveState.privateKeyHex || finalBtn.disabled) return;
      var mnemonicToBackup = mnemonicInput.value.trim();
      apply(function () {
        $ctrl.formData.privateKey = deriveState.privateKeyHex;

        // wallet オブジェクトが出来上がった瞬間(まだ.wltダウンロードや
        // ローカルストレージ保存の前)に mnemonicBackup を足すため、
        // WalletBuilder.createPrivateKeyWallet をこの1回の呼び出しだけフックする。
        // フック関数が呼ばれた時点ですぐ元に戻すので、他の(通常の)プライベート
        // キーウォレット作成には一切影響しない。
        var wb = $ctrl._WalletBuilder;
        if (wb && typeof wb.createPrivateKeyWallet === 'function' && mnemonicToBackup) {
          var originalCreatePrivateKeyWallet = wb.createPrivateKeyWallet.bind(wb);
          wb.createPrivateKeyWallet = function (walletName, walletPassword, privateKey, network) {
            wb.createPrivateKeyWallet = originalCreatePrivateKeyWallet; // 即座に復元
            return originalCreatePrivateKeyWallet(walletName, walletPassword, privateKey, network)
              .then(function (wallet) {
                if (!wallet || typeof wallet !== 'object') return wallet;
                return encryptMnemonicForWlt(mnemonicToBackup, walletPassword)
                  .then(function (backup) {
                    wallet.mnemonicBackup = backup;
                    return wallet;
                  })
                  .catch(function () {
                    return wallet; // 暗号化に失敗してもウォレット作成自体は止めない
                  });
              });
          };
        }

        $ctrl.createPrivateKeyWallet();
      });
    });

    var panel = el(
      'div',
      { class: 'col-md-offset-3 col-md-6', style: 'display:none;' },
      el(
        'fieldset',
        { class: 'form-group' },
        mnemonicInput
      ),
      el('div', { class: 'form-group text-center' }, generateBtn),
      el(
        'p',
        { class: 'text-center', style: 'font-size:12px;color:#888;' },
        el('i', { class: 'fa fa-exclamation-triangle' }),
        ' 生成した単語列は誰にも見せず、紙などオフラインの安全な場所に書き留めてください。'
      ),
      errorBox,
      el(
        'div',
        { class: 'row form-group' },
        el('div', { class: 'col-md-2 col-sm-6' }, backBtn),
        el('div', { class: 'col-md-10 col-sm-6' }, finalBtn)
      )
    );

    host.insertBefore(panel, privKeyStep4 ? privKeyStep4.nextSibling : null);

    ngScope.$watch(
      function () {
        return !!($ctrl.step4 && $ctrl._selectedType && $ctrl._selectedType.type === HD_TYPE);
      },
      function (show) {
        panel.style.display = show ? '' : 'none';
        if (!show) {
          // ステップを離れたら、DOM/メモリ上にニーモニックを残さないよう破棄する
          mnemonicInput.value = '';
          deriveState.privateKeyHex = null;
          errorBox.style.display = 'none';
          finalBtn.disabled = true;
        }
      }
    );

    ngScope.$watch(function () { return $ctrl.network; }, function () { updatePreview(); });
  }

  /* ============================================================
     アカウント画面: ニーモニック復元パネル
     wallet.mnemonicBackup が付いているウォレット(=HDウォレット作成
     フローで作られたもの、またはそれが埋め込まれた.wltをインポートした
     もの)でのみ表示し、ウォレットのログインパスワードで復号して表示する。
  ============================================================ */
  function mountAccountMnemonicPanel(accountPageEl, injector) {
    if (accountPageEl.__mnwAcctMounted) return;
    accountPageEl.__mnwAcctMounted = true;

    var ngScope;
    try {
      ngScope = window.angular.element(accountPageEl).scope();
    } catch (e) {
      return;
    }
    var $ctrl = ngScope && ngScope.$ctrl;
    if (!$ctrl || !$ctrl._Wallet) return;

    function apply(fn) {
      try {
        if (ngScope.$root.$$phase) fn();
        else ngScope.$apply(fn);
      } catch (e) {
        console.warn('[mnemonic-wallet] 内部エラー:', e);
      }
    }

    // 「アカウント（ウォレット）の削除」等が入っている右カラムの末尾に追加する。
    var columns = accountPageEl.querySelectorAll('.container-fluid.main > .row > .col-md-6');
    var host = columns[columns.length - 1];
    if (!host) return;

    var passInput = el('input', {
      class: 'form-control', type: 'password', placeholder: 'ウォレットのパスワード'
    });
    var revealBtn = el('button', { type: 'button', class: 'btn btn-primary', text: '表示' });
    var resultBox = el('div', { style: 'margin-top:10px;' });

    var panel = el(
      'div',
      { style: 'display:none;' },
      el('div', { class: 'panel-heading' }, el('h3', {}, 'ニーモニックの復元')),
      el(
        'div',
        { class: 'panel-body' },
        el('p', { class: 'bg-info' }, 'このウォレットがニーモニックフレーズから作成またはインポートされている場合のみ、ウォレットのパスワードでニーモニックを復元できます。'),
        el('div', { class: 'input-group' }, passInput, el('span', { class: 'input-group-btn' }, revealBtn)),
        resultBox
      )
    );
    host.appendChild(panel);

    function currentBackup() {
      var wallet = $ctrl._Wallet && $ctrl._Wallet.current;
      return wallet && wallet.mnemonicBackup;
    }

    function refreshVisibility() {
      panel.style.display = currentBackup() ? '' : 'none';
    }
    refreshVisibility();
    ngScope.$watch(function () { return currentBackup(); }, refreshVisibility);

    revealBtn.addEventListener('click', function () {
      var backup = currentBackup();
      resultBox.textContent = '';
      if (!backup) return;
      if (!passInput.value) {
        resultBox.textContent = 'パスワードを入力してください。';
        return;
      }
      decryptMnemonicFromWlt(backup, passInput.value).then(function (mnemonic) {
        apply(function () {
          resultBox.textContent = '';
          var pre = el('pre', {
            style: 'color:white;background-color:#444;font-weight:bold;white-space:pre-wrap;word-break:break-word;'
          });
          pre.textContent = mnemonic;
          resultBox.appendChild(pre);
          var warn = el('p', { class: 'bg-warning' }, 'この単語列は誰にも見せず、紙などオフラインの安全な場所に書き留めてください。');
          resultBox.appendChild(warn);
        });
      }).catch(function () {
        apply(function () {
          resultBox.textContent = 'パスワードが違うか、バックアップデータが壊れています。';
        });
      });
    });
  }

  /* ============================================================
     初期化。失敗しても他のスクリプトに影響しないよう全体をtry/catchで囲む。
  ============================================================ */
  function init() {
    try {
      if (!window.crypto || !window.crypto.subtle) {
        console.warn('[mnemonic-wallet] Web Crypto APIが利用できないため機能を無効化します');
        return;
      }
      waitForInjector(0);
    } catch (e) {
      console.warn('[mnemonic-wallet] 初期化に失敗したため機能を無効化します:', e);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

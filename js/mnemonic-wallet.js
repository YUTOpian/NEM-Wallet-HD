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
//     1. タイプ選択画面に「HDウォレット(新規作成)」「HDウォレット(復元)」ボタンを追加し、
//        [HD新規作成] [HD復元] [シンプル] [プライベートキー] の順に並べ替える
//     2. ステップ3(パスワード入力)用の「次へ」ボタン
//        (ネイティブの「次へ」はタイプ1/3専用のため、タイプ4/5=HDでは表示されない)
//     3. ステップ4用の独自パネル(新規作成用: ニーモニック入力/新規生成、
//        復元用: プライベートキーウォレットに近い最小構成のニーモニック入力)
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
  var HD_CREATE_TYPE = 4;
  var HD_RESTORE_TYPE = 5;

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

    try {
      $transitions.onSuccess({ to: 'app.signup' }, function () { tryMount(); });
    } catch (e) {
      /* $transitionsが無い/シグネチャが違う: 統合をあきらめる */
      return;
    }

    // スクリプト読み込み時点で既にsignup画面にいる場合(リロード等)にも対応
    try {
      if ($state.current && $state.current.name === 'app.signup') tryMount();
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
    var privateKeyBtn = buttonsContainer.querySelector('button[ng-click*="changeWalletType(3)"]');

    /* ---- 0. ボタンを [HD新規作成] [HD復元] [シンプル] [プライベートキー] の順に配置 ---- */
    var hdCreateBtn = el('button', {
      type: 'button',
      class: 'btn btn-primary',
      style: 'margin:0 4px;',
      text: 'HDウォレット(新規作成)',
      onmouseover: function () {
        apply(function () { $ctrl.showInfo = HD_CREATE_TYPE; });
      },
      onclick: function () {
        apply(function () {
          $ctrl._selectedType = { type: HD_CREATE_TYPE };
          $ctrl.start = true;
        });
      }
    });
    var hdRestoreBtn = el('button', {
      type: 'button',
      class: 'btn btn-primary',
      style: 'margin:0 4px;',
      text: 'HDウォレット(復元)',
      onmouseover: function () {
        apply(function () { $ctrl.showInfo = HD_RESTORE_TYPE; });
      },
      onclick: function () {
        apply(function () {
          $ctrl._selectedType = { type: HD_RESTORE_TYPE };
          $ctrl.start = true;
        });
      }
    });
    buttonsContainer.insertBefore(hdCreateBtn, simpleBtn);
    buttonsContainer.insertBefore(hdRestoreBtn, simpleBtn);
    simpleBtn.style.margin = '0 4px';
    if (privateKeyBtn) privateKeyBtn.style.margin = '0 4px';

    /* ---- 説明パネル(タイプ選択画面でマウスオーバー時に表示) ---- */
    if (infoContainer) {
      var infoCreateDiv = el(
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
      var infoRestoreDiv = el(
        'div',
        { style: 'display:none;' },
        el(
          'p',
          {},
          el('span', { class: 'fa fa-info-circle', 'aria-hidden': 'true' }),
          ' お持ちのニーモニックフレーズを入力して、アカウントを復元します。'
        ),
        el(
          'p',
          {},
          el('i', { class: 'fa fa-exclamation-triangle' }),
          ' ニーモニックは秘密鍵と同じくらい重要です。入力は安全な環境で行ってください。'
        )
      );
      infoContainer.appendChild(infoCreateDiv);
      infoContainer.appendChild(infoRestoreDiv);
      ngScope.$watch(
        function () { return $ctrl.showInfo; },
        function (v) {
          infoCreateDiv.style.display = v === HD_CREATE_TYPE ? '' : 'none';
          infoRestoreDiv.style.display = v === HD_RESTORE_TYPE ? '' : 'none';
        }
      );
    }

    /* ---- タイトル(ネイティブはタイプ1/2/3専用のため、HD用に補完表示) ---- */
    var titleHost = signupPageEl.querySelector('.form-group.text-center');
    if (titleHost) {
      var titleEl = el('h4', { style: 'display:none;' });
      titleHost.appendChild(titleEl);
      ngScope.$watch(
        function () { return $ctrl._selectedType && $ctrl._selectedType.type; },
        function (type) {
          if (type === HD_CREATE_TYPE) titleEl.textContent = 'HDウォレットを作成';
          else if (type === HD_RESTORE_TYPE) titleEl.textContent = 'HDウォレットを復元';
        }
      );
      ngScope.$watch(
        function () {
          return !!(
            $ctrl._selectedType &&
            (
              $ctrl._selectedType.type === HD_CREATE_TYPE ||
              $ctrl._selectedType.type === HD_RESTORE_TYPE
            ) &&
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
            return !!(
              $ctrl.step3 &&
              $ctrl._selectedType &&
              ($ctrl._selectedType.type === HD_CREATE_TYPE || $ctrl._selectedType.type === HD_RESTORE_TYPE)
            );
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

    function isHdType(t) {
      return t === HD_CREATE_TYPE || t === HD_RESTORE_TYPE;
    }

    /* ---- ステップ7(秘密鍵の表示)をHDウォレットではスキップする ----
       ニーモニックのバックアップ(ステップ4で既に完了)が実質的なバックアップであり、
       秘密鍵を改めて表示・保管させる必要はないため、HDタイプの時だけ
       ステップ6→ステップ8 / ステップ8→ステップ6 と直接行き来させる。 */
    var step6Container = signupPageEl.querySelector('[ng-show="$ctrl.step6"]');
    if (step6Container) {
      var step6ConfirmBtn = step6Container.querySelector('button[ng-click*="step7 = true"]');
      if (step6ConfirmBtn) {
        step6ConfirmBtn.addEventListener('click', function () {
          apply(function () {
            if (isHdType($ctrl._selectedType && $ctrl._selectedType.type) && $ctrl.step7) {
              $ctrl.step7 = false;
              $ctrl.step8 = true;
            }
          });
        });
      }
    }
    var step8Container = signupPageEl.querySelector('[ng-show="$ctrl.step8"]');
    if (step8Container) {
      var step8BackBtn = step8Container.querySelector('button[ng-click*="step7 = true"]');
      if (step8BackBtn) {
        step8BackBtn.addEventListener('click', function () {
          apply(function () {
            if (isHdType($ctrl._selectedType && $ctrl._selectedType.type) && $ctrl.step6) {
              $ctrl.step6 = true;
              $ctrl.step8 = false;
            }
          });
        });
      }

      /* ---- ステップ8の警告文言を「秘密鍵」→「ニーモニック」表記に差し替え(HDのみ) ---- */
      var step8WarningP = step8Container.querySelector('.form-group p');
      if (step8WarningP) {
        var step8OverlayP = el(
          'p',
          { style: 'display:none;' },
          el('b', {}, el('i', { class: 'fa fa-exclamation-triangle' }),
            ' あなたのニーモニックがバックアップされていることを確認した後に、あなたのアカウントに自己の責任において資金を送金してください。')
        );
        step8WarningP.parentNode.insertBefore(step8OverlayP, step8WarningP.nextSibling);
        ngScope.$watch(
          function () {
            return isHdType($ctrl._selectedType && $ctrl._selectedType.type);
          },
          function (isHd) {
            step8WarningP.style.display = isHd ? 'none' : '';
            step8OverlayP.style.display = isHd ? '' : 'none';
          }
        );
      }
    }

    /* ---- ステップ4: ニーモニック入力パネル(新規作成・復元それぞれ) ---- */
    buildStep4Panel(signupPageEl, ngScope, $ctrl, apply, {
      type: HD_CREATE_TYPE,
      showGenerateButton: true,
      showPassphrase: true,
      showAddressPreview: true,
      headerText: 'ニーモニックを入力してください(お持ちでない場合は新規生成できます)',
      finalButtonLabel: '作成'
    });
    buildStep4Panel(signupPageEl, ngScope, $ctrl, apply, {
      type: HD_RESTORE_TYPE,
      showGenerateButton: false,
      showPassphrase: false,
      showAddressPreview: true,
      headerText: 'お持ちのニーモニックを入力してください',
      finalButtonLabel: '次へ'
    });
  }

  function buildStep4Panel(signupPageEl, ngScope, $ctrl, apply, opts) {
    // ネイティブのタイプ3(プライベートキー)用ステップ4の直後に、HD用の独自ステップ4を挿入する。
    var privKeyStep4 = signupPageEl.querySelector(
      '[ng-show="$ctrl.step4 && $ctrl._selectedType.type === 3"]'
    );
    var host = privKeyStep4 ? privKeyStep4.parentNode : signupPageEl.querySelector('.container');
    if (!host) return;

    var deriveState = { privateKeyHex: null };

    var mnemonicInput = el('textarea', {
      class: 'form-control',
      rows: opts.showGenerateButton ? '3' : '2',
      placeholder: opts.showGenerateButton
        ? 'ニーモニック(12〜24単語)を入力、または下のボタンで新規生成してください'
        : 'ニーモニック(12〜24単語)を入力してください'
    });
    var generateBtn = opts.showGenerateButton
      ? el('button', { type: 'button', class: 'btn btn-dark', text: '新しいニーモニックを生成(24語)' })
      : null;
    var passphraseInput = opts.showPassphrase
      ? el('input', {
          class: 'form-control',
          type: 'text',
          placeholder: 'BIP39パスフレーズ(任意・上級者向け・通常は空欄)'
        })
      : null;
    var indexInput = el('input', { class: 'form-control', type: 'number', min: '0', value: '0' });

    var addressPreviewValue = el('b', { text: '' });
    var previewFieldset = opts.showAddressPreview
      ? el(
          'fieldset',
          { class: 'form-group', style: 'display:none;' },
          el('p', { class: 'text-center', text: 'このアカウント番号から生成されるアドレス' }),
          el('div', { class: 'form-control' }, el('p', { style: 'font-size:15px;' }, addressPreviewValue))
        )
      : null;

    var errorText = el('p', { class: 'text-center', style: 'color:#a94442;' });
    var errorBox = el('div', { class: 'form-group', style: 'display:none;' }, errorText);

    var finalBtn = el('button', {
      type: 'button',
      class: 'btn btn-primary',
      style: 'width:100%;',
      disabled: 'disabled'
    });
    finalBtn.innerHTML = opts.finalButtonLabel + ' <span class="fa fa-chevron-right" aria-hidden="true"></span>';

    var backBtn = el('button', { type: 'button', class: 'btn btn-dark', style: 'width:auto;' });
    backBtn.innerHTML = '<span class="fa fa-chevron-left" aria-hidden="true"></span> 戻る';

    function showError(msg) {
      errorText.textContent = msg;
      errorBox.style.display = '';
      if (previewFieldset) previewFieldset.style.display = 'none';
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
      if (previewFieldset) previewFieldset.style.display = 'none';
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
          var idx = parseInt(indexInput.value, 10);
          if (!(idx >= 0)) idx = 0;
          var passphrase = passphraseInput ? passphraseInput.value : '';
          var privateKey = derivePrivateKeyFromMnemonic(mnemonic, passphrase, idx);
          var info = deriveAccountInfo(privateKey, netKey === 'testnet');
          deriveState.privateKeyHex = info.privateKey;
          addressPreviewValue.textContent = info.address;
          if (previewFieldset) previewFieldset.style.display = '';
          finalBtn.disabled = false;
        })
        .catch(function (e) {
          showError('ニーモニックの読み込みに失敗しました: ' + (e && e.message ? e.message : e));
        });
    }, 400);

    mnemonicInput.addEventListener('input', updatePreview);
    if (passphraseInput) passphraseInput.addEventListener('input', updatePreview);
    indexInput.addEventListener('input', updatePreview);

    if (generateBtn) {
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
    }

    backBtn.addEventListener('click', function () {
      apply(function () {
        $ctrl._selectedType = undefined;
        $ctrl.hideAllSteps();
      });
    });

    finalBtn.addEventListener('click', function () {
      if (!deriveState.privateKeyHex || finalBtn.disabled) return;
      apply(function () {
        // ここから先(暗号化保存・安全確認画面・ローカルストレージ追加)は
        // 本体のプライベートキーウォレット作成処理をそのまま利用する。
        $ctrl.formData.privateKey = deriveState.privateKeyHex;
        $ctrl.createPrivateKeyWallet();
      });
    });

    var panel = el(
      'div',
      { class: 'col-md-offset-3 col-md-6', style: 'display:none;' },
      el(
        'fieldset',
        { class: 'form-group' },
        el('p', { class: 'text-center', text: opts.headerText }),
        mnemonicInput
      ),
      generateBtn ? el('div', { class: 'form-group text-center' }, generateBtn) : null,
      generateBtn
        ? el(
            'p',
            { class: 'text-center', style: 'font-size:12px;color:#888;' },
            el('i', { class: 'fa fa-exclamation-triangle' }),
            ' 生成した単語列は誰にも見せず、紙などオフラインの安全な場所に書き留めてください。'
          )
        : null,
      passphraseInput
        ? el(
            'fieldset',
            { class: 'form-group' },
            el(
              'div',
              { class: 'input-group' },
              el('span', { class: 'input-group-btn' }, el('label', { text: 'パスフレーズ: ' })),
              passphraseInput
            )
          )
        : null,
      el(
        'fieldset',
        { class: 'form-group' },
        el(
          'div',
          { class: 'input-group' },
          el('span', { class: 'input-group-btn' }, el('label', { text: 'アカウント番号: ' })),
          indexInput
        )
      ),
      previewFieldset,
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
        return !!($ctrl.step4 && $ctrl._selectedType && $ctrl._selectedType.type === opts.type);
      },
      function (show) {
        panel.style.display = show ? '' : 'none';
        if (!show) {
          // ステップを離れたら、DOM/メモリ上にニーモニックを残さないよう破棄する
          mnemonicInput.value = '';
          if (passphraseInput) passphraseInput.value = '';
          deriveState.privateKeyHex = null;
          errorBox.style.display = 'none';
          if (previewFieldset) previewFieldset.style.display = 'none';
          finalBtn.disabled = true;
        }
      }
    );

    ngScope.$watch(function () { return $ctrl.network; }, function () { updatePreview(); });
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

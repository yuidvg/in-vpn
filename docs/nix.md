# Nixでの配布

更新日: 2026-10-10（JST）／CLI 0.1.0

CLIを独立したflakeとして配布する。参照先は [yuidvg/in-vpn](https://github.com/yuidvg/in-vpn)、ライセンスは [MIT](../LICENSE)。`v0.1.0` を指定し、Nixpkgsへの登録を待たずに `nix run`・`nix build` やnix-darwinから利用する。[Nix公式のflake仕様](https://nix.dev/manual/nix/2.33/command-ref/new-cli/nix3-flake.html)

このMacでビルド、ビルド内51件・通常77件の試験、導入済みCLIの22項目の確認が成功した。[検証記録](evidence/nix-package-0.1.0.md)に対象と証跡を保存した。

バイナリキャッシュとNixpkgsへの登録はこの配布に含めない。ネイティブアプリの一般配布も別作業である。検証記録の公開・ライセンスに関する記述は、その記録を作成した時点の状態を示す。

## 配布するもの

| 項目 | 今回のパッケージ |
| --- | --- |
| CLI | `in-vpn` と `invpn`、版0.1.0 |
| 実行依存 | 固定したPython 3.14.7、sing-box 1.14.1 |
| 対象 | Apple SiliconのmacOS（`aarch64-darwin`） |
| 利用範囲 | proxyモード、能力の表示、プロファイル登録、状態確認。完全隔離は利用不可 |
| 実験的な透過モード | CLI側の制御コードを含む。署名・承認済みの別アプリが必要 |
| WireGuardの秘密設定 | 同梱しない。実行時に利用者の非公開ディレクトリから読む |
| Network Extension | 同梱しない。開発署名の実機実験と一般配布を分ける |
| nix-darwinでのCLI導入 | `darwinModules.default` の `programs.invpn.enable` で追加 |
| 常駐アプリ・機能拡張の導入 | 別途署名・OS承認が必要。モジュールでは起動しない |

Nixパッケージにしても、子孫の透明選別・システムDNS分離・クラッシュ時の直接通信遮断は実現しない。[能力の境界](implementation.md)が引き続き適用される。Intel Mac、Linux、Developer IDによるアプリ配布は今回の提供対象・実証範囲に含めない。

## ソースの作業フォルダで使う

```sh
./scripts/nix-package check
./scripts/nix-package build --print-out-paths
./scripts/nix-package run -- --version
./scripts/nix-package run -- capabilities --json
./scripts/nix-package run -- --mode proxy vpn1 curl --disable https://example.com
```

`build` は既定で `--no-link`。必要なら `--out-link /path/to/result` を指定する。既存のユーザーインストールやnix-darwin設定は変更しない。`lock` は許可リストで作った入力に対してlockを解決し、成功したlockだけをルートへ戻す。依存の更新はsing-boxの版互換性を再検証してから行う。

Git未初期化のフォルダや展開したソースに秘密設定がある場合は、**直接 `nix build .`、`nix run .`、`nix flake check .` を使わない。** 非Gitのflakeでは入力ディレクトリがNix storeへコピーされるため、`.gitignore` やderivationの `src` フィルターだけでは秘密を保護できない。`scripts/nix-package` は製品ソース・テスト・Nix定義の許可リストだけを別の一時ディレクトリへコピーし、そのディレクトリをNixへ渡す。選択対象のsymlinkと通常ファイル以外を拒否し、追加のinstallableや入力の差し替えも拒否する。生ログ、プロファイル、署名済みアプリ、証明書を入力に含めない。

通常のGit checkoutでも、flakeの入力になり得る追跡ファイルへ秘密を登録しない。秘密設定は `~/Library/Application Support/InVPN/profiles/` 等に置き、Nix式でファイルの内容を読み込まない。

## タグを指定して使う

```sh
nix run 'github:yuidvg/in-vpn/v0.1.0#invpn' -- --version
nix run 'github:yuidvg/in-vpn/v0.1.0#invpn' -- capabilities --json
nix build 'github:yuidvg/in-vpn/v0.1.0#invpn'
./result/bin/in-vpn profiles import vpn1 /path/to/dedicated-WireGuard.conf
./result/bin/in-vpn --mode proxy vpn1 curl --disable https://example.com
```

nix-darwinの既存flakeでは、inputと `darwinSystem` のmodulesに追加する。

```nix
# flake.nix の inputs に追加
invpn.url = "github:yuidvg/in-vpn/v0.1.0";

# darwinSystem の modules に追加
modules = [
  inputs.invpn.darwinModules.default
  { programs.invpn.enable = true; }
];
```

この版はCLIが起動ごとにバックエンドを管理するため、常駐サービス設定は不要。モジュールはパッケージを導入し、VPN・Network Extensionを有効化しない。WireGuard設定は導入後に実行時の `profiles import` で登録する。秘密鍵をNix設定へ埋め込まない。

利用範囲はproxy対応ツールのTCPと、そのproxy環境を継承する子孫に限る。通常ソケット、システムDNS、子孫の透明選別、クラッシュ時遮断は保証しない。デフォルトの完全隔離モードはコマンドを起動せず終了78で拒否する。実験的な起点PID・指定宛先TCPには、Nixパッケージと別に署名・承認済みの `InVPN.app` が必要で、製品bundleの実機確認は未完了である。

Nixpkgs本体への掲載は別の作業である。保守者、プラットフォーム、公開ソースの版とハッシュ、検証結果を整えたうえで、その時点の投稿条件に合わせる。今回Nixpkgsへの申請は行っていない。

## 実装と検証

定義は `flake.nix`、固定依存は `flake.lock`、Pythonアプリのビルドは `packaging/nix/package.nix`、nix-darwinの導入モジュールは `packaging/nix/darwin-module.nix`。Nixの標準Pythonラッパーによる子コマンドの環境変更を避け、固定Pythonを `-I` で起動して自分のsite-packagesだけを明示する。`INVPN_SING_BOX` の既定値でバックエンドを固定し、呼出元のPATH・PYTHONPATH・PYTHONNOUSERSITEを保つ。明示的に上書きする場合は、絶対パスの実行ファイルを指定する。バックエンドの1.14.x確認は実行時にも行う。

ビルド内では通信を要しない単体試験、公開CLIの起動拒否、インストールした両コマンドの版と能力表示を確認する。localhost通信を含む試験と起動環境の確認はsandbox外で実施する。

```sh
python3 verification/nix-package.py --package /nix/store/…-invpn-0.1.0
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

`verification/nix-package.py` は合成WireGuard設定で起動・後始末・環境保持を確認する。外部VPNの到達性や透過転送の合格証明には使わない。今回の結果は [Nixパッケージ検証記録](evidence/nix-package-0.1.0.md) に保存する。

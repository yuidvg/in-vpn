# Nix CLIパッケージの検証

実施日: 2026-10-10（JST）／CLI 0.1.0／Apple Silicon macOS 27.0.1／Nix 2.34.8

CLIのNixビルドと、ビルド済みCLIの実行を確認した。公開は未実施。Network Extensionの配布・署名・有効化、外部VPNの到達性、完全隔離の合格はこの検証に含めない。

## 対象

- 定義: `flake.nix`、`flake.lock`、`packaging/nix/package.nix`
- nixpkgs: `a7868a727837f3c09cee2ce0ca671c76b1589fed`
- 実行依存: Python 3.14.7、sing-box 1.14.1
- derivation: `/nix/store/ydqw1w4hk8hkrbxiydr0mgkdv3hdayvv-invpn-0.1.0.drv`
- CLI出力: `/nix/store/5d9j3wagklv1hcidl4lz5961hi3lf6gx-invpn-0.1.0`
- 秘密を除いた結果と入力ハッシュ: [nix-package-0.1.0.json](nix-package-0.1.0.json)

この作業フォルダは非Gitであり、秘密を持つルートを直接flake入力にしない。`scripts/nix-package` により許可した24ファイルだけをリポジトリ外へコピーしてビルドした。

## 結果

| 検証 | 結果 | 確認した範囲 |
| --- | --- | --- |
| `scripts/nix-package build --json` | 成功 | Python wheelのビルド・導入、51件の通信不要な試験、インストール済み両コマンドの版・能力表示、Python import |
| `scripts/nix-package check` | 成功 | packages/apps/checksのflake出力検査。ビルド済みderivationはキャッシュを使用 |
| `scripts/nix-package run -- --version` | 0.1.0、終了0 | ヘルパーからNixとインストール済みCLIへ引数が届く |
| `scripts/nix-package lock` | 成功 | 非公開フォルダを入力にせずlockを解決し、検証後に戻す |
| 製品の単体・部品試験 | 77/77成功、skipなし | 既存試験とバックエンド選択・Nix入力の回帰。localhostの実WireGuard部品試験を含む |
| ビルド済みCLIの確認 | 22/22成功 | 公開入口、固定依存、起動するコマンドの環境・cwd・ファイル・引数・終了コード・後始末 |
| 秘密設定の混入検査 | 3対象とも混入なし | flake入力24ファイル、derivation入力21ファイル、CLI出力38ファイル |

実行したコマンド:

```sh
./scripts/nix-package build --json
./scripts/nix-package check
./scripts/nix-package run -- --version
./scripts/nix-package lock
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 verification/nix-package.py \
  --package /nix/store/5d9j3wagklv1hcidl4lz5961hi3lf6gx-invpn-0.1.0
```

NixパッケージのPython起動部は `-I` を使用し、自分のインストール先からimportする。呼出元のPATHからPythonやsing-boxを拾わず、子コマンドのPATH・PYTHONPATH・PYTHONNOUSERSITEを変更しない。テストではsing-boxを含まないPATHと、CLIのimportを壊す偽のPYTHONPATHを渡した。それでもCLIが起動し、PATH上の試験コマンドへ元の環境が届いた。

試験コマンドは別ディレクトリの相対ファイルを読み、日本語・空白・改行・shell記号を含む引数を記録し、終了17を返した。cwdはmacOSの `/var` と `/private/var` の表記差を考慮し、実ディレクトリの一致で確認した。sessionはfinished/17となり、生成したバックエンド認証設定は消え、所有したバックエンドPIDは終了した。

起動試験のWireGuard鍵は公開の合成fixture、peerは文書用IP `198.51.100.10`、keepaliveは0。通信はローカル入力の認証準備確認だけで、子はファイル操作のみ。提供された実VPN設定や製品Extension設定は使用していない。

秘密の混入検査では、実際にNix storeへ入ったflake入力・derivation入力・CLI出力のファイル一覧を照合した。`.local/`、WireGuard設定、証明書、プロビジョニング情報は含まれていない。ローカルに保持する実WireGuardの秘密値との完全一致検索も行い、いずれにも見つからなかった。秘密値自体は報告・ログへ出していない。

## 証跡と制約

生の実行記録は `.local/runs/packaging/nix-0.1.0/` に保持した。公開用JSONに、最終ビルド情報、22項目の結果、入力ファイルのハッシュ、各ログのハッシュを保存した。中間試行の結果を最終結果と混同しない。Nix storeのパスはローカルのキャッシュ状態に依存し、GC後も残るとは保証しない。

公開リポジトリ、ライセンス、リリースタグ、バイナリキャッシュ、Nixpkgsへの登録は未実施。Intel Macと一般配布用のネイティブアプリも未検証。このパッケージは引き続き部分実装であり、子孫の透明選別・システムDNS分離・障害時の直接通信遮断は利用できない。[実装の能力表](../implementation.md)を参照。

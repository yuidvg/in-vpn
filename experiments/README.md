# 事前実験の実行

製品CLIとは独立したmacOS実験。`scripts/experiment` の終了コード0は「観測を保存して実行を終えた」という意味で、F系列全体の合格ではない。結論と未確認範囲は各 `result.json` と `docs/evidence/feasibility/` の報告を読む。

```sh
./scripts/experiment list
./scripts/experiment run F00-platform
./scripts/experiment run F01-flow-identity
./scripts/experiment run F02-process-lineage
./scripts/experiment run F03-dns-attribution
./scripts/experiment run F04-failure-containment
./scripts/experiment run F05-vpn-forwarding
./scripts/experiment run F06-workspace-compatibility
./scripts/experiment run F07-multiple-vpns
```

各実行は `.local/runs/feasibility/<run-id>/` を新規作成し、ソースの保存版・SHA-256、ビルド／コマンド結果、観測、後始末を残す。秘密を含み得るこのディレクトリは公開しない。F01のループバック選別は各100組を実施したが、F系列全体の採用確認は未完了。

| 実験 | 現在の実装範囲 | 前提 |
| --- | --- | --- |
| F00 | OS・署名条件・プロファイルの一覧、NE APIの型検査、ES API実呼び出し | Xcode、Python、sing-box |
| F01 | 既知PIDの選別、C・curl・nc、IPv4/NAT64、TCP受信・UDP echo。条件は[README](F01-flow-identity/README.md) | [検証用Host/Extension](../test-support/macos/README.md) の署名・有効化。Cloudflareへの合成HTTPS通信 |
| F02 | 1,000個の短命な子のUDP送信と10ms待機付き `ps` 採取、二重fork後のPPID | Xcode。送信先は同一Macの受信プロセスのみ |
| F03 | 新しい試験ドメインでgetaddrinfoとdigの要求元を比較 | Provider 0.0.6以降。DNS設定・キャッシュは変更しない |
| F04 | sandbox継承FD、または `INVPN_F04_MODE=provider_crash` で試験Providerのabortと受信を比較 | sandbox試験は `sandbox-exec`。クラッシュ試験はProvider 0.0.6以降 |
| F05 | sing-boxのSOCKS TCP／UDPから実WireGuardへの疎通、専用バックエンド停止 | `.local/secrets/wg-CH-FREE-8.conf`、sing-box。api.ipify.orgと設定内DNSへの通信 |
| F07 | 独立したローカルWireGuard2組でTCP/UDP、DNS回答・キャッシュ、片側停止 | Provider 0.0.7以上、sing-box |
| F06 | sandbox内でcwd・環境・引数・ファイル・パイプ・TTY・Nix Python・UNIXソケットを確認 | Xcode、zsh、Python。製品ランチャーやVPNとの統合ではない |

F08は未実装。F03の単独入口は要求元探索。DNSの回答・共有状態の比較はF07で実行する。透明VPN転送はF05のtransparentモード、子孫のセッションID候補はF02のsessionモード、独立FilterはF04のcontent_filterモードに追加した。

F05は提供された秘密設定から、実行ごとに認証付きローカルSOCKSとユーザー空間WireGuardを起動する。通常経路で行う `api.ipify.org` の事前名前解決は明記する。これは標準DNSのセッション分離を検証しない。生成設定も秘密扱いとし、試験用sing-boxだけを終了する。

F01は試験対象を終了してから試験用ネットワーク設定を削除する。Extension本体の導入・OS承認は自動実験の外に置く。実験は既存VPNを勝手に止めない。

## 第2回の実測

[report-2.md](../docs/report-2.md)にF02/F04/F05/F07の追加結果を保存した。試験用ProviderはTCP/UDP中継、既知PIDまたはセッションIDの選択、Guardは単純な別プロセスの遮断候補。いずれも製品実装ではない。F07は2本の独立したローカルWireGuardを実際に使う。DNS・子孫分類・クラッシュ遮断の不合格を「実行できた」ことと混同しない。

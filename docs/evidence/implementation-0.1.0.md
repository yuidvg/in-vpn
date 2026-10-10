# 0.1.0の実装と実測

実施日: 2026-10-09（JST）  
対象: macOS 27.0.1、Python 3.14.7、sing-box 1.14.1。TailscaleはRunning。全受け入れV00〜V25の合格報告ではない。

要件と利用範囲は [implementation.md](../implementation.md)。機械可読の観測・ソースハッシュ・生データ参照は [implementation-0.1.0.json](implementation-0.1.0.json)。秘密鍵・認証情報・実際の外向きIP・端末の生ログは公開しない。

| 検査 | 実測結果 | 成立する範囲 |
| --- | --- | --- |
| 単体・部品試験 | 62件成功 | 設定検証、exec barrier、FD、引数、シグナル、排他、半閉鎖、認証、ローカルWG DNS/HTTP等 |
| 実CLIから外部HTTPS | 3試行中2成功、VPNと通常回線の出口が異なる | proxyモードで、名前をproxyへ渡すcurl。残る1試行は終了35 |
| 追加DNS診断 | 同じ設定の追加HTTPSは6/6成功。明示的DNSパケットには断続的タイムアウト | 恒常的なIPv4/IPv6・EDNS原因は特定せず。安定した接続の保証とはしない |
| 作業環境・終了状態 | cwd、環境、Unicode・空白・記号・改行を含む引数、ファイル、stdio、終了17、SIGTERM→143を確認 | 実CLI経由のzsh等 |
| 通常モードの拒否 | markerファイルを作るコマンドを実行せず拒否 | 完全隔離の不足を起動前に通知 |
| 非proxyの通常ソケット | proxyモード内から通常側と同じ出口へ到達 | **直接通信は遮断されない**という反例 |
| 対話シェル | PTY、背景ジョブ、wait、終了17が成功 | 実CLIでの対話zsh |
| 端末の停止・再開 | Ctrl-Z→fg→Ctrl-C、root停止→wrapper停止→再開、bg時の外側端末維持、fg時のrootへの端末引渡しを確認 | 通常の端末・プロセスグループ制御 |
| 異なる2プロファイル | 3組・6接続が正しいbodyと受信側path。誤受信0。全組で受信側barrierが同時到達を確認 | **同じMac上の独立したローカルWireGuard 2本**。外部VPN出口2本の証明ではない |
| ネイティブ製品bundle | 署名付き・署名なしビルド成功、0.1.0/2導入 | OS承認待ち。製品bundleでの実フロー転送は未検証 |

外部実CLIのrunは `.local/runs/acceptance/20261009T131224Z-partial-caea42/`。診断は `.local/product/checks/dns-engine-1791551309-58e5de/`、並行実行は `.local/product/checks/20261009T132026Z-parallel-local-3a6ffe/`。端末検査は `.local/product/checks/pty-jobs/` と `pty-bg-final/`。公開JSONから個別の観測とハッシュをたどれる。

最初の外部DNS試行もタイムアウトし、literal IPを指定したHTTPSは成功した。その後の名前付きHTTPS成功だけで失敗を消さない。原因の確定、スリープ・回線変更、Tailscale一般共存、複数の外部VPN出口は残る検証範囲。

準備中・後片付け中の通常TERMで資源が残る問題、状態保存先による排他の迂回、非正規base64による同じ鍵の重複、背景再開で端末を奪う問題を修正し、回帰試験または実端末で確認した。SIGKILLやProviderクラッシュに対する通信遮断を成立させた修正ではない。

ネイティブの初回有効化はapplication-group entitlement不足でOSが拒否した。必要なgroupとMach service接頭辞を一致させて修正後、OSの利用者承認待ちになった。現在、製品アプリの通信設定は存在せず、Extension登録のみ残る。承認要求はタイムアウトしており、許可後に必要なら `activate` を再実行する。

root/backend/peerの終了と認証設定の削除を確認した。既存mirrorやTailscaleを停止・書換していない。鍵は所有者限定の場所に保存し、製品ソースから実験コードへの依存もない。

通常起動の完全隔離は未提供。子孫の透明選別、標準DNSとキャッシュの分離、VPN／Provider／CLI故障時の直接通信遮断は [第2報](../report-2.md) の未達状態を保持する。

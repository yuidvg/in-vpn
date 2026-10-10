# 2026-10-07の事前実験

追記: 以下は初回時点の記録。[Tailscale切断後の追加実験](../20261007-tailscale-off/report.md)で、既知PIDの選別と標準DNSの要求元取得が成立し、Providerクラッシュ後の直接通信を観測した。古い「外向きIPv4」の推定も訂正している。現在の状態は追加報告を参照。

実施環境: macOS 27.0.1（26A434）、arm64、Xcode 27.0（27A266a）、SDK 27.0、通常ユーザー。SIP有効、MDM未登録。sing-box 1.14.1。

**製品構成を採用できる段階には達していない。** 実WireGuardへのTCP/UDP疎通を確認し、定期プロセス一覧とsandbox単独の候補について反例を得た。Network Extensionは署名・有効化・設定適用まで進んだが、試験通信のフロー通知を取得できていない。

## 実施結果

| 実験 | 実施範囲と事実 | 結論／残件 |
| --- | --- | --- |
| F00 | 開発署名、OS承認、System Extension有効化、ProviderとのIPC、設定適用を確認 | このMacでの開発用導入は成立。フロー処理・Developer ID配布は未成立／未実施 |
| F01 | ループバックTCP/UDP、外向き同一curl A/B各3組を2条件で実行。Providerのフロー通知は0 | 判定不能。メタデータを得られていないため「PIDを区別できない」という反証にもならない |
| F02 | 短命な子1,000個×2回のUDP送信をすべて受信。一覧で捕捉できた子は12個／16個。二重fork後のPPIDは1 | 定期一覧と現在のPPIDだけに依存する追跡候補は不採用。イベント方式は未確認 |
| F03 | 未実施。フロー取得の有効性が未確認 | 標準DNSの要求元、VPN別回答、キャッシュ分離はすべて残件 |
| F04 | 2回の別起動で、新規IPv4/IPv6 TCP/UDPはsandboxで拒否。接続済みFDを渡すと4条件すべてでペイロードが受信側へ届いた | このsandboxだけでは継承済みIPソケットまで保護できない。Providerのクラッシュ試験は未実施 |
| F05 | SOCKS CONNECT＋WireGuardでHTTPS成功、通常側と出口IPが異なる。UDP ASSOCIATE＋WireGuardで設定内DNSから正常応答。専用バックエンド停止後のSOCKS接続は拒否 | バックエンドの限定的疎通は成立。透明なフロー転送、標準DNS、完全な経路観測の証拠にはしない |
| F06 | sandbox内でcwd、合成環境変数、引数、ファイル、パイプ、システムzsh、Nix Python、通常UID、TTYを維持。一つのUNIXソケットを許可でき、新規TCPは拒否を継続 | 基本操作は成立。全ツール・対話ジョブ制御・IPC委譲・VPNとの同時成立は残件 |
| F07 | 未実施。F03/F05の透明転送が未成立で、2本目の検証用VPNも未指定 | 複数VPNの独立性は未確認 |
| F08 | 未実施 | 製品方式は確定しない |

## F00: 署名と実行条件

初期一覧ではNetwork Extension／Endpoint Securityのプロファイルは0件だった。ユーザーが既存のApple Developerチームの利用を了承した後、Xcodeの自動プロビジョニングで検証用の2つのApp IDと開発プロファイルを作成した。

- Host: `jp.diverge.invpn.feasibility`
- Provider: `jp.diverge.invpn.feasibility.proxy`
- 必要な権限: Network Extension、HostのSystem Extensionインストール、ProviderのApp Sandbox・ネットワーク、NEMachServiceNameに対応するApp Group

最初はDeveloper ID用のentitlement値でプロファイルが一致せず失敗した。開発用の `app-proxy-provider` に修正して署名が通った。その後、Provider自身のUsageDescriptionとApp Group接頭辞の不足をOSログで特定・修正し、有効化に成功した。これらは試験実装の修正であり、macOSの不可能性を示す結果ではない。[署名区分のApple資料](https://developer.apple.com/forums/thread/125508)

同SDKにはmacOS 27以降の `es_new_descendants_client` がある。インストール済み `EndpointSecurity/ESClient.h` では子孫に限定したクライアントであり、root／TCCを要しない一方、ES entitlementは必要とされる。通常ユーザーで実際に呼ぶと `ERR_NOT_ENTITLED`（3）。従来の `es_new_client` は `ERR_NOT_PRIVILEGED`（5）。新APIのイベント取得・順序・再親化はまだ試せていない。[ES entitlementのApple資料](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)

初期条件は [F00初回](../20261007T061637Z-F00-8f56b3/report.md)、署名後の条件・ビルドと有効化の記録は [F00再採取](../20261007T063949Z-F00-e50f74/report.md) に保存した。Developer ID Application証明書は見つかっておらず、開発機での成功を配布可能性の実証とはしない。

## F01: 起動できてもフロー通知は得られていない

まず同一Macの受信機に対し、同じCバイナリのA/Bを実行した。Provider内のイベント取得用IPCは応答したが、TCP/UDPとも通知0件でA/Bの送信は届いた。[ループバック実行](../20261007T063103Z-F01-10f070/report.md)

次に `/usr/bin/curl` の同一バイナリを別々のシェルからexecし、Bの既知のPIDだけを遮断する条件で `1.1.1.1:443` へ同時送信した。3組ともA/Bが成功し、フロー通知は0件だった。[外向き実行](../20261007T063308Z-F01-0d8347/report.md)

さらに設定適用完了の `ready` 応答を追加し、旧NENetworkRule初期化API、単一IP内の全ポート、明示的な空の除外ルールに変更した。適用成功を確認後の3組でも通知は0件だった。[設定適用を待つ再実行](../20261007T063642Z-F01-9e69c5/report.md)。HostをLaunchServicesから起動し、2秒待って新たにcurlを起動した追加の切り分けでも通知0件（ローカルの `activation/launchservices-probe.json`）。

Tailscaleは接続中、ProtonVPNアプリ側の接続は切断中。試験時点では既存VPNを停止していない。Tailscaleとの共存が原因かは未確認で、一時切断による比較をユーザーへ確認中。試験実装、ルール、OSの挙動、他のExtensionの影響を切り分ける必要がある。

**この状態で後続のDNS帰属やProviderクラッシュ試験を合格／反証にはしない。** まず実際にフローを取得・遮断できる対照条件を作る必要がある。

## F02/F04: 設計に使える反例

F02は別の受信スレッドで子の送信を受け、生成記録と一覧を照合した。`ps` 完了後に10ms待つ実装であり、厳密な10ms周期ではない。1回目は1,000個中988個、2回目は984個が送信後に一度も一覧へ現れなかった。受信欠落は0。親が先に終わると孫のPPIDが1になる実例も得た。[初回](../20261007T061641Z-F02-66b535/report.md)、[再実行](../20261007T063054Z-F02-add373/report.md)

F04はsandbox適用前に接続したソケットFDを対象へ渡し、受信側でペイロードを確認した。IPv4/IPv6それぞれのTCP/UDPで送信できた。新規接続およびfork＋execした子の新規TCPはEPERMとなり、前後の通常通信は通った。確認したのはループバック上の境界で、外部向け漏れの全経路を観測したわけではない。[初回](../20261007T061758Z-F04-745c9f/report.md)、[再実行](../20261007T063056Z-F04-261b54/report.md)

採用時には、起動前のIPソケットFDの扱いと、通信開始前に成立する継承可能な保護を検証する必要がある。`sandbox-exec` はこのMacのman pageでもdeprecated。今回動いたことを保守・配布の保証にしない。

## F05/F06: 成立した部分と限界

WireGuardファイルはユーザー指定のものを `.local/secrets/wg-CH-FREE-8.conf` へ移動し、ディレクトリ700・ファイル600、`.local/` 全体とルートの `wg-*.conf` をGit除外した。既存mirror用と鍵が異なることを比較した後、OSの経路を変更しない `system: false` の専用sing-boxを起動した。

最初の `1.1.1.1` 向けTLS試験はEOFで失敗した。この失敗も保存しており、原因は未特定。[初回](../20261007T062257Z-F05-abc1aa/report.md)。接続先を `api.ipify.org` に変えた試験ではTCP成功、出口IPの相違、設定内DNSへのUDP正常応答（rcode 0、A回答2件）を確認した。[再試験](../20261007T062432Z-F05-d1091c/report.md)

api.ipify.orgの事前名前解決は通常のシステムリゾルバーで行った。DNSプローブは独自にSOCKS UDPを利用している。この結果をgetaddrinfoのVPN分離に読み替えない。受信側の外部IP表示とDNS応答は取得したが、外部受信ログ・パケット採取による完全な経路確認は残っている。

F06は広いファイル環境を維持しながらネットワークだけを制限できる限定例を示した。同時に、network全拒否はUNIXソケットも止めるため、必要なIPCの許可設計が要る。UNIXソケットを通して既存デーモンに外向き通信を依頼できる範囲は別課題。[F06](../20261007T062617Z-F06-2d6dc9/report.md)

## 後始末と残る状態

試験プロセス、受信機、専用sing-boxは終了した。F01の試験用ネットワーク設定は削除し、Hostの確認は `no_configuration`。既存mirror、通常VPNの設定、SIP、システムDNSは変更していない。

再試験用のアプリは `/Applications/InVPNFeasibility.app` にあり、System Extension 0.0.3/3の登録・承認は残る。古い0.0.1/1と0.0.2/2はOSが `terminated waiting to uninstall on reboot` と表示する。これは試験更新の残状態として記録し、完全に未導入の状態へ戻ったとは報告しない。Apple側の検証用App ID／開発プロファイルも残している。

生データと実行時のソース保存版は `.local/runs/feasibility/<run-id>/`。各runの公開用manifestに対応するハッシュがある。秘密設定、出口IP、詳細な署名・OSログはローカル保存のみ。パケット採取は実施していない。受信機と生成数の照合ができる試験以外では、採取欠落がないことは保証していない。

次はF01のフロー通知が来ない原因を切り分け、成立した観測条件でF03/F04を進める。独立してES権限の利用条件と新APIを確認する。これらが揃うまで製品方式は確定しない。

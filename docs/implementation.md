# 初版の実装と利用範囲

更新日: 2026-10-09（JST）／版: 0.1.0  
状態: 部分モードを実装。完全なVPN隔離は未達。

## 使い方

Python 3.11以上、sing-box 1.14.xを使う。追加のPythonライブラリは不要。このMacには `~/.local/bin/in-vpn` と `invpn` を導入した。

```sh
in-vpn doctor --json
in-vpn capabilities --json
in-vpn --mode proxy vpn1 curl --disable https://example.com
in-vpn --mode proxy vpn1 shell
in-vpn status --json
```

提供されたWireGuard設定は `~/Library/Application Support/InVPN/profiles/vpn1.conf` にコピーし、元の `.local/secrets/wg-CH-FREE-8.conf` も保持。ディレクトリ700、ファイル600で、Git・Nix storeには置かない。

Nix版ではPython・sing-boxを固定して提供する。[Nixでの配布・検証](nix.md)を参照。通常インストールではPATH上のsing-box、Nix版では同梱する絶対パスを使う。`INVPN_SING_BOX` に絶対パスを指定すれば明示的に変更でき、1.14.x確認は維持する。子コマンドのPATHは変更しない。

リポジトリからは `./bin/in-vpn` で実行できる。設定の登録とCLI導入:

```sh
./bin/in-vpn profiles import vpn2 /path/to/dedicated-WireGuard.conf
./bin/in-vpn profiles list
./scripts/install-cli
```

既存プロファイルは上書きしない。1 Interface・1 Peer、リテラルIPのEndpointとDNS、IPv4全経路 `0.0.0.0/0` を要求する。フックやOS経路設定は実行しない。MTUは設定値または1280。DNSは最初の設定済みサーバーを使用し、自動フェイルオーバーはない。

同じ秘密鍵の重複登録・同時実行、既存mirrorの鍵との共用を拒否する。排他は利用者の固定lockディレクトリと正規化した鍵の識別値で行い、設定名・状態保存先を変えても同じ鍵は並行使用できない。peerの移動を避けるため、同じVPNで複数シェルを同時に使う機能もこの版では提供しない。

## 能力の境界

| 項目 | この版の扱い |
| --- | --- |
| 作業環境 | cwd、PATH、通常環境、引数、ファイル、stdio、終了コードを保持。端末の前景制御を引き渡す |
| proxy対応TCP | 認証付きローカルHTTP/SOCKS → userspace WireGuard。プロキシに渡された名前はVPN DNSで解決 |
| proxy対応の子孫・シェル | 環境変数を継承。無視・上書きするプログラムの通常ソケットは直接通信できる |
| 通常TCPの透過転送 | 指定IPv4・ポート、起点PIDのみの実験コード。製品ExtensionのOS承認・実機確認が必要 |
| 複数VPN | 異なる鍵・プロファイルのproxyバックエンドを別々に起動。透過の並行実行は拒否 |
| 起動前の準備 | 認証付きバックエンド入力を確認。透過ではProvider準備・登録応答後に同じPIDでexec |
| 継承FD | 余分なFDを閉じる。socketのstdin/stdout/stderrを拒否 |
| 通常終了・TERM/HUP | 所有バックエンドと一時認証設定を後始末。準備・終了処理中の通常シグナルにも対応 |
| 子孫の透明選別 | 利用不可。短命プロセス、setsid、親終了等を確実に扱う追跡方式が未決定 |
| システムDNS分離 | 提供しない。getaddrinfo・共有キャッシュ・アプリ独自DNSは保証外 |
| 直接通信の遮断 | 提供しない。両部分モードとも直接通信が可能 |
| Provider/CLIクラッシュ | 通常回線への漏れを防げない。SIGKILL・再起動後の自動復旧も未対応 |
| バックグラウンド子孫 | root終了時にバックエンドを止める。残る子の寿命・通信を維持または隔離しない |
| UDP・QUIC・ICMP | 製品の透過転送は未対応。通常経路で通信する可能性がある |
| IPv6 | 一般的な透過IPv6は未対応。指定IPv4のwell-known NAT64対応宛先だけを併せて捕捉 |
| LAN・loopback | proxyの迂回指定は空にするが、設定を無視する通信は遮断しない。透過は指定宛先だけ |
| 既存デーモンへの依頼 | Docker・launchd等へのIPCによる代理通信は対象外 |
| 導入・共存 | Developer ID、公証、他ユーザーIPC認可、スリープ・回線変更、一般的なTailscale共存は未検証 |

各起動のstderrと `capabilities` に制限を表示する。通常の `in-vpn vpn1 command` / `in-vpn vpn1 shell` は必須要件の不足で、コマンドを実行せず終了78。部分モードを明示して利用する。

proxyに名前を渡すツールの成功は、すべてのDNSの隔離ではない。`curl --proxy ''` や通常のsocketを開くプログラムは直接通信できる。入力の準備確認もVPN peer到達・常時通信可能性を保証しない。アプリ側のproxy設定や `~/.curlrc` が環境変数を上書きする場合もある。

## 透過実験モード

独立した製品コードは `macos/`。署名・導入・有効化:

```sh
python3 macos/build.py --team YOUR_TEAM_ID
ditto .local/build/native/Build/Products/Debug/InVPN.app /Applications/InVPN.app
/Applications/InVPN.app/Contents/MacOS/InVPN activate
```

このMacには開発署名した0.1.0/2を `/Applications/InVPN.app` に導入した。製品用 `jp.diverge.invpn.proxy` はmacOSの利用者承認待ち。設定 → 一般 → ログイン項目と機能拡張 → ネットワーク機能拡張で「InVPN」を有効にする必要がある。旧「InVPN Feasibility」とは別登録。

許可後の例:

```sh
in-vpn --mode transparent --experimental --destination 1.1.1.1:443 vpn1 \
  /usr/bin/curl --disable --proxy '' --noproxy '*' -4 --http1.1 \
  https://1.1.1.1/cdn-cgi/trace
```

このモードは `shell` 操作を拒否する。実行ファイルとしての `/bin/zsh` は起動できるが、その子のcurl等は対象外。指定以外の宛先・UDP・標準DNSは従来の経路を使う。

BSD開始時刻とaudit世代の照合を実装したが、sandbox内の照合と実転送は製品bundleでの実機確認が必要。同じPIDの再execで世代が変わるケースも一般対応を約束しない。audit情報の欠落やProviderクラッシュを含め、完全保護は提供しない。

## 検証と配置

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 verification/run-partial.py --config-dir .local/product/profiles
python3 verification/parallel-local.py
# 製品Extensionの許可後:
python3 verification/run-partial.py --config-dir .local/product/profiles --transparent
```

実exec barrier、シグナル、FD、設定・状態保存先を変えた排他、認証、TCP半閉鎖・512 KiB転送、実際のローカルWireGuardを通るDNS・HTTPを検査する。ネイティブは署名付き・署名なしビルド成功。稼働証明とは分ける。

外部通信と実端末、独立した2本のローカルWireGuardによる製品CLI並行実行は [初版の実測](evidence/implementation-0.1.0.md) に保存。DNSタイムアウトを含む失敗試行も残す。[verification.md](verification.md)のV00〜V25を部分試験の成功で全項目合格にしない。[report-2.md](report-2.md)の反例も有効。

製品は `src/invpn/`（Python CLI・バックエンド等）と `macos/`（Swift/C Host・Provider）。`tests/`は部品試験、`verification/`は公開CLIによる実測、`bin/`と`pyproject.toml`は実行入口。製品からexperiments/test-supportをimport・リンクしない。

通常の状態・所有者限定ログは `~/Library/Application Support/InVPN/run/sessions/`、排他は`locks/`。バックエンドの認証設定は終了時に削除し、診断ログ・状態を残す。生ログは公開しない。`scripts/install-cli`はCLIのみ導入し、鍵やアプリをコピーしない。nix-darwinのマシン設定は今回変更していない。

設定仕様: sing-boxの [mixed inbound](https://sing-box.sagernet.org/configuration/inbound/mixed/)、[UDP DNS](https://sing-box.sagernet.org/configuration/dns/server/udp/)、[WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)。仕様と全要件の成立を区別する。

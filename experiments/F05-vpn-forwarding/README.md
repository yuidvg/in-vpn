# F05: バックエンド疎通

`./scripts/experiment run F05-vpn-forwarding`。提供された `.local/secrets/wg-CH-FREE-8.conf` を読み、試験ごとの認証付きSOCKS入力とsing-boxのWireGuard endpointを作る。OSの経路・DNS設定は変更しない。設定を既存mirrorと同じ鍵で同時接続してしまわないよう事前に比較する。

通常のシステムDNSによる `api.ipify.org` の事前解決後、同じIPへの通常／SOCKS＋VPNのTLS要求で出口IPを比較する。SOCKS UDP ASSOCIATEで設定内DNSへ `example.com` のA問い合わせを送り、応答ID・送信元アドレス・rcode・回答数を検査する。最後に試験用sing-boxを止め、SOCKS接続失敗と通常通信の継続を確認する。

このプローブ自体はSOCKSを話す。NEからの透過転送や標準DNS分離の合格にはしない。外部IP表示は補助証拠で、管理下の出口受信ログやパケットの完全な採取はまだない。[WireGuard endpoint仕様](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)

## 通常ソケットから外部WireGuardへ

`INVPN_F05_MODE=transparent ./scripts/experiment run F05-vpn-forwarding`

Provider 0.0.7以上と専用WireGuard設定を使う。プロキシを無効にした未改修のcurlをA/Bで実行し、通常出口と事前確認したVPN出口を比較する。宛先api.ipify.orgのIPv4は試験前に通常DNSで取得し、curlへ`--resolve`で固定する。この準備をDNS分離の成功に数えない。対象1アドレス:443と試験専用DNS名だけを捕捉する。

最終実験はMTU=1280。初期条件でWireGuardの受信に`message too long`が出たため変更したが、原因の確定や長時間安定性の証明ではない。VPNバックエンド停止、ローカル中継停止、Provider自身のabortを分けて観測する。クラッシュ試験のBは停止前に登録し、停止後10回の新規TLS接続を試す。出口のIP・設定は非公開のまま残す。

# F07: 2本のWireGuardへの透明転送とDNS分離

`./scripts/experiment run F07-multiple-vpns`

TTL=0の比較: `INVPN_DNS_TTL=0 ./scripts/experiment run F07-multiple-vpns`

Host/Provider 0.0.7以上を導入・承認してから実行する。試験ごとに新しい鍵を作り、sing-boxのuserspace WireGuard peerを2組作る。実際の暗号化トンネルだが、peerは同じMac内に置くため、異なる外部VPN出口の証拠ではない。2本とも同じ仮想宛先を持ち、受信機を分ける。個別のSOCKS経由の疎通を前提確認してから、プロキシ無効の同一curlバイナリA/Bと通常UDPソケットを既知PIDで振り分ける。

TCPは5組を同時解放し、受信したURLとvpn1/vpn2の回答を照合する。UDPは各VPNで5回の往復を行う。VPN1バックエンド停止後にVPN1が失敗しVPN2が継続することを観測する。

DNS受信機は同じ名前のA回答をVPN1では192.0.2.11、VPN2では192.0.2.22にする。新規名、同じ名前の交互要求、逆順、同時要求、通常セッションでの再利用を実行する。標準getaddrinfoと直接digも分ける。直接digのポートは透明ProviderのDNS規則の制限を避けた試験用18080であり、任意の53番通信の捕捉の証明ではない。

sandboxのnetwork-outbound禁止と透明転送の併用も観測する。結果を推定で合格にせず、クライアント・受信機・Providerの三者を照合する。秘密鍵・SOCKS認証・中継認証は`.local/`内だけに保存する。終了時に自分のプロセス・受信機・透明プロキシ設定を除去する。

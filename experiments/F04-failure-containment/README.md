# F04: 遮断候補と故障の境界

`./scripts/experiment run F04-failure-containment`。同一MacのIPv4/IPv6受信機に対し、新規TCP/UDP、sandbox適用前に接続して渡したFD、fork＋execを比較する。前後の通常送信を対照とする。送信側のエラーだけでなく、受信側で合成ペイロードを照合する。

`(allow default)(deny network*)` は探索用。継承FDで送信できれば「このプロファイルだけで全IP通信を止める」という候補の反証になる。外部向け経路、透過転送との両立、Providerのクラッシュは次の別条件で実行する。deprecatedな `sandbox-exec` を長期採用済みとはしない。生成したプロセスとソケットだけを終了する。


`INVPN_F04_MODE=provider_crash ./scripts/experiment run F04-failure-containment` は、稼働中にBのTCPだけが拒否されることを確認し、試験Provider自身にabortを実行させる。同じA/Bを生かしたまま500ms上限の新規TCP接続を各10回試す。元のProvider PID消失、コールバック、受信記録、後始末を保存する。ループバックIPv4 TCPの限定試験で、UDP・既存接続・独立した保護機構は未検証。

`INVPN_F04_MODE=provider_crash INVPN_F04_DESTINATION=external_https ./scripts/experiment run F04-failure-containment` は、持続する同一libcurlプローブから毎回新しいTLS接続を作る。プロキシを無効化し、証明書検証を有効にしたままCloudflareの試験宛先のHTTP 200を観測する。ローカル受信機の代わりにHTTPS応答を記録し、外部サーバー内部のログやパケット採取とは区別する。

## 独立したContent Filterの候補

`INVPN_F04_MODE=content_filter ./scripts/experiment run F04-failure-containment`

Host/Proxy/Guard 0.0.9を導入し、GuardもmacOS上で承認する。フィルターは試験用127.0.0.1の1ポートだけを調べ、既知B PIDの新規フローを拒否する。他の宛先のdefaultActionはallow。通常A/B、透明転送のみ、透明転送とFilterの併用、Filter単独、Filter自身のabortを比較する。フィルターのPID消失とクライアント・受信機の結果を分けて記録する。

ローカルVPNを使う。試験用ブリッジは元のループバック宛先を仮想宛先10.77.0.99へ置換し、直接受信とVPN受信を別サーバーで観測する。これは製品の宛先書き換え仕様ではない。

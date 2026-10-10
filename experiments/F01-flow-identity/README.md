# F01: フロー識別

`./scripts/experiment run F01-flow-identity` は同じ `/usr/bin/curl` をA/Bとしてシェルからexecする。Providerが設定適用を返した後、IPCでBのPIDを選び、同時にHTTPS要求を開始する。一度の設定作成で3組を試す。宛先URLは `1.1.1.1` だが、このMacでは通常のcurlがNAT64の `64:ff9b::101:101` に接続したため、実際のremote_ipも保存する。外部サーバーの内部受信ログは取得しない。

追加の探索条件は `INVPN_F01_MODE` で選ぶ。

- `client_matrix`: 一度のProvider稼働中にC TCP、通常curl、IPv4指定curl、システムnc、再度Cを比較。
- `external_sockets`: 外向きC TCP/UDP。sendの成功を受信の証拠にはしない。
- `loopback_confirm`: 独立したTCP受信／UDP echoスレッドを使い、毎回新規のA/Bを起動する。既定5組、`INVPN_F01_PAIRS=100` で各プロトコル100組。テストID付き受信、audit token、PID、判断を照合する。

`INVPN_F01_MODE=loopback ./scripts/experiment run F01-flow-identity` は専用のCプローブと同一Mac上のTCP/UDP受信機を使う初期候補。対照→Provider稼働→停止後を採取する。Providerにフロー通知がない場合、その結果から停止時の漏れや識別不能を一般化しない。

実験後は対象プロセスを終了して試験設定を削除する。`loopback` は旧探索手順で、UDP送信直後にソケットを閉じる。`loopback_confirm` はUDP応答を待って閉じる。別条件なので結果を混同しない。100組の照合はループバックで実施済み。子孫、PID再利用、VPN転送は別の残件。

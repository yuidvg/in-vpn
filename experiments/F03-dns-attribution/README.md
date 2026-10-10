# F03: DNS要求元の探索

`./scripts/experiment run F03-dns-attribution` は、新しい名前を `invpn-feasibility.example.com` 配下に生成し、同じCのgetaddrinfoプローブをA/Bから起動する。次にdigを対照として試す。Provider 0.0.6以降の試験ドメイン限定DNSルールを使い、BのPIDを既知として遮断を指定する。

システムのDNS設定やキャッシュは変更しない。要求元のaudit tokenとプロセス、応答／タイムアウトを採取する。回答を変える管理下リゾルバー、キャッシュ分離、VPN内DNS、URLSessionは未実装。この初期試験だけでDNS分離の成立とはしない。

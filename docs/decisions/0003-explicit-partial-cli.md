# 0003: 能力を明示する部分CLIを実装する

日付: 2026-10-09（JST）  
状態: 初版の採用範囲。完全隔離方式の決定ではない。

ユーザーは第2報後、設計に影響する点を確認し、実装したうえでできる範囲・できない範囲を明示するよう指示した。

第2報の子孫・DNS・障害時遮断の反例に加え、全宛先・一般IPv6・UDP/QUIC・半閉鎖・長時間接続・バックエンドの再捕捉・端末制御・導入と他ユーザー認可が設計に影響する。試験用コードはそのまま一般的な透過実行として提供しない。

Python標準ライブラリでCLI・プロファイル・バックエンド・ランチャーを、Swift/Cで独立した製品用TCP Providerを実装する。製品は実験コードをimport・リンクしない。

- 通常の `in-vpn vpn1 command` は完全隔離の契約を保持し、条件不足でコマンド実行前に拒否する。
- `--mode proxy` はHTTP/SOCKS設定を利用するツールと、その環境を継承するシェル向けの部分機能。
- `--mode transparent --experimental --destination IPv4:port` は起点PIDの指定宛先TCPだけを扱う。子孫・標準DNS・UDP・他宛先・故障時遮断を含めない。
- 透過起動にはexec barrierと登録応答、BSD開始時刻の照合、取得後のaudit世代照合を入れる。POSIXセッションIDによる子孫選別は採用しない。
- 両部分モードで直接通信が可能であることを、起動時と能力一覧に表示する。

bundle IDは `jp.diverge.invpn` と `jp.diverge.invpn.proxy`。開発署名の導入を、Developer ID配布・公証の成立証明とは扱わない。

実装・使用方法・検証の正本は [implementation.md](../implementation.md)。[purpose.md](../purpose.md)の必須要件は下げない。

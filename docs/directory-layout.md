# リポジトリのディレクトリ設計

作成日: 2026-10-07（JST）  
状態: 配置方針と将来の構成案。実験に加え、2026-10-09に製品初版のsrc/invpn、macos、tests、verification、binを実装した。

初版はPythonの`pyproject.toml`と`src/invpn/`を採用した。`macos/`は独立した製品用bundle、`test-support/macos/`は旧実験用bundleとして分離する。実装済み配置は[implementation.md](implementation.md)。以下のSwiftPM等は将来候補を含む設計ツリー。

2026-10-10に、ルートの`flake.nix`・`flake.lock`、`packaging/nix/package.nix`、秘密を含まないビルド入力を作る`scripts/nix-package`、導入済みCLIの確認用`verification/nix-package.py`を追加した。配布・対象範囲は[nix.md](nix.md)。署名済みアプリと秘密設定はNix入力へ含めない。

## 配置の方針

最初に [事前不確実性テスト](feasibility.md) の実験を実装する。結果に応じて構成を変えられるよう、実験コード、製品コード、製品の受け入れ試験、実行時の証跡を分ける。製品から実験コードを参照しない。

以下のツリーは配置先の設計であり、作成済みファイルの一覧ではない。実験に必要な最小ファイルから追加し、将来用の空ディレクトリや動かない実装の雛形を先に増やさない。

## 全体構成

```text
in_vpn/
├── README.md                         # 現在の状態・読む順序・実行入口
├── docs/
│   ├── report-2.md                   # 第2回の実測と反例
│   ├── purpose.md                    # 目的とR1〜R8
│   ├── feasibility.md                # 方式を選ぶF00〜F08の設計
│   ├── architecture.md               # 候補構成 → 実証後に採用構成へ更新
│   ├── directory-layout.md           # この文書
│   ├── verification.md               # 製品のV00〜V25
│   ├── decisions/                    # 証跡に基づく設計判断（ADR）
│   │   └── NNNN-<decision>.md
│   └── evidence/                     # 秘匿処理・確認済みの報告
│       ├── feasibility/<run-id>/
│       └── acceptance/<run-id>/
├── experiments/                      # F系列。製品未実装でも実行可能
│   ├── README.md                     # 実験一覧・依存・現在の結果
│   ├── F00-platform/
│   ├── F01-flow-identity/
│   ├── F02-process-lineage/
│   ├── F03-dns-attribution/
│   ├── F04-failure-containment/
│   ├── F05-vpn-forwarding/
│   ├── F06-workspace-compatibility/
│   ├── F07-multiple-vpns/
│   └── F08-composition/
├── test-support/                     # 実験・受け入れ試験の観測用部品
│   ├── probes/                       # TCP/UDP・DNS・子孫生成のクライアント
│   ├── macos/                        # 最小の検証用Host/Extensionとビルド設定
│   ├── network/                      # 実装済み: 認証中継、WireGuard peer生成
│   ├── servers/                      # 受信ログ・DNS回答を制御する試験サーバー
│   ├── collectors/                   # プロセス・フロー・パケット採取
│   ├── fixtures/                     # 合成入力、秘密を含まない設定例
│   └── schemas/                      # 実行情報・観測イベントの共通形式
├── scripts/
│   ├── experiment                    # F系列の準備・実行・採取・後始末
│   ├── publish-feasibility           # 実装済み: 指定runの秘匿処理済み証跡を出力
│   ├── verify                        # 製品のV系列の実行入口
│   ├── build                         # 製品のビルド入口
│   └── release                       # 署名・公証・配布物の作成入口
├── Package.swift                     # Swift採用時の製品パッケージ定義
├── Sources/                          # 製品のCLI・ライブラリ・制御サービス
│   ├── InVPNCore/                    # セッション・プロファイル・状態遷移
│   ├── InVPNIPC/                     # ローカル制御のメッセージと版管理
│   ├── InVPNPlatform/                # 採用したmacOS追跡・起動・遮断の実装
│   ├── InVPNTransport/               # 転送とVPNバックエンドの制御
│   ├── InVPNService/                 # 上記を組み合わせる制御サービス
│   └── in-vpn/                      # CLIエントリーポイント
├── Tests/                            # 製品のSwiftPMによる単体・部品試験
│   ├── InVPNCoreTests/
│   ├── InVPNIPCTests/
│   └── InVPNTransportTests/
├── macos/                            # 署名済み製品のXcode構成
│   ├── InVPN.xcodeproj/
│   ├── InVPNApp/                     # 導入・OS承認・状態表示
│   ├── Extensions/
│   │   ├── TransparentProxy/         # F系列で採用した場合
│   │   ├── DNSProxy/                 # 必要性と成立を確認した場合のみ
│   │   └── NetworkFilter/            # 必要性と成立を確認した場合のみ
│   ├── Config/                       # Info.plist・entitlements・xcconfig
│   └── Tests/                        # 署名・OS機能を要する部品試験
├── verification/                     # V系列の実行可能な受け入れ試験
│   ├── cases/                        # V番号と対応する手順・アサーション
│   └── fixtures/                     # 製品CLI等への試験入力
├── config/
│   ├── schemas/                      # 製品の公開設定形式
│   └── examples/                     # 秘密情報は参照・プレースホルダーのみ
├── packaging/
│   ├── macos/                        # 署名済みアプリ等の配布構成
│   └── nix/                          # 製品のパッケージ定義。マシン設定は置かない
├── .gitignore                        # 実験実装開始時に秘密・生成物を除外
└── .local/                           # ローカル実行情報。すべてGit対象外
    ├── config/                       # このMacの試験先・鍵への参照
    ├── secrets/                      # 必要な場合のローカル秘密ファイル
    ├── build/                        # 実験・製品のビルド、DerivedData等
    └── runs/
        ├── feasibility/<run-id>/     # F系列の生データ
        └── acceptance/<run-id>/      # V系列の生データ
```

Sources/やmacos/の内訳は、SwiftとNetwork Extensionを採用した場合の案である。F系列の結果に応じて責務を統合・分割し、必要なtargetだけ作る。Endpoint Securityを採用する場合も、追跡コードはInVPNPlatformへ、別System Extensionが必要ならmacos/Extensions/に配置する。追加Extensionを初めから必須とはしない。

## 実験ディレクトリの中身

実験ごとの最低限の構成は次のとおり。

```text
experiments/F03-dns-attribution/
├── README.md        # 問い、候補、前提、再現手順、観測、反証条件、復旧
├── run              # 共通入口から呼ぶ実行処理。試験環境を受け取る
├── Sources/         # この実験だけのコード。必要な場合のみ
└── fixtures/        # この実験だけの合成入力。必要な場合のみ
```

実験用のビルド定義はexperiment自身またはtest-support/内で完結させ、製品のPackage.swiftを必要としない。検証用Host/Extensionも製品用とは別のbundle IDとビルド出力を使う。候補APIごとに必要な権限を列挙し、全部の権限を付けた構成でしか動かない状態を隠さない。

README.mdには実験単位の仕様を置き、実行結果の正本はdocs/evidence/へ置く。別候補を試す場合は同じ問いの中で候補名を付け、どのソースと設定を実行したかをrun-idからたどれるようにする。

test-support/は観測のための小さな部品に限定する。二つ以上の実験で必要になったものを抽出し、先に汎用フレームワークを作らない。試験サーバーのコードも、どこへ実際に配置したかとは分ける。サーバー作成や外部サービスの契約はこの設計に含まれない。

## 一回の実行で残すもの

```text
.local/runs/feasibility/<run-id>/
├── manifest.json       # 実験・候補・OS・版・条件・入力ハッシュ・実施状態
├── timeline.jsonl      # テストID付きの生成・分類・送信・故障注入イベント
├── client.jsonl        # クライアント側の操作と結果
├── receiver.jsonl      # 受信側の接続元・テストID・連番
├── dns.jsonl           # DNS問い合わせ・回答・観測点
├── capture/            # 必要な範囲のパケット記録
├── logs/               # ビルド・Host/Extensionのログ
└── cleanup.json        # 作成した資源と元の状態への復帰結果
```

この構成は共通の保存契約で、実験に不要な空ファイルは作らない。パケット採取の失敗・欠落、欠けた受信ログ、未取得の権限はmanifestと報告に残す。run-idには時刻と一意な識別子を含め、上書きしない。ソースはGitのコミットに加え、未コミット変更があればそのハッシュも記録する。Git未初期化ならソース一式のハッシュと保存した版で識別する。

秘密情報の参照先を含むローカル設定、証明書・鍵、未処理のパケット・ログはGitへ入れない。ローカル秘密ファイルが必要な場合は所有者だけにアクセスを許し、可能ならKeychainまたはリポジトリ外の秘密保管を使う。

最初の実験実装時に.gitignoreを追加し、`.local/`、SwiftPMの `.build/`、Xcodeのユーザー設定や生成物を除外する。依存バージョンを固定するファイルと署名前のentitlements設定は管理対象にし、署名鍵・証明書の秘密部分・ローカルのプロビジョニング情報を混在させない。

確認済みの報告は次のように分ける。

```text
docs/evidence/feasibility/<run-id>/
├── report.md                 # 事実・推論・結論・制約・設計への影響
├── manifest.redacted.json    # 秘密を除いた再現条件
└── observations.redacted.jsonl  # 結論を追える必要最小限の観測
```

報告から生データの場所とハッシュを参照できるようにする。保存場所がローカルだけならその旨を示し、報告だけで完全再現できるとは記載しない。決定記録は証跡を参照し、実験のREADMEへ結果を重複転記しない。

## 実行入口の契約案

`scripts/experiment run` は [experiments/README.md](../experiments/README.md) に挙げた実装済み実験で利用できる。F03の要求元探索は実行できる。以下の独立cleanup・製品verifyは今後の仕様で、まだ実行できない。現在の実験は各runの終了処理で後始末を行い、状態を保存する。

```sh
./scripts/experiment run F03-dns-attribution
./scripts/experiment cleanup <run-id>
./scripts/verify run V07
```

通常のrunは、前提確認、ビルド、試験資源の準備、基準状態の採取、実験、証跡保存、後始末までを一つの入口から行う。端末ごとの設定は `.local/config/` 等から読み、秘密情報をコマンド引数に要求しない。

必要なOS承認や未取得のentitlementは不足条件として示す。無言で開発用の迂回設定や全体DNS変更を行わない。途中失敗でも作成資源と復帰状態を残し、cleanupはそのrunが作った資源だけを処理する。既存VPNの一括停止や既存設定の上書きを復旧手順にしない。

通常の後始末では試験プロセスと残った子孫の終了を確認してから遮断・経路設定を解除する。故障注入として解除する場合は、実験条件と観測範囲を別に記録する。終了を確認できなかった対象を残したまま、復帰成功とは報告しない。

## コードとビルドの境界

| 場所 | 依存してよいもの | 依存させないもの |
| --- | --- | --- |
| experiments/ | test-support/、実験用の最小SDK・バックエンド | 完成した製品CLI・サービス・UI |
| test-support/ | 試験用SDK・ライブラリ | 製品実装による自己判定。期待値と実際の経路は独立に採取する |
| InVPNCore | 基本型と純粋な状態遷移 | Network Extension、実行中のsing-box、UI |
| InVPNIPC | Coreの型と通信契約 | CLIやUIの実装 |
| InVPNPlatform / InVPNTransport | Core、必要なOS/API・バックエンド | 実験用の固定PID・観測専用コード |
| CLI・Service・macOSの各target | 必要な製品モジュール | experiments/、test-support/ |
| Tests/・macos/Tests/ | 試験対象の製品モジュール、試験用部品 | 実機でしか確かめられない条件をモックだけで合格とすること |
| verification/ | 製品の公開入口、test-support/の観測装置 | 内部の成功フラグだけによる合否判定 |

SwiftPMはCLI・共有ライブラリ等、Xcodeはアプリ・Extensionの埋め込みと署名の責務を持つ案とする。macos側はルートのパッケージを参照し、同じ製品ソースを複製しない。追跡・DNS・遮断方式が確定するまでは、これらの製品targetを作ることを事前検証の前提にしない。

Nixは開発依存と配布物の導入を助けるが、Appleの署名・OS承認の代替として扱わない。nix-darwin側には利用する版、マシン別設定、起動設定を置き、このリポジトリのexperiments/や製品ソースを移さない。

## 実験から製品へ移す手順

1. F系列の結果と採用条件をdocs/evidence/、docs/decisions/へ保存する。
2. architecture.mdを採用結果で更新し、必要な製品targetと配置を確定する。
3. 実験で使ったAPI処理を整理して製品モジュールへ実装する。固定したテストID・PID・宛先、権限の迂回、観測用の例外は持ち込まない。
4. 純粋な状態遷移はTests/、署名を要する部品はmacos/Tests/、利用者から見た要件はverification/へ試験を追加する。
5. F系列の最小反例と再現手順は残し、OSや方式を変更したときに再実行する。製品の完了はV系列で判断する。

いま確定するのは文書・実験・製品・証跡の責務と置き場である。実験結果で変わるAPI、Extension数、言語・ビルド構成の詳細は、採用判断の後で確定する。

# Feasibility report 2

実施日: 2026-10-07（JST）。対象: macOS 27.0.1 (26A434)、Apple silicon、Xcode 27.0、sing-box 1.14.1。Tailscaleは切断した条件。

**6項目それぞれに実験を追加した。通常ソケットのVPN転送と2本のローカルWireGuardへの振り分けは成立したが、目的全体の合格には至っていない。DNS分離・堅牢な子孫識別・障害時遮断には反例がある。権限不足のEndpoint Securityと、独立した2つの外部VPN出口は未検証として残す。** 「実験を実行した」と「必要な能力が成立した」を区別する。

## 判定

| 必要な能力 | 今回の判定 | 根拠・限界 |
| --- | --- | --- |
| 同じアプリでも実行ごとに通信を選別する | 限定条件で成立 | 同じcurlを同時解放し、既知PIDごとに通常回線／外部VPN、またはVPN1／VPN2へ分離。世代を含むPID管理は製品未実装 |
| 起動したコマンドと子孫をまとめて扱う | 候補を検証し、不合格 | 自動セッションID照合でfork 100件・exec 100件・親終了後1件はVPNへ到達。子自身のsetsidで所属が外れた。Endpoint Securityは権限不足で未検証 |
| 普通のソケットをアプリ改修なしにVPNへ送る | 限定条件で成立 | 未改修のsystem curlからNE→中継→SOCKS→外部WireGuardでTLS成功。UDPは通常ソケットで2本のローカルWireGuardを往復。標準DNSのUDPも外部VPN内のDNSへ中継して応答取得 |
| 実行ごとにDNSの問い合わせ先・回答・キャッシュを分ける | 不合格 | 新規名はVPN別回答。同名を使うと別VPN・通常セッションにも先の回答が返る。TTL=0でも直後の再利用で再現 |
| VPN／Provider故障時にも通常回線へ漏らさない | 不合格 | VPNバックエンド停止では対象が失敗し通常側は成功。Providerクラッシュでは対象の外部HTTPSが8/10成功。独立Filterも自身のクラッシュ後に直接通信を許した |
| 複数VPNへ同時に振り分ける | ローカルの独立WireGuard 2本では成立 | 鍵・peer・バックエンド・受信機を別にし、同じ宛先でTCP/UDPを分離。片側停止時も他方は継続。別々の外部VPN出口2本は設定が1本しかなく未検証 |

これは製品CLIやV00〜V25の合格報告ではない。試験用PID登録、宛先限定ルール、有効期間30秒の試験中継を使っている。実験の終了コード0も機能合格を意味しない。

## 実験構成

```text
通常ソケットを使う既存curl / Cプローブ / getaddrinfo
  → NETransparentProxyProvider（audit tokenからPID、またはgetsidで分類）
  → 認証付きローカル中継（TCPストリーム／UDPデータグラム）
  → 認証付きSOCKS入力
  → sing-box userspace WireGuard
  → 外部VPN、または同じMac上の独立した試験peer
```

既存クライアントにHTTP_PROXY等を渡さず、curlは設定ファイルを無効にし、`--proxy '' --noproxy '*'`を指定した。SOCKS処理は中継側だけにある。WireGuardは`system: false`で、システムの既定経路やDNSサーバーを書き換えない。

ローカルVPN試験は実際のWireGuard暗号化通信であり、VPN応答を偽装するモックではない。ただし対向peerもこのMac上で動く。2本とも10.77.0.0/24を使い、同じ宛先へ送っても別々の受信機に届くかを見る。各組で新しい鍵を生成し、受信側で試験用アドレス・ポートを専用HTTP／DNS／UDP受信機へ変換する。これを「異なる国のVPN出口を検証した」とは扱わない。

Network Extensionは0.0.7〜0.0.10へ段階的に更新した。各実行のソース保存版と導入バイナリのSHA-256はmanifestに残す。旧実行のソースを現在のファイルで上書きしていない。

## 1. 同一アプリの選別と外部VPNへの透明転送

[外部VPNの完走記録](evidence/feasibility/20261007T091238Z-F05-39b226/report.md)。同じ未改修のsystem curlをA/Bとして起動し、Bの既知PIDだけを登録した。3組ともAのTLS応答は通常出口、Bは事前にSOCKS経由で確認したVPN出口と一致し、両出口は異なった。[別起動の成功](evidence/feasibility/20261007T091115Z-F05-14f634/report.md)でも3組が一致した。

宛先はapi.ipify.org:443。試験準備の名前解決は通常DNSで行い、そのIPv4を`--resolve`へ渡した。従ってこのHTTPS結果だけでDNS分離を主張しない。TLS証明書検証は有効。出口IPは`.local/`だけに保存し、公開証跡には一致判定を残した。外部サーバー内部のログやパケットキャプチャは取得していない。

標準getaddrinfoによる新規試験名もProviderで受け、中継のUDP ASSOCIATEから設定済みVPN内DNSへ送り、NXDOMAINに相当する結果8を得た。これは経路・応答取得の証拠であり、名前が存在するという成功やキャッシュ分離の成功ではない。

最初の試行ではTLS EOF、続く試行ではVPN側がタイムアウトした。sing-boxのログには `failed to receive makeReceiveMsgX packet: message too long` と受信処理停止が残った。MTUを1280に変更した2実行は完走し、そのログは出なかった。変更と成功の対応は観測したが、根本原因の確定・一般的な修正・長時間安定性までは主張しない。

## 2. 子孫の自動分類

[セッションID実験](evidence/feasibility/20261007T090903Z-F02-fa8e62/report.md)では、ランチャーを新しいPOSIXセッションで起動し、起点PIDだけを登録した。子PIDをProviderへ個別登録せず、フロー発生時のPIDから`getsid`を取得してWireGuardへ送った。

| 条件 | 受信したUDP往復 | 判定 |
| --- | --- | --- |
| forkした子100件 | 100/100 | この条件では所属維持 |
| fork→execした子100件 | 100/100 | この条件では所属維持 |
| double-fork後、PPID=1になった子 | 1/1 | この条件では所属維持 |
| double-fork後、子自身がsetsid | 0/1 | Providerがdecline_direct。所属の取りこぼし |

最後の宛先はローカルVPN内の仮想アドレスなので、VPN受信機には届かなかった。「直接送信の許可判断」と「外部へ実データが漏れた」は区別する。セッションIDを変えられる通常のデーモン化が反例になるため、これを完全な子孫追跡として採用しない。短命プロセスの消失前の照合、PID再利用、10,000件の確認も完了していない。

[一覧ポーリングの再確認](evidence/feasibility/20261007T090253Z-F02-4ebd80/report.md)でも、通信した1,000子のうち観測できたのは12、988は未検出だった。[F00再確認](evidence/feasibility/20261007T090252Z-F00-aa493a/report.md)では`es_new_descendants_client`が`ERR_NOT_ENTITLED`、対応プロファイル0件。OS APIの存在だけではEndpoint Securityによる代替案を実証できない。

## 3. DNSの問い合わせ・回答・共有状態

[TTL=120の試験](evidence/feasibility/20261007T090550Z-F07-30b996/report.md)、[TTL=0の試験](evidence/feasibility/20261007T091510Z-F07-8ac2bd/report.md)、[TTL=0の再確認](evidence/feasibility/20261007T091642Z-F07-8ba45c/report.md)。試験用ドメイン配下のランダムな名前だけを使い、システム全体のDNSキャッシュは消去していない。

受信機はVPN1で192.0.2.11、VPN2で192.0.2.22を返す。新規名をVPNごとに別々に引くと、それぞれ正しい回答を取得した。しかし同じ名前をVPN1→VPN2の順で引くとVPN2も.11を得た。順序を逆にするとVPN1も.22を得た。同時要求でも両方が片側の回答になった。保護対象外の通常セッションも、先にVPN1で取得した.11を得た。

Provider・受信機の記録と照合すると、後続の標準問い合わせのすべてが独立したVPN別DNS要求にはならない。共有キャッシュ／要求集約を隔離できていないことの反例である。TTL=0でも直後の交互要求・同時要求で再現した。OS内部のどの段階がキャッシュ・集約を担当したかを完全に分解した試験ではない。

直接digは試験用10.77.0.99:18080への普通のUDPソケットとして2本に分け、同じ名前でそれぞれ.11/.22を取得できた。初回は受信機がdigの追加フラグをDNSとして認識せず、そのままエコーしてしまった。フラグ判定を修正した後のTTL=0の2実行で正しい回答を確認した。初回を成功に数えない。

この18080番試験は、任意の直接DNSの53番通信を捕捉できる証明ではない。SDKの`NETransparentProxyNetworkSettings.h`にはアドレスベースルールの53番指定禁止が明記されている。今回の標準DNSは専用ドメインルールで捕捉した。全DNS名、DoH/DoT、URLSession、各種キャッシュを含む要件は未達である。

## 4. VPN停止・Providerクラッシュ・独立Filter

外部VPN試験では、バックエンド停止後もAは通常出口で成功し、BはTLS接続に失敗した。ローカル中継の停止後もBは失敗した。その後Providerをabortし、元PIDの消失を確認した。事前登録したBの同一プロセスから新しいTLS接続を10回試すと、最初の2回は失敗、残る8回はHTTP 200になった。VPNと中継は既に停止しており、設定削除は観測後に実施した。透明Providerが消えた後の直接通信を再現した。

独立した`NEFilterDataProvider`も作成・署名・承認して実行した。[故障を確認できた試験](evidence/feasibility/20261007T091938Z-F04-0bcd4c/report.md)では、通常側のローカル受信機とVPN側の受信機を分けた。

- Filterなし: Aは通常側、BはVPN側でHTTP 200。
- Filter併用: Aは成功したがBは失敗し、VPN側にはHTTP要求本文が届かなかった。接続のacceptだけをデータ到達に数えない。
- Filter単独: Aは成功、Bは3回とも直接通信を拒否。
- Filter自身のabort後: 元PIDが消え、別PIDを観測。Bの10回中10回が通常側へ届きHTTP 200。Aも継続成功。

最初のFilter試験は設定更新だけではabortが走らず元PIDが残った。その結果を故障後遮断の成功には数えない。設定を除去・再作成して故障を確認した記録を上の判定に使う。後処理で保留中の故障注入をキャンセルする処理を追加した[最終版0.0.10の再試験](evidence/feasibility/20261007T092522Z-F04-de093e/report.md)でも、元PID消失後にBの10回中10回が通常側へ届いた。正常転送を併用時に止める結果も再現した。

sandboxの`network-outbound`禁止も、対象クライアントの正常な透明転送を止めた。この単純な組み合わせも正常系と障害系を同時に満たさない。前回得た「接続済みソケットFDを持ち込むとsandboxを越えて送信できる」という反例も取り消さない。

今回の候補は不合格だが、macOS上のすべての複合方式が不可能という証明ではない。独立Filter、監視・再起動、sandboxを置いたという構成図だけでfail-closedを主張しない。

## 5. 複数VPN

[最終の2本同時試験](evidence/feasibility/20261007T091642Z-F07-8ba45c/report.md)では、鍵・WireGuard peer・sing-boxプロセス・SOCKS入力・中継認証・受信機が独立している。起動前に両peerの疎通を個別に確認した。

同じcurlバイナリの2プロセスを同時解放した5組、合計10接続は、すべて指定側の`vpn1`／`vpn2`回答を受けた。受信側の要求パスにも逆側の混入はなかった。通常UDPソケットも各側5回、合計10往復が指定受信機と一致した。VPN1のバックエンドだけを停止するとVPN1は失敗し、VPN2は成功を維持した。同等のTCP/UDP振り分けは別起動でも再現している。

外部用に供給されたWireGuard設定は1本。2本目の保存先を問い合わせたが、別の設定はこの実行時点で利用できていない。同じ鍵を2つのプロセスで使って2本の独立VPNと数えることはしていない。

## 証拠の保存・再現・後始末

- [実験入口](../scripts/experiment)はソース保存版、ソース／導入バイナリのハッシュ、コマンド結果、観測を実行ごとに保存する。後半の実行はモード・TTLもmanifestに保存する。
- [公開用抽出](../scripts/publish-feasibility)は指定した完了runだけを扱い、audit tokenの生値を長さ・SHA-256に置換する。コマンド生出力や秘密設定は公開しない。失敗・タイムアウトも残す。
- WireGuard秘密鍵、SOCKS／中継の認証値、出口IP、詳細ログは`.local/`内。供給された設定は`.local/secrets/wg-CH-FREE-8.conf`、親700・ファイル600。生成した試験鍵も`.local/`だけに保存。
- 本物のパケット採取は未実施。ローカル実験は独立受信機の記録、外部実験はTLS応答と中継・Providerの記録で評価した。
- 各試験の子プロセス・バックエンド・受信機を終了し、試験用Proxy／Filter設定を削除した。最終確認はProxyが`no_configuration`、Filter削除成功、残存する試験プローブ／sing-boxが0。既存mirrorは1プロセス、TailscaleはDisconnectedのまま。アプリと承認済みProxy／Guard 0.0.10は再試験用に残した。

[証跡の独立照合結果](evidence/feasibility/report-2-checks.json)に、17runの保存ソースのハッシュ、実際の出口応答、VPN別受信、DNS混入、クラッシュ後の受信、秘密情報走査、文書リンクの確認結果を保存した。機能が不合格であることと、報告の数値・根拠が一致することは別の判定である。

再現手順は[F02](../experiments/F02-process-lineage/README.md)、[F04](../experiments/F04-failure-containment/README.md)、[F05](../experiments/F05-vpn-forwarding/README.md)、[F07](../experiments/F07-multiple-vpns/README.md)に記載。

## 設計に戻す判断と未完了条件

1. フロー分類・TCP/UDP中継・WireGuard接続の技術的な経路は成立した。製品へ移す前にIPv6一般、半閉鎖、長時間転送、UDP多宛先・MTUなどを検証する。
2. POSIXセッションID単独による子孫分類は採用しない。Endpoint Securityを実機試験するには承認済みentitlement／プロファイルが必要。権限確認を通った後も、fork/exec/再親化/短命/PID再利用の試験が残る。
3. 標準DNSへの透明中継だけではR4を満たさない。共有キャッシュと問い合わせ集約を含めた隔離方式が必要で、別Providerの名前を挙げるだけでは解決としない。
4. Provider単独、既知PIDを拒否する単純なContent Filter、単純なsandbox禁止を、今回の形では遮断境界に採用しない。正常転送と故障時遮断を同時に満たす方式が必要。
5. 独立した外部VPN設定2本を使う実験と、上記を同時に成立させるF08は未完了。R1〜R8を満たす製品CLIの実装完了には到達していない。

根拠の仕様: [WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)、[route action](https://sing-box.sagernet.org/configuration/route/rule_action/)、[NETransparentProxyProvider](https://developer.apple.com/documentation/networkextension/netransparentproxyprovider)、[Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)。仕様・SDKの記載と、上記の実測は別の根拠として扱う。

## 実行一覧

中断を含む全runを残した。詳細な条件とソースの版は各manifestを参照。

| Run | ハーネス状態 |
| --- | --- |
| [20261007T090038Z-F07-eef596](evidence/feasibility/20261007T090038Z-F07-eef596/report.md) | error |
| [20261007T090131Z-F07-d0d82e](evidence/feasibility/20261007T090131Z-F07-d0d82e/report.md) | executed |
| [20261007T090252Z-F00-aa493a](evidence/feasibility/20261007T090252Z-F00-aa493a/report.md) | executed |
| [20261007T090253Z-F02-4ebd80](evidence/feasibility/20261007T090253Z-F02-4ebd80/report.md) | executed |
| [20261007T090408Z-F05-d9d318](evidence/feasibility/20261007T090408Z-F05-d9d318/report.md) | error |
| [20261007T090440Z-F05-57df80](evidence/feasibility/20261007T090440Z-F05-57df80/report.md) | executed |
| [20261007T090550Z-F07-30b996](evidence/feasibility/20261007T090550Z-F07-30b996/report.md) | executed |
| [20261007T090746Z-F05-a22416](evidence/feasibility/20261007T090746Z-F05-a22416/report.md) | error |
| [20261007T090903Z-F02-fa8e62](evidence/feasibility/20261007T090903Z-F02-fa8e62/report.md) | executed |
| [20261007T091004Z-F05-6a102b](evidence/feasibility/20261007T091004Z-F05-6a102b/report.md) | error |
| [20261007T091115Z-F05-14f634](evidence/feasibility/20261007T091115Z-F05-14f634/report.md) | executed |
| [20261007T091238Z-F05-39b226](evidence/feasibility/20261007T091238Z-F05-39b226/report.md) | executed |
| [20261007T091510Z-F07-8ac2bd](evidence/feasibility/20261007T091510Z-F07-8ac2bd/report.md) | executed |
| [20261007T091642Z-F07-8ba45c](evidence/feasibility/20261007T091642Z-F07-8ba45c/report.md) | executed |
| [20261007T091724Z-F04-e4dbbe](evidence/feasibility/20261007T091724Z-F04-e4dbbe/report.md) | executed |
| [20261007T091938Z-F04-0bcd4c](evidence/feasibility/20261007T091938Z-F04-0bcd4c/report.md) | executed |
| [20261007T092522Z-F04-de093e](evidence/feasibility/20261007T092522Z-F04-de093e/report.md) | executed |

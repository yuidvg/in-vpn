# in-vpn

macOSで、現在のディレクトリ・ファイル・ツールを使いながら、指定したコマンドやシェルの通信を選んだVPNへ流すためのCLIです。

**0.1.0は部分実装です。proxy対応ツールのTCP通信をVPNへ送れます。子孫全体の透明選別、システムDNSの分離、故障時の直接通信遮断は提供していません。** 詳細は [実装と利用範囲](docs/implementation.md) と `in-vpn capabilities --json` で確認できます。

| 能力 | 0.1.0でできる範囲・できない範囲 |
| --- | --- |
| proxy対応TCP | 利用可能。認証付きローカルHTTP/SOCKSからuserspace WireGuardへ転送 |
| 作業環境の保持 | cwd、PATH、ファイル、引数、stdio、終了コードを保持。端末の前景制御と通常シグナルに対応。socketのstdioは拒否 |
| proxyモードのシェル・子孫 | proxy環境変数を継承。設定を無視・上書きする通信は通常回線を使える |
| proxyへ渡した名前の解決 | VPN内のDNSを使用。ツールが通常のDNSで先に解決する場合は対象外 |
| 普通のTCPソケットの透過転送 | 実験コードのみ。起点PID・指定IPv4/ポートに限定。製品Network ExtensionのOS承認と実機確認が必要 |
| 子孫全体の透明選別 | 利用不可。短命プロセス、`setsid()`、親終了を確実に扱う方式が未達 |
| 通常のDNS・回答・キャッシュの分離 | 利用不可。`getaddrinfo`や共有キャッシュを実行ごとに分離できない |
| VPN・Provider・CLIの故障時遮断 | 利用不可。通常回線への漏れを防げない |
| UDP・QUIC・ICMP、一般IPv6の透過転送 | 未対応。通常経路で通信する可能性がある |
| 複数VPN | 異なる鍵のproxyプロファイルは並行利用可能。同じ鍵の並行利用と透過モードの並行利用は拒否 |

通常の `in-vpn vpn1 command` / `in-vpn vpn1 shell` は完全隔離を要求するため、**コマンドを実行せず終了78で拒否します。** 現在は部分モードを明示して使います。proxyモードでは直接通信を遮断しません。

## Nixで使う

Apple SiliconのmacOS（`aarch64-darwin`）向けです。Nix版はPythonとsing-boxを固定して提供します。

```sh
nix run 'github:yuidvg/in-vpn/v0.1.0#invpn' -- --version
nix run 'github:yuidvg/in-vpn/v0.1.0#invpn' -- capabilities --json
nix build 'github:yuidvg/in-vpn/v0.1.0#invpn'

./result/bin/in-vpn profiles import vpn1 /path/to/dedicated-WireGuard.conf
./result/bin/in-vpn --mode proxy vpn1 curl --disable https://example.com
./result/bin/in-vpn --mode proxy vpn1 shell
```

WireGuard設定は実行時に非公開ディレクトリへ登録します。秘密鍵をGitやNix式に含めないでください。プロファイルには専用の鍵を使い、同じ鍵の重複登録・同時実行はできません。

nix-darwinではflake inputと導入モジュールを追加します。

```nix
# 既存flakeの inputs に追加
invpn.url = "github:yuidvg/in-vpn/v0.1.0";

# darwinSystem の modules に追加
modules = [
  inputs.invpn.darwinModules.default
  { programs.invpn.enable = true; }
];
```

モジュールはCLIを導入します。署名が必要なネイティブアプリは別途導入・OS承認が必要で、Nixパッケージには含めません。通常のproxyモードではネイティブアプリは不要です。[Nixの導入・検証](docs/nix.md)、[ネイティブアプリ](macos/README.md)を参照してください。

## ソースから使う

Python 3.11以上とsing-box 1.14.xが必要です。

```sh
./bin/in-vpn profiles import vpn1 /path/to/dedicated-WireGuard.conf
./bin/in-vpn --mode proxy vpn1 curl --disable https://example.com
./scripts/install-cli
```

Git未初期化のフォルダや展開したソースでNixを使う場合は、許可したファイルだけを入力にする `./scripts/nix-package build` / `run` / `check` を利用してください。非Gitの作業フォルダ全体をflake入力にすると、追跡対象外の秘密設定もNix storeへコピーされ得ます。

## 設計と検証

1. [目的と要件](docs/purpose.md)
2. [macOSの事前不確実性テスト](docs/feasibility.md)
3. [ディレクトリ設計](docs/directory-layout.md)
4. [アーキテクチャ](docs/architecture.md)
5. [実装と利用範囲](docs/implementation.md)
6. [製品の受け入れ検証](docs/verification.md)

[事前実験の第2報](docs/report-2.md)では、既知PIDの通常TCPを外部VPNへ転送し、独立した2本のローカルWireGuardへの振り分けを確認しました。同時に、DNS回答の共有、`setsid()`による子孫の取りこぼし、Proxy／Filterクラッシュ後の直接通信を再現しています。事前実験の成功は製品Extensionの動作保証ではありません。[実験の実行手順](experiments/README.md)、[CLI初版の実測](docs/evidence/implementation-0.1.0.md)、[Nixパッケージの検証記録](docs/evidence/nix-package-0.1.0.md)に証跡があります。

CLI・ネイティブアプリの開発はこのリポジトリ、マシン側の導入設定はnix-darwinで管理します。

ライセンスは [MIT](LICENSE)。リポジトリ: [yuidvg/in-vpn](https://github.com/yuidvg/in-vpn)。

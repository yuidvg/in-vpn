# 検証用Network Extension

製品ではない。`ProbeProvider` は指定試験宛先のaudit tokenを記録し、既知PIDの拒否またはTCP/UDP中継を行う。`Relay.swift`は認証付きローカル中継へ送り、Python側がSOCKS・WireGuardへ接続する。POSIXセッションIDによる子孫分類も試験候補としてあるが、setsidで破綻した。PID再利用対策・完全なDNS分離・fail-closedは未成立。

候補の比較中であり、現在は指定ポートの `1.1.1.1` とその観測済みNAT64宛先 `64:ff9b::101:101`、または明示指定したIPv4の1アドレス・1ポートを設定できる。`start` の末尾に `dns` を加えると `invpn-feasibility.example.com` 配下のDNSルールも加える。対象外は `false` を返して通常の通信へ戻す。これ自体はfail-closedの製品実装ではない。

ビルド:

```sh
python3 test-support/macos/generate-project.py
xcodebuild -project test-support/macos/Feasibility.xcodeproj \
  -scheme InVPNFeasibility -configuration Debug \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath .local/build/feasibility-activation \
  -allowProvisioningUpdates DEVELOPMENT_TEAM=YOUR_TEAM_ID build
```

`-allowProvisioningUpdates` はApple側のApp ID／プロファイルを作成・更新できる。チームを確認して使う。開発署名では `app-proxy-provider` と `content-filter-provider`、Developer ID配布では別プロファイルと `app-proxy-provider-systemextension` が必要。後者の配布試験は未実施。[Appleの説明](https://developer.apple.com/forums/thread/125508)

生成された `.app` を `/Applications/InVPNFeasibility.app` に設置してから、同アプリ内の `Contents/MacOS/InVPNFeasibility` を使う。既存の同名アプリを無確認で上書きしない。

```sh
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility activate
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility start 443 TARGET_PID 1.1.1.1
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility status
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility select TARGET_PID
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility events
/Applications/InVPNFeasibility.app/Contents/MacOS/InVPNFeasibility remove
```

OSの初回承認が必要。`start_requested` や `ready: true` はフロー通知の証拠ではない。`events` と試験プロセス・受信側の結果を別に照合する。`remove` はこのアプリの試験設定だけを削除し、Extensionの登録を残す。完全な登録解除は同じバイナリの `deactivate` を使い、`systemextensionsctl list` で結果を確認する。

`generate-project.py` は公開のInfo.plist／entitlementsとXcodeプロジェクトを再生成する。秘密鍵やプロビジョニングファイルはソースツリーへ置かない。ビルド番号は試験版を区別するため更新する。

`crash` はこの試験Provider自身に `abort()` を実行させる故障注入用コマンドで、通常の停止操作ではない。F04の対照で遮断が成立した後にだけ使う。`select` はメモリ上の試験PIDを変えてイベント列を空にする。クラッシュ後も同じPID条件を保つ試験では、PIDを `start` の設定に保存しておく。


第2報の最終試験版は0.0.10/10。新しい`Guard`ターゲットは独立したContent Filter候補で、`guard-activate`による有効化も必要。`guard-start IP PORT PID [CRASH_SECONDS]`で1つの試験宛先の対象PIDを拒否し、`guard-remove`でその設定を削除する。Proxyの`remove`とは別の設定である。`guard-remove`後もExtension登録は残る。

`route /absolute/path/to/private.json`は中継対象の`pid`、中継`port`、ランダムな`secret`をProviderに登録する試験用IPC。`selection: "session"`でPOSIXセッションID候補を選ぶ。認証情報を引数の文字列や公開資料へ直接書かず、モード600の`.local/`ファイルを使う。未知の対象は通常経路に戻る診断実装であり、製品として使わない。実験と反例は[report-2.md](../../docs/report-2.md)を参照。

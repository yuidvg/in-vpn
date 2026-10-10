# F00: 実行条件

`./scripts/experiment run F00-platform` で環境・既存のプロファイルの能力を採取し、NEの型検査と未entitlementのES呼び出しを行う。署名秘密鍵とプロファイル本体は採取しない。証明書一覧のローカルログには氏名が含まれ得る。

この入口はExtensionをインストールしない。署名・有効化は `test-support/macos/README.md` の別手順で行う。実行UIDによる拒否とentitlementによる拒否、開発署名と配布署名を区別する。

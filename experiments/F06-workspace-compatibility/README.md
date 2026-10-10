# F06: 作業環境

`./scripts/experiment run F06-workspace-compatibility`。sandboxなし／network全拒否／一つのUNIXソケットだけ許可する条件を受信側と比較する。UNIX例外が新規IPv4 TCPまで開放しないことも確認する。

同じsandbox内でcwd、合成環境変数、空白・日本語・記号を含む引数、ファイル、パイプ、システムzsh、PATH上のNix Python、UID、継承TTYを確認する。任意の開発ツール、対話ジョブ制御、IPC委譲の外向き通信、実VPNとの結合は未確認。試験プロセスをwaitし、一時UNIXソケットを削除する。

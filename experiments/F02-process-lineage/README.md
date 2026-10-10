# F02: 一覧採取方式の反証

`./scripts/experiment run F02-process-lineage`。Cのランチャーがforkした子1,000個から即UDP送信して終了させる。別スレッドが `ps` の完了後10ms待って再採取する。厳密な10ms周期ではない。生成記録・受信ログ・一覧を照合し、送信済みなのに一度も一覧に現れないPIDを数える。

二重forkでは中間の親を先に終了させ、生存する孫の送信時PPIDと一覧を保存する。これは定期一覧／現在のPPIDだけに依存する候補の反例を探す試験。NEの通信帰属、イベント方式、実際のPID再利用は検証しない。受信数が生成数に足りなければ観測欠落として扱う。自分で作ったプロセスの終了と受信ソケットの閉鎖を確認する。

## セッションID候補の実測

`INVPN_F02_MODE=session ./scripts/experiment run F02-process-lineage`

Provider 0.0.8以上。ランチャーを新しいPOSIXセッションで起動し、その起点だけを登録する。Providerが各フローのPIDからgetsidを引き、子PIDを手動登録せずにWireGuardへ中継する。fork 100件、exec 100件、double-fork後PPID=1、子自身のsetsidを比較する。これは変更可能なセッションIDの候補評価で、堅牢な子孫追跡・PID再利用への対策ではない。

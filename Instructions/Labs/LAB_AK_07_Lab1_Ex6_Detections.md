# モジュール 7 - ラボ 1 - 演習 7 - 検出を作成する

## ラボ シナリオ
あなたは、Microsoft Sentinel を実装した会社で働くセキュリティ運用アナリストです。Log Analytics KQL クエリを操作し、そこからカスタム分析ルールを作成して、環境内の脅威や異常な動作を検出するのに役立ちます。

分析ルールは、環境全体で特定のイベントまたはイベント セットを検索し、特定のイベントのしきい値または条件に達したときに警告し、SOC がトリアージと調査を行うインシデントを生成し、自動化された追跡および修復プロセスで脅威に対応します。

>**ノート:** **[interactive lab simulation](https://mslabs.cloudguides.com/guides/SC-200%20Lab%20Simulation%20-%20Create%20detections)** このラボを自分のペースで確認できます。ホスト型のラボと多少の違いはありますが、主要な概念とアイデアは同じです。

### タスク 1: 永続的攻撃の検出

このタスクでは、前の演習の最初の攻撃の検出を作成します。

1. Microsoft Sentinelポータルで、全般セクションから**ログ**を選択します。

2. 以下の KQL ステートメントを実行します。

   ```KQL
   search "temp\\startup.bat"
   ```
   > ノート：イベントの結果が表示されるまで時間がかかる場合があります。その場合の対処としてWINServerを再起動してみてください。それでも表示されない場合は、結果は表示されていませんがそのまま手順を進めてください。
   
4. SecurityEvents テーブルは、データが既に正規化されていて、クエリが簡単であるように見えます。行を展開すると、レコードに関連するすべての列が表示されます。

5. クエリ結果から、脅威アクターが reg.exe を使用してレジストリ キーにキーを追加し、プログラムが C:\temp にあることがわかります。次のステートメントを実行して、検索演算子をクエリの where 演算子に置き換えます。

    ```KQL
    SecurityEvent | where Activity startswith "4688" 
    | where Process == "reg.exe" 
    | where CommandLine startswith "REG" 
    ```

6. アラートについてできるだけ多くのコンテキストを提供することにより、セキュリティオペレーションセンターアナリストを支援することが重要です。これには、調査グラフで使用するエンティティの投影が含まれます。次のクエリを実行します。

    ```KQL
    SecurityEvent | where Activity startswith "4688" 
    | where Process == "reg.exe" 
    | where CommandLine startswith "REG" 
    | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = SubjectUserName
    ```

7.  適切な検出ルールができたので、クエリのあるログ ウィンドウで、コマンド バーの 「**新しいアラート ルール**」 を選択します。  次に、「**Microsoft Sentinel アラートの作成**」 を選択します。

8. これにより、分析ルール　ウィザードが起動します。全般タブに次のように入力します

   |設定|値|
   |:----|:----|
   |名前 |Startup RegKey|
   |説明 |Startup Regkey in c:\temp|
   |戦術 |Persistence|
   |重大度 |高|

9. 「**次: ルール ロジックを設定　>**」ボタンを選択します。

10. 「**ルール ロジックの設定**」 タブで、**ルール クエリ** が既に入力されているはずです。さらに「アラートエンリッチメント」セクションの **エンティティマッピング** を確認し、エンティティが下記のように入力されている必要があります。

   |エンティティ|識別子|データフィールド|
   |:----|:----|:----|
   |Account|FullName|AccountCustomEntity|
   |Host|Hostname|HostCustomEntity|

11. **クエリのスケジューリング設定** で、次のように設定します。

   |設定|値|
   |:----|:----|
   |クエリの実行間隔 |5 分|
   |次の時間分の過去のデータを参照します |1 日|

   > **注:** 同じデータに対して意図的に多くのインシデントを生成しています。  これにより、ラボはこれらのアラートを使用できるようになります。

12. 残りのオプションは既定値のままにします。「**次: インシデントの設定 >**」を選択します。

13. **インシデントの設定** タブで、既定値のままにして、「**次: 自動応答 >」を選択します。**

14. 自動応答タブで、「新規作成」を選択し、オートメーションルールを作成します。

   |設定|値|
   |:----|:----|
   |オートメーションルール名 |PostMessage|
   |トリガー |インシデントが作成されたとき|
   |アクション |プレイブックの実行|
   |プレイブック |PostMessageTeams|

15. **確認と応答** タブで、**作成** を選択します。

### タスク 2: 特権昇格攻撃の検出

このタスクでは、セキュリティ イベント コネクタがインストールされているホスト上の **攻撃 2 (WinServer)** の検出を作成します。

1. Microsoft Sentinel メニューの 全般 セクションで **ログ** を選択します。

2. 以下の　KQL　ステートメントを実行します。

   ```KQL
   search "administrators" | summarize count() by $table
   ```

3. 最初のデータソースはSecurityEventです。特権グループへのメンバーの追加を識別するためにWindowsが使用するイベントIDを調査するときが来ました。探していた EventID と Event は "4732 - A member was added to a security-enabled local group" でした。次のスクリプトを実行して確認します。

   ```KQL
   SecurityEvent
   | where EventID == "4732"
   | where TargetAccount == "Builtin\\Administrators"
   ```

4. 行を展開して、レコードに関連するすべての列を表示します。  探しているユーザー名は表示されません。  問題は、ユーザー名を保存する代わりに、セキュリティ識別子 (SID) が保存されるということです。次の KQL は、SID を照合して、Administrators グループに追加された TargetUserName にデータを入力しようとします。

   ```KQL
   SecurityEvent
   | where EventID == "4732"
   | where TargetAccount == "Builtin\\Administrators"
   | extend Acct = MemberSid, MachId = SourceComputerId 
   | join kind=leftouter (
      SecurityEvent 
      | summarize count() by TargetSid, SourceComputerId, TargetUserName
      | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
   ) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 
   ```

   ![スクリーンショット](../Media/SC200_sysmon_attack3.png)

   > **注:** ラボで使用されるデータセットが小さいため、このKQLは期待される結果を返さない場合があります。

5. 行を拡張して結果の列を表示すると、最後の列には、KQL クエリ内に表示される UserName1 列の下に追加されたユーザーの名前が表示されます。セキュリティ運用アナリストは、アラートに関するコンテキストをできるだけ多く提供することで、セキュリティ運用アナリストを支援することが重要です。これには、調査グラフで使用するエンティティの表示が含まれます。次のクエリを実行します。

   ```KQL
   SecurityEvent
   | where EventID == "4732"
   | where TargetAccount == "Builtin\\Administrators"
   | extend Acct = MemberSid, MachId = SourceComputerId 
   | join kind=leftouter (
      SecurityEvent 
      | summarize count() by TargetSid, SourceComputerId, TargetUserName
      | project Acct1 = TargetSid, MachId1 = SourceComputerId, UserName1 = TargetUserName
   ) on $left.MachId == $right.MachId1, $left.Acct == $right.Acct1 
   | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = UserName1
   ```

6. 適切な検出ルールができたので、クエリのあるログ ウィンドウで、コマンド バーの 「**新しいアラート ルール**」 を選択し、「**Microsoft Sentinel アラートの作成**」 を選択します。

7. これにより、分析ルール　ウィザードが起動します。全般タブに次のように入力します

   |設定|値|
   |:----|:----|
   |名前 |SecurityEvents Local Administrators User Add|
   |説明 |User added to Local Administrators group|
   |戦術 |Privilege Escalation|
   |重大度 |高|

8. 「**次: ルール ロジックを設定　>**」ボタンを選択します。

9. ルールロジックの設定タブで、**ルールのクエリ** と **エンティティマッピング** のエンティティが既に入力されている必要があります。さらに「アラートエンリッチメント」セクションの **エンティティマッピング** を確認し、エンティティが下記のように入力されている必要があります。

   |エンティティ|識別子|データフィールド|
   |:----|:----|:----|
   |Account|FullName|AccountCustomEntity|
   |Host|Hostname|HostCustomEntity|

10. **クエリのスケジューリング設定** で、次のように設定します。

   |設定|値|
   |:----|:----|
   |クエリの実行間隔 |5 分|
   |次の時間分の過去のデータを参照します |1 日|

   > **注:** 同じデータに対して意図的に多くのインシデントを生成しています。これにより、ラボはこれらのアラートを使用できるようになります。

11. 残りのオプションは既定値のままにします。「**次: インシデントの設定 >**」を選択します。

12. **インシデントの設定** タブで、既定値のままにして、「**次: 自動応答 >」を選択します。**

13. 自動応答タブで、「新規作成」を選択し、オートメーションルールを作成します。

   |設定|値|
   |:----|:----|
   |オートメーションルール名 |PostMessage|
   |トリガー |インシデントが作成されたとき|
   |アクション |プレイブックの実行|
   |プレイブック |PostMessageTeams|
   
1. **確認と応答** タブで、**作成** を選択します。

## 演習 8 に進みます。

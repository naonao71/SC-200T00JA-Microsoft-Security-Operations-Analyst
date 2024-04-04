# モジュール 8 - ラボ 1 - 演習 1 - Microsoft Sentinel で脅威ハンティングを実行する

## ラボ シナリオ

![Lab overview.](../Media/SC-200-Lab_Diagrams_Mod8_L1_Ex1.png)

あなたは Microsoft Sentinel を実装した企業で働いているセキュリティ オペレーションアナリストです。あなたはコマンドと制御 (C2 または C&C) テクニックについて脅威インテリジェンスを受け取りました。その脅威に対してハンティングとウォッチを実行する必要があります。

> **重要:** このラボで使用するログデータは、前のモジュールで作成したものです。演習 6 の WINServer サーバーの **タスク 3** を確認してください。

> **注:**  前のモジュールでデータを探索するプロセスをすでに経験しているため、ラボでは開始するための KQL ステートメントを提供しています。  
>**ノート:** **[interactive lab simulation](https://mslabs.cloudguides.com/guides/SC-200%20Lab%20Simulation%20-%20Perform%20threat%20hunting%20in%20Microsoft%20Sentinel)** このラボを自分のペースで確認できます。ホスト型のラボと多少の違いはありますが、主要な概念とアイデアは同じです。

### タスク 1: ハンティング クエリの作成

このタスクでは、ハンティングクエリを作成し、結果をブックマークして、ライブ ストリームを作成します。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは**Pa55w.rd** です。  

2. Microsoft Edge ブラウザーで Azure portal (https://portal.azure.com) に移動します。

3. **サインイン** ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントのメール** アカウントをコピーして貼り付け、「**次へ**」を選択します。

4. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

5. Azure portal の検索バーに「*Sentinel*」と入力してから、「**Microsoft Sentinel**」を選択します。

6. Microsoft Sentinel ワークスペースを選択します。

7. 「**ログ**」を選択する 

8. 新規クエリ1のスペースに以下のKQLステートメントを入力します。

   > **重要:** エラーを防止するため、最初に KQL クエリをメモ帳に貼り付けてから、**新しいクエリ 1** のログ ウィンドウにコピーしてください。

    ```KQL
    let lookback = 2d; 
    SecurityEvent | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam 
    | order by count_ desc nulls last 
    ```

9. さまざまな結果を確認します。これで、環境で実行されている PowerShell 要求を特定できました。

10. PwshParam フィールドの値に、「-file c2.ps1」と表示されている結果のチェックボックスを選択します。

11. 中央のコマンド バーで、「**ブックマークの追加**」 ボタンを選択します。

12. 「エンティティ マッピング」の下にある 「+ Add new entriy」をクリックします。

    |エンティティ|識別子|データフィールド|
    |:----|:----|:----|
    |Host|Hostname|Computer|

13. 「戦術と手法」で、「Command and Control」を選択します。

14. 「作成」をクリックします。

15. ウィンドウの右上にある「X」を選択して「ログ」ウィンドウを閉じ、「OK」を選択して変更を破棄します。
16. Microsoft Sentinel ワークスペースをもう一度選択し、「脅威管理」セクションの「ハンティング」ページを選択します。
17. 「クエリ」タブを選択し、コマンド バーから 「+ 新しいクエリ」を選択します。
18. 「カスタム クエリの作成」ウィンドウの「名前」に「PowerShell Hunt」と入力します。
19. カスタム クエリの場合は、次の KQL ステートメントを入力します。

    ```KQL
    let lookback = 2d; 
    SecurityEvent | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam 
    | order by count_ desc nulls last 
    ```
20. 「エンティティ マッピング」を設定します。

    |エンティティ|識別子|データフィールド|
    |:----|:----|:----|
    |Host|Hostname|Computer|

21. **戦術と手法**で、「**Command and Control**」を選択します。「**作成**」を選択して、ハンティング クエリを作成します。

22. **「Microsoft Sentinel | ハンティング」** ブレードで、**クエリの検索** から先ほど作成した **PowerShell Hunt** クエリを検索します。

23. リストの中から「**PowerShell Hunt**」を選択します。

24. 結果の数は、結果の列の下に表示されます。

25. 「**結果の表示**」ボタンを選択します。KQLクエリが自動的に実行されます。

26. ウィンドウの右上にある「X」を選択して「ログ」ウィンドウを閉じ、「OK」を選択して変更を破棄します。

27. 「**PowerShell Hunt**」を右クリックして、「**ライブストリームに追加**」を選択します。

28. 「状態」が 「実行中」になっていることを確認します。これはバックグラウンドで 30 秒ごとに実行され、新しい結果が見つかると Azure Portal (ベルのアイコン) に通知が表示されます。

29. 「**ブックマーク**」タブを選択します。

30. 結果一覧で作成したブックマークを選択します。

31. 「**調査**」 ボタンを選択します。

32. グラフを調査します。

33. 右上の「x」を選択して、ウィンドウを閉じて、Microsoft Sentinel ポータルのハンティング ページに戻ります。

34. >> アイコンを選択して右ブレードを非表示にし、省略記号 (...) アイコンが表示されるまで右にスクロールします。

35. 右側の行の最後にある **「...」** を選択して、コンテキスト メニューを開きます。

36. 「**既存のインシデントに追加**」を選択します。

37. インシデントの 1 つを選択し、 「追加」を選択します。

38. 左にスクロールすると、「重大度」列にインシデントのデータが表示されます。

### タスク 2: NRTクエリルールの作成

このタスクでは、ライブストリームを使用する代わりに、NRT 分析クエリ ルールを作成します。NRT ルールは 1 分ごとに実行され、1 分間振り返ります。NRT ルールの利点は、アラートとインシデント作成ロジックを使用できることです。

1. Microsoft Sentinel の分析をクリックします。

1. メニューから作成を選択し、NRTクエリルールをクリックします。

1. 分析ルール ウィザードを構成します。

    |項目|値|
    |---|---|
    |名前|**NRT PowerShell Hunt**|
    |説明|**NRT PowerShell Hunt**|
    |戦術と手法|**Command and Control**|
    |重大度|**高**|

1. 「次：ルールのロジックを設定>」をクリックします。

1. ルールのクエリに以下のKQLクエリを入力します。

    ```KQL
    let lookback = 2d; 
    SecurityEvent | where TimeGenerated >= ago(lookback) 
    | where EventID == 4688 and Process =~ "powershell.exe"
    | extend PwshParam = trim(@"[^/\\]*powershell(.exe)+" , CommandLine) 
    | project TimeGenerated, Computer, SubjectUserName, PwshParam 
    | summarize min(TimeGenerated), count() by Computer, SubjectUserName, PwshParam
    ```

1. **クエリ結果の表示>** を選択して、クエリにエラーがないことを確認します。

1. ウィンドウの右上にある「X」を選択して「ログ」ウィンドウを閉じ、「OK」を選択して変更を破棄します。

1. 「結果のシミュレーション」で「現在のデータでテスト」を選択します。1 日あたりのアラートの予想数に注目してください。

1. 「エンティティ マッピング」を設定します。

    |エンティティ|識別子|データフィールド|
    |:----|:----|:----|
    |Host|Hostname|Computer|

1. 残りのオプションはデフォルトのままにします。「次：インシデントの設定>」をクリックします。

1. インシデントの設定タブで、既定値のままにして、「次：確認と作成>」をクリックします。

1. 「確認と作成」タブで、設定を確認し「保存」をクリックします。

### <a name="task-3-create-a-search"></a>タスク 3:検索の作成

このタスクでは、検索ジョブを使用して C2 を検索します。 

1. Microsoft Sentinel で **[検索]** ページを選択します。 

1. 検索ボックスに「reg.exe」と入力し、「開始」を選択します。

1. クエリを実行する新しいウィンドウが開きます。右上の省略記号アイコン (...) を選択し、検索ジョブ モードを切り替えます。

1. コマンド バーから **検索ジョブ** ボタンを選択します。

1. 検索ジョブは、結果が到着するとすぐに、結果を含む新しいテーブルを作成します。結果は「保存された検索」タブから参照できます。

1. ウィンドウの右上にある「X」を選択して「ログ」ウィンドウを閉じ、「OK」を選択して変更を破棄します。

1. コマンド バーから **復元**タブを選択し、「復元」ボタンを選択します。

1. 「復元するテーブルの選択」で、**SecurityEvent** を検索して選択します。

1. 使用可能なオプションを確認し、「キャンセル」ボタンを選択します。

   >NOTE: 復元ジョブが数分間実行され、データが新しいテーブルで使用できるようになります。
   
## 演習 2 に進みます。

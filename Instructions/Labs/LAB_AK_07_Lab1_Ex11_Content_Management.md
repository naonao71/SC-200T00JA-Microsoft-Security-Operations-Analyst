---
lab:
    title: '演習 11 - Microsoft Sentinel でリポジトリを使用する'
    module: 'ラーニング パス 7 - Microsoft Sentinel を使用して検出を作成し、調査を実行する'
---

# ラーニング パス 7 - ラボ 1 - 演習 11 - Microsoft Sentinel でリポジトリを使用する

## ラボのシナリオ

あなたは、Microsoft Sentinel を実装した会社で働くセキュリティ運用アナリストです。スケジュールされたルールと Microsoft セキュリティ分析ルールは既に作成されています。分析ルールを Azure DevOps リポジトリに一元化する必要があります。次に、Sentinel を Azure DevOps リポジトリに接続し、コンテンツをインポートします。

>**ノート:** **[interactive lab simulation](https://mslabs.cloudguides.com/guides/SC-200%20Lab%20Simulation%20-%20Use%20repositories%20in%20Microsoft%20Sentinel)** このラボを自分のペースで確認できます。ホスト型のラボと多少の違いはありますが、主要な概念とアイデアは同じです。

### タスク 1: 分析ルールの作成とエクスポート

このタスクでは、Microsoft Sentinel でエンティティ動作分析を有効にします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードはPa55w.rd です。

2. サインイン ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供されたテナントのメール アカウントをコピーして貼り付け、「次へ」を選択します。

3. パスワードの入力ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供されたテナントパスワードをコピーして貼り付け、「サインイン」を選択します。

4. Azure portal の検索バーに「Sentinel」と入力してから、「Microsoft Sentinel」を選択します。

5. Microsoft Sentinel ワークスペースを選択します。

6. 「構成」セクションの「分析」を選択します。

7. 前に作成した **Startup RegKey** 規則を選択します。

8. ツールバーから 「エクスポート」を選択します。ヒント：省略記号アイコン (...) を選択して表示することが必要な場合があります。

9.  ルールは **Azure_Sentinel_analytic_rule.json** という名前のテキスト ファイルにエクスポートされます。

10. ダウンロードしたファイルをメモ帳で開きます。

11. ARMテンプレートの内容を確認し、完了したら閉じます。

### タスク 2: Azure DevOps 環境を作成する

このタスクでは、Azure DevOps リポジトリの作成と設定をテストします。

1. ブラウザで別のタブを開きます。

1. https://aexprodcus1.vsaex.visualstudio.com/me?mkt=jp-JA に移動します。

2. *詳細情報をいくつか入力する必要があります* ページで、 **続行** をクリックし「**Create new organization**」をクリックします。

3. 「Get started with Azure DevOps」でチェックし「**Continue**」をクリックします。*Almost done...* ページで、今後使用しないDEbOps組織の名前 (テナント プレフィックスなど) を入力します。ヒント：これは、ラボの 「リソース」 タブにあります (WWLx...)。

4. 表示される文字を入力してから、「**Continue**」を選択します。

5. *Create a project to get started* ページで 「Project name」に「**My Sentinel Content**」を入力し、「**Create project**」をクリックします。

6. 左ペインの **Repos** をクリックします。

7. 「Switch to the default My Sentinel Content repository」をクリックします。「*Initialize main branch with a README or gitignore*」エリアで「**Initialize**」をクリックします。.

8. このページには、リポジトリのファイルが表示されます。唯一のファイルは README.me です。

9. 「ファイル」 (ページの右側) ブレードのツール バーには、*Set up build*、*Clone*、および **:** (More Actions)のオプションが含まれています。: を選択すると、その他のオプションが表示されます。

10. 「:」 を選択し「**Upload Files**」をクリックします。.

11. 「**Browse**」をクリックし、「ダウンロード」ディレクトリから **Azure_Sentinel_analytic_rule.json** を選択します。

12. 「**Commit**」をクリックします。

13. ページの左上隅にある **Azure DevOps** を選択します。これにより、組織とプロジェクトが表示されます。

14. ページの左下にある「**Organization settings**」を選択します。

15. 「*Security*」エリアにある「**Policies**」を選択します。

16. 「*Application connection policies*」エリアの「*Third-party application access via OAuth*」のスイッチを「On」にします。

### タスク 3: Sentinel を Azure DevOps に接続します。

1. ブラウザーで Microsoft Sentinelを開きます。

1. Microsoft Sentinel で、「コンテンツ管理」セクションの「**リポジトリ (プレビュー)**」を選択します。

1. ツールバーから「新規追加」を選択します。

1. 名前に「**My Content**」と入力します。

2. 「ソース管理」で、「Azure DevOps」を選択します。

3. 「**承認**」をクリックします。アクセス許可要求を下にスクロールし、「**承認**」をクリックします。

4. 以前に作成した組織を選択します(例:WWLxなど)。

5. 前に作成したプロジェクトの「*My Sentinel Content*」を選択します。

6. 前に作成したリポジトリの「*My Sentinel Content*」を選択します。

7. 「ブランチ」で「**main**」を選択します。

8. すべてのコンテンツ タイプを選択します。

9. 「**作成**」をクリックします。

10. 必要に応じて Microsoft Sentinel ワークスペースに戻ります。

11. 「**リポジトリ (プレビュー)**」ページで、「最新の情報に更新」をクリックします。「前回のデプロイの状態」が「失敗」になります。  

    >ノート：「失敗」 状態は、ホストされているラボ環境の制限が原因です。通常は 「成功」 と表示されます。その後、Azure DevOps からインポートされた「**Rule from Azure DevOps**」ルールを分析で確認できます。

## これでラボは完了です。
